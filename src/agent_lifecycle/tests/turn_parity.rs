//! Multi-turn cross-engine Agent-loop parity (#182, #143).
//!
//! ## What this adds over the single-stage parity gate
//!
//! `tests.rs::every_stage_executor_agrees_on_every_deterministic_stage_of_one_source_program`
//! compares one stage dispatch at a time, and every leg is handed the *same*
//! hand-built arguments: the state chain is computed once, on the
//! interpreter, and replayed into the other three legs. That proves each
//! stage body is equivalent in isolation. It cannot observe an accumulating
//! divergence, because no backend's output is ever fed back into that
//! backend's next input.
//!
//! This module closes exactly that hole. Each leg -- interpreter, native C11
//! `-O0`, native C11 `-O2`, Core Wasm -- drives the **whole conversation by
//! itself**: its own `initialize` result is the `observe`/`authorize`/`reduce`
//! input, and its own `reduce` result becomes the next turn's `Task`. A
//! one-field error at turn 1 therefore changes every later turn, the decision
//! branch taken, the terminal status and the counters, rather than being
//! overwritten by the reference leg's value on the next line.
//!
//! The comparison is over a whole **transcript**: the ordered state,
//! observation, decision and report values of every turn, plus the turn,
//! grant and refusal counters and the terminal status. That is #182's
//! required test "the same Agent fixture produces equal state transitions,
//! results, terminal statuses, and counters on all three backends" for the
//! deterministic stage profile.
//!
//! ## What this still does not establish, stated so it is not inferred away
//!
//! The conversation is a *driver* over deterministic stage bodies. The
//! per-turn grant material, the typed effect/model request protocol,
//! Proposal decoding, checkpoints, cancellation and fuel accounting remain
//! interpreter-only, exactly as `wasm_executor.rs` and `native_executor.rs`
//! already record. `steps_used` is `0` off-interpreter and is deliberately
//! not part of the compared transcript, because a step count that is
//! structurally zero on three of four legs would make the comparison weaker,
//! not stronger. The outcome carrier each turn feeds into `reduce` is a
//! fixture constant, not the product of a real effect.
//!
//! Evidence class: local and re-runnable, macOS/Unix, requires `clang` and
//! `node` on PATH and skips without them. Not hosted, not a browser, not a
//! production-support claim.

use super::*;

/// Which sealed [`authorization::StageExecutor`] one dispatch selects.
///
/// This is a test-local label, not a fourth backend: every arm below builds
/// one of the four already-admitted `StageBackend` values and goes through
/// the one `authorization::dispatch_on` route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Leg {
    Interpreter,
    NativeO0,
    NativeO2,
    Wasm,
}

impl Leg {
    const fn label(self) -> &'static str {
        match self {
            Self::Interpreter => "interpreter",
            Self::NativeO0 => "native -O0",
            Self::NativeO2 => "native -O2",
            Self::Wasm => "Core Wasm",
        }
    }
}

/// One turn's worth of dispatch, through the single admitted route.
fn dispatch(
    leg: Leg,
    native_host: Option<&authorization::NativeStageHost>,
    source: &str,
    program: &hir::ResolvedProgram,
    prepared: &crate::interpreter::retained_call::PreparedRetainedCall,
    arguments: &[RetainedValue],
) -> Result<RetainedCallOutcome, Vec<Diagnostic>> {
    let backend = match leg {
        Leg::Interpreter => authorization::StageBackend::Interpreter,
        Leg::NativeO0 => native_backend(native_host.expect("native leg retains held host")),
        Leg::NativeO2 => native_o2_backend(native_host.expect("native leg retains held host")),
        Leg::Wasm => authorization::StageBackend::Wasm { source },
    };
    authorization::dispatch_on(backend, program, prepared, arguments, DEFAULT_STAGE_STEPS)
        .map(|evaluation| evaluation.outcome)
}

/// The value a stage returned, or a panic naming the leg and the stage: a
/// conversation that cannot continue is a failure, never a shorter transcript
/// that happens to match another leg's shorter transcript.
fn returned(
    leg: Leg,
    label: &str,
    outcome: Result<RetainedCallOutcome, Vec<Diagnostic>>,
) -> RetainedValue {
    match outcome {
        Ok(RetainedCallOutcome::Returned(value)) => value,
        Ok(other) => panic!("{}: {label} did not return a value: {other:?}", leg.label()),
        Err(errors) => panic!("{}: {label} failed: {errors:?}", leg.label()),
    }
}

/// One record field, selected by the suffix of its persistent identity.
///
/// Identity, never declaration order: reordering the fixture's fields must
/// not silently reselect a different field.
fn field_by_suffix<'a>(value: &'a RetainedValue, suffix: &str) -> &'a RetainedValue {
    let RetainedValue::Record(record) = value else {
        panic!("expected a record, got {value:?}");
    };
    &record
        .fields
        .iter()
        .find(|field| field.field.as_str().ends_with(suffix))
        .unwrap_or_else(|| panic!("no field ending in {suffix} on {value:?}"))
        .value
}

fn bytes_field(value: &RetainedValue, suffix: &str) -> Vec<u8> {
    match field_by_suffix(value, suffix) {
        RetainedValue::Bytes(bytes) => bytes.clone(),
        other => panic!("{suffix} is not Bytes: {other:?}"),
    }
}

fn i64_field(value: &RetainedValue, suffix: &str) -> i64 {
    match field_by_suffix(value, suffix) {
        RetainedValue::I64(value) => *value,
        other => panic!("{suffix} is not i64: {other:?}"),
    }
}

/// One leg's complete record of the same fixture conversation.
///
/// Everything here is derived from that leg's own stage results, so two
/// transcripts are equal only if the two engines agreed at every turn.
#[derive(Debug, Eq, PartialEq)]
struct Transcript {
    /// Ordered semantic transitions: the exact carriers each stage produced.
    lines: Vec<String>,
    /// Counters. A conversation that stops a turn early differs here even if
    /// every line it did produce matched.
    turns_completed: usize,
    grants: usize,
    refusals: usize,
    /// Why the conversation stopped.
    terminal: String,
    /// Every state carrier this run produced, in order. These are the exact
    /// resume points `the_core_wasm_leg_resumes_an_interpreter_conversation`
    /// below hands to a different engine, and they are part of the compared
    /// value, so a leg whose carriers differ cannot pass by rendering the
    /// same lines.
    checkpoints: Vec<RetainedValue>,
}

/// The initial task budget, and the per-turn requested budget schedule.
///
/// Chosen so the fixture's own arithmetic drives the conversation to a
/// *refusal* rather than to the turn cap: `reduce` spends the granted budget
/// out of the state (`state.budget - budget`) while the request grows, so
/// turn 3 asks for more than the state still holds. Both `authorize`
/// branches, and the `urgent` discriminator inside the refusal, are therefore
/// exercised by the conversation itself instead of by hand-built arguments.
const INITIAL_BUDGET: i64 = 10;
const TURN_CAP: usize = 3;

const fn requested_budget(turn: usize) -> i64 {
    3 * turn as i64
}

/// Runs the whole fixture conversation on exactly one leg.
///
/// `dispatches` counts the stage calls this leg actually made, so a leg that
/// silently did nothing cannot pass by producing an empty transcript that
/// matches another empty transcript.
fn converse(
    leg: Leg,
    native_host: Option<&authorization::NativeStageHost>,
    compiled: &CompiledAgentLifecycle,
    source: &str,
    dispatches: &mut usize,
) -> Transcript {
    let task = payload(&compiled.binding.task, b"alpha".to_vec(), INITIAL_BUDGET);
    *dispatches += 1;
    let state = returned(
        leg,
        "initialize",
        dispatch(
            leg,
            native_host,
            source,
            &compiled.program,
            compiled.binding.initialize.prepared(),
            std::slice::from_ref(&task),
        ),
    );
    let mut transcript = drive(
        leg,
        native_host,
        compiled,
        source,
        state.clone(),
        1,
        dispatches,
    );
    transcript.lines.insert(0, format!("state@0 {state:?}"));
    transcript.checkpoints.insert(0, state);
    transcript
}

/// Drives the conversation from an existing state carrier at `first_turn`.
///
/// Split out from [`converse`] so a run can be *resumed* from a recorded
/// carrier on a different engine without re-executing the turns that produced
/// it. The returned transcript covers only the turns this call drove.
fn drive(
    leg: Leg,
    native_host: Option<&authorization::NativeStageHost>,
    compiled: &CompiledAgentLifecycle,
    source: &str,
    start: RetainedValue,
    first_turn: usize,
    dispatches: &mut usize,
) -> Transcript {
    let binding = &compiled.binding;
    let mut call = |label: &str,
                    prepared: &crate::interpreter::retained_call::PreparedRetainedCall,
                    arguments: &[RetainedValue]| {
        *dispatches += 1;
        returned(
            leg,
            label,
            dispatch(
                leg,
                native_host,
                source,
                &compiled.program,
                prepared,
                arguments,
            ),
        )
    };

    let mut lines = Vec::new();
    let mut checkpoints = Vec::new();
    let mut state = start;

    let mut turns_completed = 0usize;
    let mut grants = 0usize;
    let mut refusals = 0usize;
    let mut terminal = format!("turn-cap@{TURN_CAP}");

    for turn in first_turn..=TURN_CAP {
        let observation = call("observe", binding.observe.prepared(), &[state.clone()]);
        lines.push(format!("observe@{turn} {observation:?}"));

        let request = requested_budget(turn);
        let urgent = turn == TURN_CAP;
        let arguments = [
            state.clone(),
            RetainedValue::I64(request),
            RetainedValue::Bool(urgent),
            RetainedValue::Usize(turn as u64),
        ];
        let decision = call(
            "authorize",
            binding.authorize.stage().prepared(),
            &arguments,
        );
        lines.push(format!(
            "authorize@{turn} request={request} urgent={urgent} {decision:?}"
        ));

        let RetainedValue::Variant(variant) = &decision else {
            panic!(
                "{}: authorize@{turn} did not decide: {decision:?}",
                leg.label()
            );
        };
        // The branch is read from the persistent case identity, so "both legs
        // agreed" can never be satisfied by both taking the same wrong branch.
        if variant.case.as_str() == binding.authorize.refuse_case().as_str() {
            refusals += 1;
            terminal = format!("refused@{turn} {decision:?}");
            break;
        }
        assert_eq!(
            variant.case.as_str(),
            binding.authorize.grant_case().as_str(),
            "{}: authorize@{turn} returned neither admitted case",
            leg.label()
        );
        grants += 1;

        let outcome = payload(&binding.outcome, b"observed".to_vec(), 4);
        let report = call(
            "reduce",
            binding.reduce.prepared(),
            &[
                state.clone(),
                RetainedValue::I64(request),
                RetainedValue::Bool(urgent),
                RetainedValue::Usize(turn as u64),
                outcome,
            ],
        );
        lines.push(format!("reduce@{turn} {report:?}"));

        // The feedback edge that makes this a conversation rather than four
        // independent stage calls: the NEXT turn's task is built from THIS
        // leg's own report, so any divergence compounds instead of being
        // overwritten by the reference leg's value.
        let next = payload(
            &binding.task,
            bytes_field(&report, ".summary"),
            i64_field(&report, ".budget"),
        );
        state = call("initialize", binding.initialize.prepared(), &[next]);
        lines.push(format!("state@{turn} {state:?}"));
        checkpoints.push(state.clone());
        turns_completed += 1;
    }

    Transcript {
        lines,
        turns_completed,
        grants,
        refusals,
        terminal,
        checkpoints,
    }
}

/// #182's first required test, at the deterministic stage profile: the same
/// Agent fixture, driven end to end by each engine on its own values,
/// produces equal state transitions, decisions, results, terminal status and
/// counters on interpreter, native C11 `-O0`/`-O2`, and Core Wasm.
#[test]
fn every_backend_drives_the_same_multi_turn_conversation_to_the_same_transitions_and_counters() {
    if !native_wasm_tools_available() {
        eprintln!("skipping multi-turn conversation parity: clang or node unavailable");
        return;
    }
    let native_host = native_stage_host().expect("availability retains native host");
    let compiled = lifecycle();
    // The Wasm leg re-resolves exactly the module text the caller supplies.
    // `CompiledAgentLifecycle::source` is the rendered lifecycle document,
    // not this text, so it is threaded in explicitly.
    let source = MODULE;

    let mut interpreter_dispatches = 0usize;
    let reference = converse(
        Leg::Interpreter,
        None,
        &compiled,
        source,
        &mut interpreter_dispatches,
    );

    // The conversation the fixture's own arithmetic produces: two grants,
    // then a refusal on turn 3 because `reduce` has spent the state's budget
    // down below the growing request. Pinned exactly, so a future fixture or
    // backend change that makes every leg agree on a *different, shorter*
    // conversation cannot pass unnoticed.
    assert_eq!(reference.turns_completed, 2, "turns");
    assert_eq!(reference.grants, 2, "grants");
    assert_eq!(reference.refusals, 1, "refusals");
    assert!(
        reference.terminal.starts_with("refused@3 "),
        "terminal: {}",
        reference.terminal
    );
    assert!(
        reference
            .terminal
            .contains(compiled.binding.authorize.refuse_case().as_str()),
        "the terminal decision names the refusal case: {}",
        reference.terminal
    );
    // 1 initialize + 2 full turns (observe, authorize, reduce, initialize)
    // + the final observe and refused authorize.
    assert_eq!(interpreter_dispatches, 11, "interpreter dispatches");

    let mut counts = Vec::new();
    for leg in [Leg::NativeO0, Leg::NativeO2, Leg::Wasm] {
        let mut dispatches = 0usize;
        let transcript = converse(leg, Some(&native_host), &compiled, source, &mut dispatches);
        // Line by line first, so a divergence reports the exact turn and
        // stage rather than a wall of two whole transcripts.
        for (index, (expected, actual)) in reference
            .lines
            .iter()
            .zip(transcript.lines.iter())
            .enumerate()
        {
            assert_eq!(expected, actual, "{}: transition {index}", leg.label());
        }
        assert_eq!(
            reference.lines.len(),
            transcript.lines.len(),
            "{}: transition count",
            leg.label()
        );
        assert_eq!(reference, transcript, "{}: transcript", leg.label());
        // Non-vacuity: this leg really executed every stage of every turn.
        assert_eq!(
            dispatches,
            interpreter_dispatches,
            "{}: dispatch count",
            leg.label()
        );
        counts.push((leg.label(), dispatches));
    }

    assert_eq!(counts.len(), 3);
    eprintln!(
        "multi-turn conversation parity: {} transitions, {} turns, {} grants, \
         {} refusals, terminal {}; {} interpreter dispatches and {counts:?} \
         compared against it",
        reference.lines.len(),
        reference.turns_completed,
        reference.grants,
        reference.refusals,
        reference.terminal,
        interpreter_dispatches,
    );
}

/// The empty-`Bytes` side of the same invariant: Core Wasm synthesizes the
/// admitted exact zero-length range/copy construction and returns the same
/// answer as the interpreter and both native legs.
#[test]
fn empty_bytes_are_equal_across_interpreter_native_and_wasm_legs() {
    if !native_wasm_tools_available() {
        eprintln!("skipping empty-Bytes parity: clang or node unavailable");
        return;
    }
    let native_host = native_stage_host().expect("availability retains native host");
    let compiled = lifecycle();
    let source = MODULE;
    let empty = payload(&compiled.binding.task, Vec::new(), INITIAL_BUDGET);

    let reference = returned(
        Leg::Interpreter,
        "initialize",
        dispatch(
            Leg::Interpreter,
            None,
            source,
            &compiled.program,
            compiled.binding.initialize.prepared(),
            std::slice::from_ref(&empty),
        ),
    );
    for leg in [Leg::NativeO0, Leg::NativeO2] {
        let native = returned(
            leg,
            "initialize",
            dispatch(
                leg,
                Some(&native_host),
                source,
                &compiled.program,
                compiled.binding.initialize.prepared(),
                std::slice::from_ref(&empty),
            ),
        );
        assert_eq!(reference, native, "{}: empty objective", leg.label());
    }

    let wasm = returned(
        Leg::Wasm,
        "initialize",
        dispatch(
            Leg::Wasm,
            None,
            source,
            &compiled.program,
            compiled.binding.initialize.prepared(),
            std::slice::from_ref(&empty),
        ),
    );
    assert_eq!(reference, wasm, "{}: empty objective", Leg::Wasm.label());
}

/// #143's "recovery with a fresh instance" case, and #182's "the semantic
/// lifecycle is target-independent", in one run: a conversation the
/// interpreter drove for one turn is **resumed on Core Wasm** from the
/// recorded state carrier alone, and produces exactly the remainder of the
/// all-interpreter transcript without re-executing a single earlier turn.
///
/// Every Wasm dispatch already builds a fresh module and starts a fresh
/// `node` process (`wasm_executor.rs`), so "a fresh instance" is not
/// simulated here -- it is the only mode this backend has.
///
/// ## What this proves, and what it deliberately does not
///
/// It proves the state carrier is a *portable* resume point: an engine that
/// did not run turn 1 reconstructs nothing, trusts the recorded carrier, and
/// reaches the same decisions, the same terminal refusal and the same
/// counters. The dispatch count is asserted exactly, so "did not repeat
/// earlier work" is a measured fact rather than a claim.
///
/// It does **not** prove that a real external effect was not repeated: the
/// deterministic stage profile has no effects to repeat, because the effect
/// and model request protocol still runs interpreter-side only. Closing that
/// half of #143's fifth case needs the executor wired into the effect
/// machinery, which is a reviewed architectural expansion, not a gap fix.
#[test]
fn the_core_wasm_leg_resumes_an_interpreter_conversation_from_a_recorded_carrier_alone() {
    if !native_wasm_tools_available() {
        eprintln!("skipping resume parity: clang or node unavailable");
        return;
    }
    let compiled = lifecycle();
    let source = MODULE;

    let mut whole = 0usize;
    let reference = converse(Leg::Interpreter, None, &compiled, source, &mut whole);
    assert_eq!(whole, 11, "the uninterrupted run's dispatches");
    assert_eq!(
        reference.checkpoints.len(),
        3,
        "state@0, state@1 and state@2"
    );

    // The conversation is interrupted after turn 1. The only thing carried
    // across the interruption is the recorded state carrier -- no engine
    // handle, no partial module, no interpreter object.
    let resume_from = reference.checkpoints[1].clone();

    let mut resumed_dispatches = 0usize;
    let resumed = drive(
        Leg::Wasm,
        None,
        &compiled,
        source,
        resume_from,
        2,
        &mut resumed_dispatches,
    );

    // The recorded prefix is `state@0` plus turn 1's four lines.
    const PREFIX_LINES: usize = 5;
    const PREFIX_DISPATCHES: usize = 5;
    assert_eq!(
        resumed.lines,
        reference.lines[PREFIX_LINES..].to_vec(),
        "the resumed tail differs from the uninterrupted tail"
    );
    assert_eq!(
        resumed.checkpoints,
        reference.checkpoints[2..].to_vec(),
        "the resumed carriers differ"
    );
    assert_eq!(resumed.terminal, reference.terminal, "terminal status");
    assert_eq!(resumed.grants, 1, "grants after the resume point");
    assert_eq!(resumed.refusals, 1, "refusals after the resume point");
    assert_eq!(resumed.turns_completed, 1, "turns after the resume point");

    // Recovery costs exactly the remaining turns: the five dispatches that
    // produced the recorded carrier are not re-driven on the new engine.
    assert_eq!(
        resumed_dispatches,
        whole - PREFIX_DISPATCHES,
        "recovery must not repeat the recorded prefix"
    );
    // Non-vacuity: the resumed run really executed stages rather than
    // returning an empty tail that trivially matches an empty slice.
    assert_eq!(resumed_dispatches, 6);
    assert!(!resumed.lines.is_empty());
    eprintln!(
        "cross-engine resume: interpreter drove {PREFIX_DISPATCHES} dispatches, \
         Core Wasm resumed from the recorded carrier in {resumed_dispatches} \
         dispatches and reproduced {} transitions and terminal {}",
        resumed.lines.len(),
        resumed.terminal
    );
}
