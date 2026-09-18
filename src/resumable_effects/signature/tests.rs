//! Signature-checking regressions.
//!
//! Every fixture here deliberately models **two** distinct effects inside
//! one `Request`/`Observation` Rust type, because that is precisely the
//! case `core`'s whole-program type parameters cannot distinguish: to
//! `rustc`, a `clock` answer and a `model` answer are the same type, and
//! swapping them type-checks. Each refusal below is therefore a check that
//! exists nowhere else in the module.

use super::*;
use crate::resumable_effects::core::*;

/// One tagged value, used as both this fixture program's `Request` and its
/// `Observation` — the realistic shape once a computation waits on more
/// than one effect.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Tagged {
    effect: String,
    shape: String,
    body: String,
}

impl Tagged {
    fn new(effect: &str, shape: &str, body: &str) -> Self {
        Self {
            effect: effect.to_string(),
            shape: shape.to_string(),
            body: body.to_string(),
        }
    }
}

fn tag_of(value: &Tagged) -> EffectTag {
    EffectTag::new(value.effect.clone(), value.shape.clone())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TwoEffectState {
    turn: u32,
    log: Vec<String>,
}

impl TwoEffectState {
    fn start() -> Self {
        Self {
            turn: 0,
            log: Vec::new(),
        }
    }
}

/// Turn 0 waits on `clock`, turn 1 waits on `model`, turn 2 completes.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TwoEffectProgram;

impl ResumableEffectProgram for TwoEffectProgram {
    type State = TwoEffectState;
    type Result = String;
    type Request = Tagged;
    type Observation = Tagged;
    type CleanupOp = ();

    fn request(&self, state: &TwoEffectState) -> Option<Tagged> {
        match state.turn {
            0 => Some(Tagged::new("clock", "clock.request.v1", "now")),
            1 => Some(Tagged::new("model", "model.request.v1", "ask")),
            _ => None,
        }
    }

    fn transition(
        &self,
        state: &TwoEffectState,
        observation: Option<&Tagged>,
    ) -> Step<TwoEffectState, String> {
        match observation {
            Some(observed) => {
                let mut log = state.log.clone();
                log.push(observed.body.clone());
                Step::Continue(TwoEffectState {
                    turn: state.turn + 1,
                    log,
                })
            }
            None => Step::Complete(state.log.join(",")),
        }
    }

    fn cleanup_plan(&self, _state: &TwoEffectState) -> Vec<()> {
        Vec::new()
    }
}

fn scope() -> EffectScope {
    EffectScope {
        program_root: "root:v1".to_string(),
        invocation_id: "sig-1".to_string(),
        policy_epoch: 3,
    }
}

fn table() -> EffectSignatureTable {
    EffectSignatureTable::new(vec![
        EffectSignature::new("clock", "clock.request.v1", "clock.answer.v1"),
        EffectSignature::new("model", "model.request.v1", "model.answer.v1"),
    ])
    .expect("the fixture table is well formed")
}

/// Wired as the *wrapped* handler wherever the signature check must refuse
/// before the physical effect boundary is reached. If it is ever called the
/// test fails loudly rather than silently proving nothing.
struct PanicHandler;

impl EffectHandler<Tagged, Tagged> for PanicHandler {
    fn dispatch(&mut self, request: &Tagged) -> Result<Tagged, String> {
        panic!("the wrapped handler must never be reached, but got {request:?}");
    }
}

/// Answers each dispatch with the next scripted value, in order.
struct ScriptedHandler {
    answers: Vec<Tagged>,
    next: usize,
    calls: u32,
}

impl ScriptedHandler {
    fn new(answers: Vec<Tagged>) -> Self {
        Self {
            answers,
            next: 0,
            calls: 0,
        }
    }
}

impl EffectHandler<Tagged, Tagged> for ScriptedHandler {
    fn dispatch(&mut self, _request: &Tagged) -> Result<Tagged, String> {
        self.calls += 1;
        let answer = self
            .answers
            .get(self.next)
            .cloned()
            .ok_or_else(|| "script exhausted".to_string())?;
        self.next += 1;
        Ok(answer)
    }
}

struct NoCleanup;

impl CleanupHandler<()> for NoCleanup {
    fn run(&mut self, _op: &()) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------- table

#[test]
fn a_table_rejects_more_effects_than_the_bounded_maximum() {
    let too_many: Vec<EffectSignature> = (0..=EffectSignatureTable::MAX_EFFECTS)
        .map(|i| EffectSignature::new(format!("effect-{i}"), "req.v1", "ans.v1"))
        .collect();
    let count = too_many.len();
    assert_eq!(
        EffectSignatureTable::new(too_many),
        Err(SignatureTableError::TooManyEffects { count })
    );
}

#[test]
fn a_table_rejects_a_duplicate_effect_id_rather_than_making_the_answer_shape_ambiguous() {
    assert_eq!(
        EffectSignatureTable::new(vec![
            EffectSignature::new("clock", "clock.request.v1", "clock.answer.v1"),
            EffectSignature::new("clock", "clock.request.v1", "other.answer.v1"),
        ]),
        Err(SignatureTableError::DuplicateEffect {
            id: "clock".to_string()
        })
    );
}

#[test]
fn a_table_rejects_an_empty_effect_id_or_an_empty_shape() {
    assert_eq!(
        EffectSignatureTable::new(vec![EffectSignature::new("", "req.v1", "ans.v1")]),
        Err(SignatureTableError::EmptyEffectId)
    );
    assert_eq!(
        EffectSignatureTable::new(vec![EffectSignature::new("clock", "", "ans.v1")]),
        Err(SignatureTableError::EmptyShape {
            id: "clock".to_string()
        })
    );
    assert_eq!(
        EffectSignatureTable::new(vec![EffectSignature::new("clock", "req.v1", "")]),
        Err(SignatureTableError::EmptyShape {
            id: "clock".to_string()
        })
    );
}

#[test]
fn an_empty_table_declares_nothing_and_admits_no_effect() {
    let empty = EffectSignatureTable::none();
    assert!(empty.signatures().is_empty());
    assert_eq!(
        empty.check_request(&EffectTag::new("clock", "clock.request.v1")),
        Err(SignatureMismatch::UnknownEffect {
            effect_id: "clock".to_string()
        })
    );
}

#[test]
fn a_table_preserves_declaration_order_and_never_sorts_it() {
    let declared = EffectSignatureTable::new(vec![
        EffectSignature::new("zulu", "z.req.v1", "z.ans.v1"),
        EffectSignature::new("alpha", "a.req.v1", "a.ans.v1"),
    ])
    .expect("well formed");
    let ids: Vec<&str> = declared
        .signatures()
        .iter()
        .map(|signature| signature.effect_id.as_str())
        .collect();
    assert_eq!(ids, vec!["zulu", "alpha"]);
}

// -------------------------------------------------- refusal before dispatch

#[test]
fn an_undeclared_effect_is_refused_before_the_wrapped_handler_is_called() {
    // The table declares `model` only; the program's first request is `clock`.
    let partial = EffectSignatureTable::new(vec![EffectSignature::new(
        "model",
        "model.request.v1",
        "model.answer.v1",
    )])
    .expect("well formed");
    let mut inner = PanicHandler;
    let mut checked = SignatureCheckedHandler::new(&mut inner, partial, tag_of, tag_of);
    let mut cleanup = NoCleanup;

    let outcome = run(
        &TwoEffectProgram,
        scope(),
        TwoEffectState::start(),
        8,
        &mut checked,
        &mut cleanup,
        &|| false,
    );

    let (error, journal) = outcome.expect_err("an undeclared effect must be refused");
    assert!(
        matches!(error, DriverError::HandlerFailed { turn: 0, .. }),
        "expected a turn-0 HandlerFailed, got {error:?}"
    );
    assert_eq!(
        checked.mismatches(),
        &[SignatureMismatch::UnknownEffect {
            effect_id: "clock".to_string()
        }]
    );
    // The refusal is journalled, never silently discarded, and no
    // observation was recorded for it.
    assert!(matches!(
        journal.entries().last(),
        Some(JournalEntry::ObservationFailed { turn: 0, .. })
    ));
    assert!(!journal
        .entries()
        .iter()
        .any(|entry| matches!(entry, JournalEntry::Observed { .. })));
}

#[test]
fn a_request_whose_shape_disagrees_with_its_declaration_is_refused_before_the_wrapped_handler() {
    let drifted = EffectSignatureTable::new(vec![
        // The declared request shape is v2; the program still emits v1.
        EffectSignature::new("clock", "clock.request.v2", "clock.answer.v1"),
        EffectSignature::new("model", "model.request.v1", "model.answer.v1"),
    ])
    .expect("well formed");
    let mut inner = PanicHandler;
    let mut checked = SignatureCheckedHandler::new(&mut inner, drifted, tag_of, tag_of);
    let mut cleanup = NoCleanup;

    let outcome = run(
        &TwoEffectProgram,
        scope(),
        TwoEffectState::start(),
        8,
        &mut checked,
        &mut cleanup,
        &|| false,
    );

    assert!(matches!(
        outcome.expect_err("a shape-drifted request must be refused"),
        (DriverError::HandlerFailed { turn: 0, .. }, _)
    ));
    assert_eq!(
        checked.mismatches(),
        &[SignatureMismatch::RequestShapeMismatch {
            effect_id: "clock".to_string(),
            declared: "clock.request.v2".to_string(),
            presented: "clock.request.v1".to_string(),
        }]
    );
}

// --------------------------------------------------- refusal of a bad answer

#[test]
fn an_answer_naming_a_different_effect_never_becomes_an_observation() {
    // A well-formed `model` answer offered against the pending `clock`
    // suspension. Both are `Tagged`, so nothing in `core` can reject it.
    let mut inner = ScriptedHandler::new(vec![Tagged::new(
        "model",
        "model.answer.v1",
        "wrong-effect",
    )]);
    let mut checked = SignatureCheckedHandler::new(&mut inner, table(), tag_of, tag_of);
    let mut cleanup = NoCleanup;

    let outcome = run(
        &TwoEffectProgram,
        scope(),
        TwoEffectState::start(),
        8,
        &mut checked,
        &mut cleanup,
        &|| false,
    );

    let (error, journal) = outcome.expect_err("an answer to the wrong effect must be refused");
    assert!(matches!(error, DriverError::HandlerFailed { turn: 0, .. }));
    assert_eq!(
        checked.mismatches(),
        &[SignatureMismatch::AnswerForWrongEffect {
            requested: "clock".to_string(),
            answered: "model".to_string(),
        }]
    );
    assert!(!journal
        .entries()
        .iter()
        .any(|entry| matches!(entry, JournalEntry::Observed { .. })));
}

#[test]
fn an_answer_of_the_wrong_shape_for_the_right_effect_is_refused() {
    let mut inner =
        ScriptedHandler::new(vec![Tagged::new("clock", "clock.answer.v2", "wrong-shape")]);
    let mut checked = SignatureCheckedHandler::new(&mut inner, table(), tag_of, tag_of);
    let mut cleanup = NoCleanup;

    let outcome = run(
        &TwoEffectProgram,
        scope(),
        TwoEffectState::start(),
        8,
        &mut checked,
        &mut cleanup,
        &|| false,
    );

    assert!(matches!(
        outcome.expect_err("a shape-drifted answer must be refused"),
        (DriverError::HandlerFailed { turn: 0, .. }, _)
    ));
    assert_eq!(
        checked.mismatches(),
        &[SignatureMismatch::AnswerShapeMismatch {
            effect_id: "clock".to_string(),
            declared: "clock.answer.v1".to_string(),
            presented: "clock.answer.v2".to_string(),
        }]
    );
}

#[test]
fn matching_requests_and_answers_run_through_unchanged() {
    let mut inner = ScriptedHandler::new(vec![
        Tagged::new("clock", "clock.answer.v1", "t0"),
        Tagged::new("model", "model.answer.v1", "t1"),
    ]);
    let mut checked = SignatureCheckedHandler::new(&mut inner, table(), tag_of, tag_of);
    let mut cleanup = NoCleanup;

    let (outcome, journal) = run(
        &TwoEffectProgram,
        scope(),
        TwoEffectState::start(),
        8,
        &mut checked,
        &mut cleanup,
        &|| false,
    )
    .expect("a matching run completes");

    assert_eq!(outcome.terminal, Step::Complete("t0,t1".to_string()));
    assert_eq!(outcome.dispatched, 2);
    assert!(checked.mismatches().is_empty());
    assert_eq!(journal.validate(&scope()), Ok(()));
    assert_eq!(
        validate_journal_signatures(&journal, &table(), tag_of, tag_of),
        Ok(())
    );
}

// ------------------------------------------------- recovered-journal refusal

/// Drive the fixture to completion and return its genuine journal.
fn genuine_journal() -> Journal<TwoEffectProgram> {
    let mut inner = ScriptedHandler::new(vec![
        Tagged::new("clock", "clock.answer.v1", "t0"),
        Tagged::new("model", "model.answer.v1", "t1"),
    ]);
    let mut cleanup = NoCleanup;
    let (_, journal) = run(
        &TwoEffectProgram,
        scope(),
        TwoEffectState::start(),
        8,
        &mut inner,
        &mut cleanup,
        &|| false,
    )
    .expect("the fixture run completes");
    journal
}

/// Rewrite the observation of the `Observed` entry at `index`, leaving its
/// request, turn and scope untouched so structural validation still passes.
fn retag_observation(
    journal: &Journal<TwoEffectProgram>,
    index: usize,
    replacement: Tagged,
) -> Journal<TwoEffectProgram> {
    let mut entries = journal.entries().to_vec();
    match &mut entries[index] {
        JournalEntry::Observed { observation, .. } => *observation = replacement,
        other => panic!("entry {index} is not an Observed entry: {other:?}"),
    }
    Journal::from_entries(entries)
}

#[test]
fn a_tampered_answer_that_structural_validation_accepts_is_refused_by_signature_checking() {
    let tampered = retag_observation(
        &genuine_journal(),
        1,
        Tagged::new("model", "model.answer.v1", "t0"),
    );

    // The existing structural validator cannot see this: observation and
    // request are the same Rust type, and every scope, turn and request
    // identity is untouched.
    assert_eq!(tampered.validate(&scope()), Ok(()));

    assert_eq!(
        validate_journal_signatures(&tampered, &table(), tag_of, tag_of),
        Err(JournalSignatureError {
            at: 1,
            mismatch: SignatureMismatch::AnswerForWrongEffect {
                requested: "clock".to_string(),
                answered: "model".to_string(),
            },
        })
    );
}

#[test]
fn a_tampered_answer_shape_is_refused_at_its_exact_entry() {
    let tampered = retag_observation(
        &genuine_journal(),
        4,
        Tagged::new("model", "model.answer.v2", "t1"),
    );
    assert_eq!(tampered.validate(&scope()), Ok(()));
    assert_eq!(
        validate_journal_signatures(&tampered, &table(), tag_of, tag_of),
        Err(JournalSignatureError {
            at: 4,
            mismatch: SignatureMismatch::AnswerShapeMismatch {
                effect_id: "model".to_string(),
                declared: "model.answer.v1".to_string(),
                presented: "model.answer.v2".to_string(),
            },
        })
    );
}

#[test]
fn journal_signature_checking_is_deterministic_and_reports_the_first_offending_entry() {
    let genuine = genuine_journal();
    let both_tampered = retag_observation(
        &retag_observation(&genuine, 1, Tagged::new("model", "model.answer.v1", "t0")),
        4,
        Tagged::new("clock", "clock.answer.v1", "t1"),
    );

    let first = validate_journal_signatures(&both_tampered, &table(), tag_of, tag_of);
    let second = validate_journal_signatures(&both_tampered, &table(), tag_of, tag_of);
    assert_eq!(first, second, "signature checking must be deterministic");
    assert_eq!(
        first.expect_err("both entries are tampered").at,
        1,
        "the earliest offending entry in journal order is reported; \
         the journal is never sorted or skipped past"
    );
}

#[test]
fn a_journal_recovered_under_a_table_that_no_longer_declares_its_effect_is_refused() {
    // The "resuming after a code change can execute state under
    // incompatible semantics" case: the journal is genuine, but the
    // signature table now in force no longer declares `model`.
    let narrowed = EffectSignatureTable::new(vec![EffectSignature::new(
        "clock",
        "clock.request.v1",
        "clock.answer.v1",
    )])
    .expect("well formed");
    assert_eq!(
        validate_journal_signatures(&genuine_journal(), &narrowed, tag_of, tag_of),
        Err(JournalSignatureError {
            at: 3,
            mismatch: SignatureMismatch::UnknownEffect {
                effect_id: "model".to_string()
            },
        })
    );
}

#[test]
fn signature_checking_dispatches_nothing_and_grants_no_authority() {
    // Construction and validation take no handler at all: there is no seam
    // through which declaring a signature could cause an effect to happen.
    // A genuine journal replayed through the signature checker alone yields
    // a verdict and nothing else.
    let journal = genuine_journal();
    assert_eq!(
        validate_journal_signatures(&journal, &table(), tag_of, tag_of),
        Ok(())
    );

    // And a table on its own refuses an answer for an effect it declares
    // without ever being handed a handler to call.
    assert_eq!(
        table().check_answer(
            &EffectTag::new("clock", "clock.request.v1"),
            &EffectTag::new("clock", "clock.answer.v2"),
        ),
        Err(SignatureMismatch::AnswerShapeMismatch {
            effect_id: "clock".to_string(),
            declared: "clock.answer.v1".to_string(),
            presented: "clock.answer.v2".to_string(),
        })
    );
}

#[test]
fn a_refused_answer_is_replayed_as_the_same_refusal_without_a_second_dispatch() {
    // Exactly-once: the refusal recorded on the first attempt is replayed
    // from the journal, and the wrapped handler is never contacted again.
    let mut inner = ScriptedHandler::new(vec![Tagged::new(
        "model",
        "model.answer.v1",
        "wrong-effect",
    )]);
    let mut checked = SignatureCheckedHandler::new(&mut inner, table(), tag_of, tag_of);
    let mut cleanup = NoCleanup;
    let (_, journal) = run(
        &TwoEffectProgram,
        scope(),
        TwoEffectState::start(),
        8,
        &mut checked,
        &mut cleanup,
        &|| false,
    )
    .expect_err("the first attempt is refused");
    drop(checked);
    assert_eq!(inner.calls, 1);

    let mut replay_inner = PanicHandler;
    let mut replay_checked =
        SignatureCheckedHandler::new(&mut replay_inner, table(), tag_of, tag_of);
    let replayed = resume(
        &TwoEffectProgram,
        scope(),
        journal,
        TwoEffectState::start(),
        8,
        &mut replay_checked,
        &mut cleanup,
        &|| false,
    );
    assert!(matches!(
        replayed.expect_err("the recorded refusal replays"),
        (DriverError::HandlerFailed { turn: 0, .. }, _)
    ));
    assert!(replay_checked.mismatches().is_empty());
}
