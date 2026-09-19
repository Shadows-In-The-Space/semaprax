//! Checkpoint codec regressions: round trip, hostile-input rejection, and
//! the "decode never trusts by itself" boundary against `Journal::validate`.

use super::*;
use crate::resumable_effects::core::*;

/// A non-Agent fixture program whose `State` is a small record (so encoding
/// an object, not just a scalar, is exercised) carrying a non-`Copy`
/// `Vec<String>` log, the same ownership-transfer shape `core`'s own
/// fixture uses.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CounterState {
    turn: u32,
    acc: i64,
    log: Vec<String>,
}

impl EffectCodec for CounterState {
    fn encode_effect(&self) -> Value {
        json!({
            "turn": self.turn,
            "acc": self.acc,
            "log": self.log.encode_effect(),
        })
    }
    fn decode_effect(value: &Value) -> Result<Self, String> {
        keys(value, &["turn", "acc", "log"])?;
        let turn = value["turn"]
            .as_u64()
            .ok_or_else(|| "state.turn".to_string())?;
        let turn = u32::try_from(turn).map_err(|_| "state.turn out of range".to_string())?;
        let acc = value["acc"]
            .as_i64()
            .ok_or_else(|| "state.acc".to_string())?;
        let log = Vec::<String>::decode_effect(&value["log"])?;
        Ok(CounterState { turn, acc, log })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CounterProgram {
    total_turns: u32,
    suspend_at: Option<u32>,
}

impl ResumableEffectProgram for CounterProgram {
    type State = CounterState;
    type Result = i64;
    type Request = i64;
    type Observation = i64;
    type CleanupOp = String;

    fn request(&self, state: &CounterState) -> Option<i64> {
        if state.turn < self.total_turns {
            Some(state.turn as i64)
        } else {
            None
        }
    }

    fn transition(
        &self,
        state: &CounterState,
        observation: Option<&i64>,
    ) -> Step<CounterState, i64> {
        match observation {
            None => Step::Complete(state.acc),
            Some(obs) => {
                let mut next = state.clone();
                next.acc += obs;
                next.log.push(format!("turn-{}:{}", state.turn, obs));
                next.turn += 1;
                if self.suspend_at == Some(next.turn) {
                    Step::Suspend(next)
                } else if next.turn >= self.total_turns {
                    Step::Complete(next.acc)
                } else {
                    Step::Continue(next)
                }
            }
        }
    }

    fn cleanup_plan(&self, _state: &CounterState) -> Vec<String> {
        Vec::new()
    }
}

struct MultiplyHandler;
impl EffectHandler<i64, i64> for MultiplyHandler {
    fn dispatch(&mut self, request: &i64) -> Result<i64, String> {
        Ok(request * 10)
    }
}

struct NoopCleanup;
impl CleanupHandler<String> for NoopCleanup {
    fn run(&mut self, _op: &String) -> Result<(), String> {
        Ok(())
    }
}

fn scope(root: &str, invocation: &str, epoch: u64) -> EffectScope {
    EffectScope {
        program_root: root.to_string(),
        invocation_id: invocation.to_string(),
        policy_epoch: epoch,
    }
}

fn initial() -> CounterState {
    CounterState {
        turn: 0,
        acc: 0,
        log: Vec::new(),
    }
}

fn run_journal(program: &CounterProgram, scope_val: &EffectScope) -> Journal<CounterProgram> {
    let mut handler = MultiplyHandler;
    let mut cleanup = NoopCleanup;
    let (_outcome, journal) = run(
        program,
        scope_val.clone(),
        initial(),
        10,
        &mut handler,
        &mut cleanup,
        &|| false,
    )
    .expect("these fixture programs never exhaust their budget or fail");
    journal
}

fn minimal_document(scope_val: &EffectScope, entries_value: Value) -> Vec<u8> {
    let scope_value = scope_json(scope_val);
    let digest = checkpoint_digest(
        RESUMABLE_EFFECTS_CHECKPOINT_SCHEMA,
        &scope_value,
        &entries_value,
    );
    let doc = json!({
        "schema": RESUMABLE_EFFECTS_CHECKPOINT_SCHEMA,
        "scope": scope_value,
        "digest": digest,
        "entries": entries_value,
    });
    format!("{doc}\n").into_bytes()
}

#[test]
fn round_trip_of_a_multi_turn_suspended_journal_preserves_every_entry_exactly() {
    let program = CounterProgram {
        total_turns: 3,
        suspend_at: Some(2),
    };
    let scope_val = scope("root:v1", "inv-1", 7);
    let journal = run_journal(&program, &scope_val);

    let bytes = encode_checkpoint(&scope_val, &journal);
    let decoded: Journal<CounterProgram> = decode_checkpoint(&bytes, &scope_val)
        .expect("a document just encoded under the same scope must decode");
    assert_eq!(decoded.entries(), journal.entries());
}

#[test]
fn encoding_the_same_journal_twice_is_byte_for_byte_identical() {
    let program = CounterProgram {
        total_turns: 2,
        suspend_at: None,
    };
    let scope_val = scope("root:v1", "inv-2", 1);
    let journal = run_journal(&program, &scope_val);

    let a = encode_checkpoint(&scope_val, &journal);
    let b = encode_checkpoint(&scope_val, &journal);
    assert_eq!(
        a, b,
        "checkpoint encoding must be a deterministic function of its input"
    );
}

#[test]
fn decode_reconstructs_an_out_of_order_journal_without_replicating_validate() {
    // A bare terminal `Transition` at turn 0 with no Intent/Observed before
    // it, followed by an `Intent` at turn 1: structurally illegal for
    // `Journal::validate` (an entry after a terminal), but this codec's job
    // is only to reconstruct entries, never to re-derive `validate`'s
    // ordering discipline.
    let scope_val = scope("root:v1", "inv-3", 1);
    let entries: Vec<JournalEntry<CounterProgram>> = vec![
        JournalEntry::Transition {
            turn: 0,
            scope: scope_val.clone(),
            step: Step::Complete(9),
        },
        JournalEntry::Intent {
            turn: 1,
            scope: scope_val.clone(),
            request: 5,
        },
    ];
    let journal = Journal::from_entries(entries);

    let bytes = encode_checkpoint(&scope_val, &journal);
    let decoded: Journal<CounterProgram> = decode_checkpoint(&bytes, &scope_val)
        .expect("decode reconstructs entries even when their order is invalid");
    assert_eq!(decoded.entries(), journal.entries());

    let err = decoded
        .validate(&scope_val)
        .expect_err("validate, not decode, must catch the illegal ordering");
    assert_eq!(err, JournalError::EntryAfterTerminal { at: 1 });
}

#[test]
fn a_decoded_journal_still_cannot_be_resumed_under_a_different_scope() {
    let program = CounterProgram {
        total_turns: 3,
        suspend_at: Some(1),
    };
    let minted_scope = scope("root:v1", "inv-4", 1);
    let journal = run_journal(&program, &minted_scope);

    let bytes = encode_checkpoint(&minted_scope, &journal);
    let decoded: Journal<CounterProgram> = decode_checkpoint(&bytes, &minted_scope)
        .expect("decoding under the minting scope must succeed");

    // Recovering the bytes grants no authority: resuming under a scope the
    // caller did not itself derive is refused exactly as it would be for a
    // journal that was never serialized at all.
    let reminted_scope = scope("root:v1", "inv-4", 2);
    let mut handler = MultiplyHandler;
    let mut cleanup = NoopCleanup;
    let (err, _journal) = resume(
        &program,
        reminted_scope,
        decoded,
        initial(),
        10,
        &mut handler,
        &mut cleanup,
        &|| false,
    )
    .unwrap_err();
    assert_eq!(
        err,
        DriverError::Journal(JournalError::WrongPolicyEpoch { at: 0 })
    );
}

#[test]
fn corrupted_bytes_are_rejected_as_malformed_not_panicking() {
    let scope_val = scope("root:v1", "inv-5", 1);
    let err = decode_checkpoint::<CounterProgram>(b"{not json", &scope_val).unwrap_err();
    assert!(matches!(err, CodecError::Malformed(_)));
}

#[test]
fn a_truncated_document_is_rejected_as_malformed() {
    let program = CounterProgram {
        total_turns: 2,
        suspend_at: None,
    };
    let scope_val = scope("root:v1", "inv-6", 1);
    let journal = run_journal(&program, &scope_val);
    let bytes = encode_checkpoint(&scope_val, &journal);

    let truncated = &bytes[..bytes.len() / 2];
    let err = decode_checkpoint::<CounterProgram>(truncated, &scope_val).unwrap_err();
    assert!(matches!(err, CodecError::Malformed(_)));
}

#[test]
fn an_oversized_document_is_rejected_before_it_is_parsed() {
    let scope_val = scope("root:v1", "inv-7", 1);
    let oversized = vec![b'x'; MAX_CHECKPOINT_BYTES + 1];
    let err = decode_checkpoint::<CounterProgram>(&oversized, &scope_val).unwrap_err();
    assert_eq!(err, CodecError::TooLarge);
}

#[test]
fn too_many_entries_is_rejected_before_the_digest_is_even_checked() {
    let scope_val = scope("root:v1", "inv-8", 1);
    let entries_value = Value::Array(vec![Value::Null; MAX_CHECKPOINT_ENTRIES + 1]);
    let scope_value = scope_json(&scope_val);
    // A digest that could not possibly be correct: proves the entry-count
    // bound is enforced before the digest is ever computed or compared.
    let doc = json!({
        "schema": RESUMABLE_EFFECTS_CHECKPOINT_SCHEMA,
        "scope": scope_value,
        "digest": "sha256:0",
        "entries": entries_value,
    });
    let bytes = format!("{doc}\n").into_bytes();
    let err = decode_checkpoint::<CounterProgram>(&bytes, &scope_val).unwrap_err();
    assert_eq!(err, CodecError::TooManyEntries);
}

#[test]
fn a_wrong_schema_name_is_rejected_specifically() {
    let scope_val = scope("root:v1", "inv-9", 1);
    let scope_value = scope_json(&scope_val);
    let entries_value = Value::Array(Vec::new());
    let digest = checkpoint_digest(
        "semaprax.resumable-effects-checkpoint.v0",
        &scope_value,
        &entries_value,
    );
    let doc = json!({
        "schema": "semaprax.resumable-effects-checkpoint.v0",
        "scope": scope_value,
        "digest": digest,
        "entries": entries_value,
    });
    let bytes = format!("{doc}\n").into_bytes();
    let err = decode_checkpoint::<CounterProgram>(&bytes, &scope_val).unwrap_err();
    assert_eq!(err, CodecError::SchemaMismatch);
}

#[test]
fn a_tampered_entry_is_rejected_by_digest_mismatch() {
    let program = CounterProgram {
        total_turns: 1,
        suspend_at: None,
    };
    let scope_val = scope("root:v1", "inv-10", 1);
    let journal = run_journal(&program, &scope_val);
    let bytes = encode_checkpoint(&scope_val, &journal);

    let mut doc: Value = serde_json::from_str(std::str::from_utf8(&bytes).unwrap()).unwrap();
    assert_eq!(doc["entries"][0]["kind"], "intent");
    // Flip the recorded request value without recomputing the digest.
    doc["entries"][0]["request"] = json!(999_999);
    let tampered = format!("{doc}\n").into_bytes();

    let err = decode_checkpoint::<CounterProgram>(&tampered, &scope_val).unwrap_err();
    assert_eq!(err, CodecError::DigestMismatch);
}

#[test]
fn a_stale_program_root_is_rejected_specifically_not_as_invocation_or_epoch() {
    let program = CounterProgram {
        total_turns: 1,
        suspend_at: None,
    };
    let minted = scope("root:v1", "inv-11", 1);
    let journal = run_journal(&program, &minted);
    let bytes = encode_checkpoint(&minted, &journal);

    let expected = scope("root:v2", "inv-11", 1);
    let err = decode_checkpoint::<CounterProgram>(&bytes, &expected).unwrap_err();
    assert_eq!(err, CodecError::StaleProgramRoot);
    assert_ne!(err, CodecError::WrongInvocation);
    assert_ne!(err, CodecError::WrongPolicyEpoch);
}

#[test]
fn a_wrong_invocation_is_rejected_specifically_not_as_program_root_or_epoch() {
    let program = CounterProgram {
        total_turns: 1,
        suspend_at: None,
    };
    let minted = scope("root:v1", "inv-12", 1);
    let journal = run_journal(&program, &minted);
    let bytes = encode_checkpoint(&minted, &journal);

    let expected = scope("root:v1", "inv-other", 1);
    let err = decode_checkpoint::<CounterProgram>(&bytes, &expected).unwrap_err();
    assert_eq!(err, CodecError::WrongInvocation);
    assert_ne!(err, CodecError::StaleProgramRoot);
    assert_ne!(err, CodecError::WrongPolicyEpoch);
}

#[test]
fn a_wrong_policy_epoch_is_rejected_specifically_not_as_program_root_or_invocation() {
    let program = CounterProgram {
        total_turns: 1,
        suspend_at: None,
    };
    let minted = scope("root:v1", "inv-13", 1);
    let journal = run_journal(&program, &minted);
    let bytes = encode_checkpoint(&minted, &journal);

    let expected = scope("root:v1", "inv-13", 2);
    let err = decode_checkpoint::<CounterProgram>(&bytes, &expected).unwrap_err();
    assert_eq!(err, CodecError::WrongPolicyEpoch);
    assert_ne!(err, CodecError::StaleProgramRoot);
    assert_ne!(err, CodecError::WrongInvocation);
}

#[test]
fn an_entry_missing_a_required_key_is_rejected_as_malformed() {
    let scope_val = scope("root:v1", "inv-14", 1);
    // "intent" requires "request"; this one omits it.
    let entries_value = Value::Array(vec![json!({"kind": "intent", "turn": 0})]);
    let bytes = minimal_document(&scope_val, entries_value);
    let err = decode_checkpoint::<CounterProgram>(&bytes, &scope_val).unwrap_err();
    assert!(matches!(err, CodecError::Malformed(_)));
}

#[test]
fn an_unknown_entry_kind_is_rejected_as_malformed() {
    let scope_val = scope("root:v1", "inv-15", 1);
    let entries_value = Value::Array(vec![json!({"kind": "bogus", "turn": 0})]);
    let bytes = minimal_document(&scope_val, entries_value);
    let err = decode_checkpoint::<CounterProgram>(&bytes, &scope_val).unwrap_err();
    assert!(matches!(err, CodecError::Malformed(_)));
}

#[test]
fn an_unknown_step_tag_is_rejected_as_malformed() {
    let scope_val = scope("root:v1", "inv-16", 1);
    let entries_value = Value::Array(vec![
        json!({"kind": "transition", "turn": 0, "step": {"tag": "bogus"}}),
    ]);
    let bytes = minimal_document(&scope_val, entries_value);
    let err = decode_checkpoint::<CounterProgram>(&bytes, &scope_val).unwrap_err();
    assert!(matches!(err, CodecError::Malformed(_)));
}

#[test]
fn an_object_with_an_extra_unexpected_key_is_rejected_as_malformed() {
    let scope_val = scope("root:v1", "inv-17", 1);
    let entries_value = Value::Array(vec![
        json!({"kind": "intent", "turn": 0, "request": 1, "extra": "surprise"}),
    ]);
    let bytes = minimal_document(&scope_val, entries_value);
    let err = decode_checkpoint::<CounterProgram>(&bytes, &scope_val).unwrap_err();
    assert!(matches!(err, CodecError::Malformed(_)));
}
