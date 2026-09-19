//! Checkpoints bound to an exact workflow revision.
//!
//! A [`Checkpoint`] records the minimum needed to resume: which revision
//! compiled it, which step to resume at, a monotonic sequence number, and a
//! snapshot of the [`super::compensation::CompensationLedger`] (so resuming
//! cannot re-run a compensation, per that module's guarantee). It never
//! carries live capabilities, grants, secrets, or transport handles — there
//! is no field for any of those, by construction, matching the repository
//! invariant that those are never serialized.
//!
//! [`Checkpoint::resume`] fails closed on any drift: a revision mismatch or
//! a corrupted snapshot never resumes at the recorded step "anyway" with a
//! warning — it refuses.
//!
//! # Wire format
//!
//! [`Checkpoint::encode`]/[`Checkpoint::decode`] give this in-memory model an
//! actual byte-level durable form: a versioned (`v1`), canonical,
//! single-line JSON document terminated by one LF, with an independent
//! decoder rather than a `serde` round trip. Decoding requires the closed
//! key set at every object level, the ledger to be strictly ascending in
//! `(step, run)` order (its only possible order from
//! [`CompensationLedger::snapshot`], so an out-of-order ledger is evidence of
//! tampering rather than a legitimate encoding choice), and the exact
//! canonical re-rendering of the parsed fields to equal the supplied bytes
//! byte-for-byte. A partially written, reordered, or hand-edited generation
//! therefore fails to decode rather than being silently repaired or
//! re-sorted.
//!
//! This authenticates *representation*, not *authority*: the wire bytes
//! carry no signature and no live capability, matching the repository
//! invariant that evidence capsules carry no authority. A party who can
//! rewrite the store can mint a self-consistent document with different
//! scalar values (see `decode_does_not_authenticate_a_self_consistent_sequence_rewrite`
//! below) — decode only proves the bytes are *some* well-formed, untampered
//! encoding, never that the encoded values are the ones a live run actually
//! reached. Revision liveness against the current workflow definition is
//! [`Checkpoint::resume`]'s job, not the codec's.

use super::compensation::CompensationLedger;
use super::graph::StepId;
use crate::diagnostic::quote_json;
use serde_json::{Map, Value};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Schema identity of the wire-format checkpoint document.
pub const CHECKPOINT_WIRE_SCHEMA: &str = "semaprax.typed-workflow.checkpoint.v1";

/// Maximum accepted encoded document size, in bytes. A document larger than
/// this is refused before it is even parsed.
const MAX_WIRE_BYTES: usize = 65_536;

/// Maximum accepted number of ledger entries in one document. A distinct
/// entry exists per `(step, run)`, so this is exactly twice
/// [`super::graph::MAX_STEPS`] (256): every step may compensate on two runs.
/// That is a decode-side cap, not a retry budget -- a workload that genuinely
/// needs a third compensating run per step must raise this deliberately, and
/// will fail closed rather than silently truncate until it does.
///
/// It is also deliberately well inside [`MAX_WIRE_BYTES`]: at 4096 the byte
/// cap rejected an over-long ledger first, so the entry bound was unreachable
/// and its own regression could never fail. The two bounds are independent now.
const MAX_LEDGER_ENTRIES: usize = 512;

/// The nonclaims this wire format republishes on every decode success, and
/// which decode also cross-checks are present verbatim (an accidental or
/// deliberate mismatch is refused, so the claims cannot silently drift
/// from what the codec actually does).
const WIRE_NONCLAIMS: [&str; 4] = [
    "no_signature_or_authority_over_these_bytes",
    "no_revision_liveness_check_here_only_resume_checks_that",
    "no_defense_against_a_self_consistent_scalar_field_rewrite",
    "no_ambient_filesystem_or_network_authority_in_this_codec",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RevisionId(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    revision: RevisionId,
    step: StepId,
    sequence: u64,
    ledger_snapshot: Vec<(u32, u64)>,
    digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    RevisionDrift,
    Corrupt,
    /// Migration named a step the checkpoint was not actually resting on,
    /// or omitted a mapping for it.
    IncompatibleStep,
    /// Wire bytes exceeded a size/entry bound, or were not the exact
    /// canonical re-rendering of a well-formed checkpoint document
    /// (truncated, reordered, injected, or otherwise malformed).
    Malformed,
}

fn digest_of(
    revision: RevisionId,
    step: StepId,
    sequence: u64,
    ledger_snapshot: &[(u32, u64)],
) -> u64 {
    let mut hasher = DefaultHasher::new();
    revision.hash(&mut hasher);
    step.hash(&mut hasher);
    sequence.hash(&mut hasher);
    ledger_snapshot.hash(&mut hasher);
    hasher.finish()
}

impl Checkpoint {
    #[must_use]
    pub fn new(
        revision: RevisionId,
        step: StepId,
        sequence: u64,
        ledger: &CompensationLedger,
    ) -> Self {
        let ledger_snapshot = ledger.snapshot();
        let digest = digest_of(revision, step, sequence, &ledger_snapshot);
        Self {
            revision,
            step,
            sequence,
            ledger_snapshot,
            digest,
        }
    }

    #[must_use]
    pub fn revision(&self) -> RevisionId {
        self.revision
    }

    #[must_use]
    pub fn step(&self) -> StepId {
        self.step
    }

    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The recorded `(step, run)` compensation-ledger snapshot, in the
    /// strictly ascending order [`CompensationLedger::snapshot`] always
    /// produces. Read-only: nothing here lets a caller mutate or replay a
    /// compensation from this value, matching [`Checkpoint`]'s own
    /// non-authority (see the module docs above).
    #[must_use]
    pub fn ledger_snapshot(&self) -> &[(u32, u64)] {
        &self.ledger_snapshot
    }

    fn is_intact(&self) -> bool {
        self.digest
            == digest_of(
                self.revision,
                self.step,
                self.sequence,
                &self.ledger_snapshot,
            )
    }

    /// Resume at this checkpoint's recorded step, only if `expected_revision`
    /// matches exactly and the snapshot has not drifted from its digest.
    /// Returns the resume step, sequence, and a rebuilt compensation ledger
    /// that already knows about every compensation this run had applied.
    pub fn resume(
        &self,
        expected_revision: RevisionId,
    ) -> Result<(StepId, u64, CompensationLedger), CheckpointError> {
        if self.revision != expected_revision {
            return Err(CheckpointError::RevisionDrift);
        }
        if !self.is_intact() {
            return Err(CheckpointError::Corrupt);
        }
        Ok((
            self.step,
            self.sequence,
            CompensationLedger::restore(&self.ledger_snapshot),
        ))
    }

    /// Migrate this checkpoint from `from` to `to`, remapping its resume
    /// step through `step_map`. Fails closed (never guesses) if this
    /// checkpoint's own revision is not `from`, or if `step_map` has no
    /// entry for this checkpoint's exact step.
    pub fn migrate(
        &self,
        from: RevisionId,
        to: RevisionId,
        step_map: &[(StepId, StepId)],
    ) -> Result<Checkpoint, CheckpointError> {
        if self.revision != from {
            return Err(CheckpointError::RevisionDrift);
        }
        if !self.is_intact() {
            return Err(CheckpointError::Corrupt);
        }
        let Some(&(_, mapped)) = step_map.iter().find(|(old, _)| *old == self.step) else {
            return Err(CheckpointError::IncompatibleStep);
        };
        let ledger_snapshot = self.ledger_snapshot.clone();
        let digest = digest_of(to, mapped, self.sequence, &ledger_snapshot);
        Ok(Checkpoint {
            revision: to,
            step: mapped,
            sequence: self.sequence,
            ledger_snapshot,
            digest,
        })
    }

    /// Test-only corruption injection: returns a checkpoint whose stored
    /// digest no longer matches its content, simulating storage-layer
    /// corruption without needing a real byte-level encoding to bit-flip.
    #[cfg(test)]
    fn corrupted(mut self) -> Self {
        self.digest ^= 1;
        self
    }

    /// Encodes this checkpoint as a canonical, single-line, LF-terminated
    /// wire document. See the module docs for exactly what decoding this
    /// back authenticates and what it does not.
    #[must_use]
    pub fn encode(&self) -> String {
        render_wire(
            self.revision,
            self.step,
            self.sequence,
            &self.ledger_snapshot,
        )
    }

    /// Decodes a wire document produced by [`Checkpoint::encode`].
    ///
    /// Refuses (rather than repairs or best-effort-parses) any document
    /// that is: too large, missing its terminal LF, not valid JSON, not a
    /// closed object at any level, tagged with the wrong schema or a
    /// tampered nonclaims list, carrying a ledger that exceeds the entry
    /// bound or is not strictly ascending in `(step, run)`, or whose
    /// canonical re-rendering from the parsed fields does not reproduce
    /// the input bytes exactly.
    pub fn decode(document: &str) -> Result<Self, CheckpointError> {
        if document.len() > MAX_WIRE_BYTES || !document.ends_with('\n') {
            return Err(CheckpointError::Malformed);
        }
        let body = &document[..document.len() - 1];
        let parsed = parse_wire(body).ok_or(CheckpointError::Malformed)?;
        let digest = digest_of(
            parsed.revision,
            parsed.step,
            parsed.sequence,
            &parsed.ledger_snapshot,
        );
        let checkpoint = Checkpoint {
            revision: parsed.revision,
            step: parsed.step,
            sequence: parsed.sequence,
            ledger_snapshot: parsed.ledger_snapshot,
            digest,
        };
        if checkpoint.encode() != document {
            return Err(CheckpointError::Malformed);
        }
        Ok(checkpoint)
    }
}

struct ParsedWire {
    revision: RevisionId,
    step: StepId,
    sequence: u64,
    ledger_snapshot: Vec<(u32, u64)>,
}

fn render_wire(
    revision: RevisionId,
    step: StepId,
    sequence: u64,
    ledger_snapshot: &[(u32, u64)],
) -> String {
    let mut output = format!(
        "{{\"schema\":{},\"revision\":{},\"step\":{},\"sequence\":{},\"ledger\":[",
        quote_json(CHECKPOINT_WIRE_SCHEMA),
        quote_json(&revision.0.to_string()),
        quote_json(&step.0.to_string()),
        quote_json(&sequence.to_string()),
    );
    for (index, (entry_step, entry_run)) in ledger_snapshot.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&format!(
            "{{\"step\":{},\"run\":{}}}",
            quote_json(&entry_step.to_string()),
            quote_json(&entry_run.to_string()),
        ));
    }
    output.push_str("],\"nonclaims\":[");
    for (index, nonclaim) in WIRE_NONCLAIMS.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&quote_json(nonclaim));
    }
    output.push_str("]}\n");
    output
}

fn wire_text<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)?.as_str()
}

fn wire_closed(map: &Map<String, Value>, keys: &[&str]) -> Option<()> {
    (map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key))).then_some(())
}

fn parse_wire(body: &str) -> Option<ParsedWire> {
    let value: Value = serde_json::from_str(body).ok()?;
    let map = value.as_object()?;
    wire_closed(
        map,
        &[
            "schema",
            "revision",
            "step",
            "sequence",
            "ledger",
            "nonclaims",
        ],
    )?;
    if wire_text(map, "schema")? != CHECKPOINT_WIRE_SCHEMA {
        return None;
    }
    let claims = map.get("nonclaims")?.as_array()?;
    if claims.len() != WIRE_NONCLAIMS.len()
        || claims
            .iter()
            .zip(WIRE_NONCLAIMS)
            .any(|(claim, expected)| claim.as_str() != Some(expected))
    {
        return None;
    }
    let revision = RevisionId(wire_text(map, "revision")?.parse().ok()?);
    let step = StepId(wire_text(map, "step")?.parse().ok()?);
    let sequence: u64 = wire_text(map, "sequence")?.parse().ok()?;
    let ledger = map.get("ledger")?.as_array()?;
    if ledger.len() > MAX_LEDGER_ENTRIES {
        return None;
    }
    let mut ledger_snapshot = Vec::with_capacity(ledger.len());
    let mut previous: Option<(u32, u64)> = None;
    for entry in ledger {
        let entry = entry.as_object()?;
        wire_closed(entry, &["step", "run"])?;
        let entry_step: u32 = wire_text(entry, "step")?.parse().ok()?;
        let entry_run: u64 = wire_text(entry, "run")?.parse().ok()?;
        if let Some(previous) = previous {
            // Strictly ascending: the only order `CompensationLedger::snapshot`
            // (a `BTreeSet` iteration) ever produces. Anything else — including
            // a legitimate-looking permutation — is refused rather than
            // silently re-sorted, matching the repository's rule that ordered
            // runtime data is never repaired downstream.
            if (entry_step, entry_run) <= previous {
                return None;
            }
        }
        previous = Some((entry_step, entry_run));
        ledger_snapshot.push((entry_step, entry_run));
    }
    Some(ParsedWire {
        revision,
        step,
        sequence,
        ledger_snapshot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed_workflow::compensation::CompensationKey;

    #[test]
    fn resume_at_matching_revision_succeeds() {
        let mut ledger = CompensationLedger::new();
        ledger.apply(
            CompensationKey {
                step: StepId(2),
                run: 1,
            },
            || Ok(()),
        )
        .unwrap();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(4), 3, &ledger);

        let (step, sequence, restored) = checkpoint
            .resume(RevisionId(1))
            .expect("matching revision resumes");
        assert_eq!(step, StepId(4));
        assert_eq!(sequence, 3);
        assert!(restored.is_applied(CompensationKey {
            step: StepId(2),
            run: 1
        }));
    }

    #[test]
    fn resume_fails_closed_on_revision_drift() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(4), 3, &ledger);
        assert_eq!(
            checkpoint.resume(RevisionId(2)),
            Err(CheckpointError::RevisionDrift)
        );
    }

    #[test]
    fn resume_fails_closed_on_corruption() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(4), 3, &ledger).corrupted();
        assert_eq!(
            checkpoint.resume(RevisionId(1)),
            Err(CheckpointError::Corrupt)
        );
    }

    #[test]
    fn migrate_to_a_mapped_step_resumes_under_the_new_revision() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(4), 3, &ledger);
        let migrated = checkpoint
            .migrate(RevisionId(1), RevisionId(2), &[(StepId(4), StepId(40))])
            .expect("mapped step migrates");
        let (step, _, _) = migrated
            .resume(RevisionId(2))
            .expect("migrated checkpoint resumes under new revision");
        assert_eq!(step, StepId(40));
        // The old revision no longer resumes this migrated checkpoint.
        assert_eq!(
            migrated.resume(RevisionId(1)),
            Err(CheckpointError::RevisionDrift)
        );
    }

    #[test]
    fn migrate_without_a_mapping_for_the_actual_step_fails_closed() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(4), 3, &ledger);
        let result = checkpoint.migrate(RevisionId(1), RevisionId(2), &[(StepId(5), StepId(50))]);
        assert_eq!(result, Err(CheckpointError::IncompatibleStep));
    }

    #[test]
    fn migrate_from_the_wrong_source_revision_fails_closed() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(4), 3, &ledger);
        let result = checkpoint.migrate(RevisionId(9), RevisionId(2), &[(StepId(4), StepId(40))]);
        assert_eq!(result, Err(CheckpointError::RevisionDrift));
    }

    #[test]
    fn encode_then_decode_round_trips_exactly() {
        let mut ledger = CompensationLedger::new();
        ledger.apply(
            CompensationKey {
                step: StepId(2),
                run: 7,
            },
            || Ok(()),
        )
        .unwrap();
        let checkpoint = Checkpoint::new(RevisionId(3), StepId(5), 11, &ledger);
        let document = checkpoint.encode();
        assert!(document.starts_with(&format!(
            "{{\"schema\":{}",
            quote_json(CHECKPOINT_WIRE_SCHEMA)
        )));
        assert!(document.ends_with('\n'));

        let decoded = Checkpoint::decode(&document).expect("a freshly encoded checkpoint decodes");
        assert_eq!(decoded.revision(), RevisionId(3));
        assert_eq!(decoded.step(), StepId(5));
        assert_eq!(decoded.sequence(), 11);
        let (_, _, restored) = decoded.resume(RevisionId(3)).unwrap();
        assert!(restored.is_applied(CompensationKey {
            step: StepId(2),
            run: 7
        }));
        assert_eq!(decoded.encode(), document, "encode must be deterministic");
    }

    #[test]
    fn decode_rejects_a_document_missing_its_terminal_newline() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(1), 1, &ledger);
        let document = checkpoint.encode();
        let without_lf = document.trim_end_matches('\n');
        assert_eq!(
            Checkpoint::decode(without_lf),
            Err(CheckpointError::Malformed)
        );
    }

    #[test]
    fn decode_rejects_truncated_bytes() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(1), 1, &ledger);
        let document = checkpoint.encode();
        let truncated = &document[..document.len() - 3];
        assert_eq!(
            Checkpoint::decode(truncated),
            Err(CheckpointError::Malformed)
        );
    }

    /// Swaps two ledger entries' raw byte spans in place (not a JSON-value
    /// round trip, which would silently re-sort them back and defeat the
    /// point of the test). This produces a ledger that is a legitimate-
    /// looking permutation of a real one, but out of the only order
    /// `CompensationLedger::snapshot` ever emits.
    #[test]
    fn decode_rejects_a_reordered_ledger() {
        let mut ledger = CompensationLedger::new();
        ledger.apply(
            CompensationKey {
                step: StepId(1),
                run: 1,
            },
            || Ok(()),
        )
        .unwrap();
        ledger.apply(
            CompensationKey {
                step: StepId(9),
                run: 9,
            },
            || Ok(()),
        )
        .unwrap();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(1), 1, &ledger);
        let document = checkpoint.encode();

        let entry0 = "{\"step\":\"1\",\"run\":\"1\"}";
        let entry1 = "{\"step\":\"9\",\"run\":\"9\"}";
        assert!(document.contains(entry0));
        assert!(document.contains(entry1));
        let swapped = document
            .replacen(entry0, "@@@PLACEHOLDER@@@", 1)
            .replacen(entry1, entry0, 1)
            .replacen("@@@PLACEHOLDER@@@", entry1, 1);
        assert_ne!(swapped, document);
        assert_eq!(
            Checkpoint::decode(&swapped),
            Err(CheckpointError::Malformed),
            "a reordered ledger must not decode"
        );
    }

    #[test]
    fn decode_rejects_an_injected_byte() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(1), 1, &ledger);
        let document = checkpoint.encode();
        // One extra, structurally-valid-JSON space: `serde_json` parses it
        // fine, but the canonical renderer never produces it.
        let injected = document.replacen("\"schema\":", "\"schema\": ", 1);
        assert_ne!(injected, document);
        assert_eq!(
            Checkpoint::decode(&injected),
            Err(CheckpointError::Malformed),
            "a byte-for-byte non-canonical (but JSON-valid) document must not decode"
        );
    }

    #[test]
    fn decode_rejects_an_unknown_extra_top_level_field() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(1), 1, &ledger);
        let document = checkpoint.encode();
        let with_extra_field =
            document.replacen("\"nonclaims\":[", "\"unexpected\":\"x\",\"nonclaims\":[", 1);
        assert_ne!(with_extra_field, document);
        assert_eq!(
            Checkpoint::decode(&with_extra_field),
            Err(CheckpointError::Malformed)
        );
    }

    #[test]
    fn decode_rejects_a_ledger_beyond_the_entry_bound() {
        let mut ledger_json = String::from("[");
        for index in 0..=MAX_LEDGER_ENTRIES {
            if index > 0 {
                ledger_json.push(',');
            }
            ledger_json.push_str(&format!("{{\"step\":\"{index}\",\"run\":\"0\"}}"));
        }
        ledger_json.push(']');
        let nonclaims = WIRE_NONCLAIMS
            .iter()
            .map(|claim| quote_json(claim))
            .collect::<Vec<_>>()
            .join(",");
        let document = format!(
            "{{\"schema\":{},\"revision\":{},\"step\":{},\"sequence\":{},\"ledger\":{},\"nonclaims\":[{}]}}\n",
            quote_json(CHECKPOINT_WIRE_SCHEMA),
            quote_json("1"),
            quote_json("1"),
            quote_json("1"),
            ledger_json,
            nonclaims,
        );
        assert_eq!(
            Checkpoint::decode(&document),
            Err(CheckpointError::Malformed),
            "a ledger beyond the entry bound must not decode"
        );
    }

    /// The honest counterpart to the rejection tests above: decode
    /// authenticates *representation* (closed keys, strict ledger order,
    /// exact canonical re-rendering), never the *content* of a scalar
    /// field. A store an adversary can rewrite can mint a self-consistent
    /// document with a different `sequence`, and decode accepts it —
    /// proving the gap is real rather than asserting it away, matching
    /// the module docs' nonclaims.
    #[test]
    fn decode_does_not_authenticate_a_self_consistent_sequence_rewrite() {
        let ledger = CompensationLedger::new();
        let checkpoint = Checkpoint::new(RevisionId(1), StepId(1), 5, &ledger);
        let document = checkpoint.encode();
        let marker = "\"sequence\":\"5\"";
        assert!(document.contains(marker), "sequence field must be present");
        let rewritten = document.replacen(marker, "\"sequence\":\"999\"", 1);
        assert_ne!(rewritten, document);

        let decoded = Checkpoint::decode(&rewritten)
            .expect("a self-consistent scalar rewrite is not a codec-detectable corruption");
        assert_eq!(
            decoded.sequence(),
            999,
            "decode re-renders whatever it parsed; it does not authenticate the original value"
        );
    }
}
