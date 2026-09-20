//! Issue #160: the shared malformed-input/wrong-binding corpus definition.
//!
//! This is the ONE source of truth every generated calling consumer's
//! shared-corpus driver (Rust/C11/C++17/TypeScript) is checked against: the
//! canonical descriptor bytes every one of the four consumers is generated
//! from, the closed set of case IDs, and the one expected outcome per case.
//! It holds pure data only -- no process spawning, no file I/O -- so it can
//! be `#[path]`-included, unmodified, from both
//! `tests/public_generic_native_adapter_v1/shared_hostile_corpus.rs` (Rust,
//! C11, C++17) and `tests/public_generic_wasm_adapter_v1/shared_hostile_corpus.rs`
//! (TypeScript/Wasm), which otherwise share no compiled crate: each
//! `#[path]`-include compiles its own copy of this same on-disk file into its
//! own separate test binary, so the two harnesses cannot literally compare
//! outcomes inside one process, but both are asserted against this single,
//! textually shared definition -- so a route that diverges from every other
//! route's outcome for the same case fails a hard assertion in its own
//! harness rather than silently passing an independent, drifted copy.
//!
//! What this corpus does NOT cover, stated once here rather than implied:
//! it exercises only the outcomes every one of the four consumers can
//! express identically today (open-time descriptor/binding rejection and
//! the per-leaf byte bound). `CarrierRejected`, `ExecutionFailed`,
//! `ResultRejected`, `AllocationFailure`, `NullArgument` (native-only), and
//! C++'s `ReleaseFailed` are exercised by each consumer's OWN existing
//! generator-produced hostile tests already (see the coverage audit in this
//! issue's report) -- duplicating them here under a false "shared" label
//! would not make them any more cross-checked, since those specific reasons
//! are not uniformly reachable across all four targets from the same
//! artifact bytes today. The full ordinal 0..=13 (native) / 0..=7 (Wasm)
//! failure-injection matrices are also deliberately excluded from this file:
//! the native and Core Wasm carrier protocols have different phase counts
//! (14 vs. 8 injectable ordinals), so "ordinal N" is not the same logical
//! phase across native and Wasm and a literal per-ordinal cross-language
//! comparison would be comparing different things under the same name. Each
//! route's own full local matrix remains covered by its existing generated
//! test, unmodified.
//!
//! Issue #173 adds fully formed alternate bindings and a canonical encoded
//! Descriptor-v1 baseline. The shared descriptor cases mutate individual
//! framed fields, UTF-8, schema, length, order, and frame count, then pin the
//! reference decoder/replay reason before passing identical bytes to all four
//! generated consumers. Each generated caller also checks the Descriptor-v1
//! frame envelope before its byte-exact trusted-descriptor pairing. The
//! provider ABI still treats its descriptor as authenticated bytes. The
//! reference replay accepts a presentation-name-only change to the same
//! identity; calling-consumer pairing remains byte-exact by its own contract.

/// The one descriptor baseline every one of the four generated consumers is
/// generated from in the shared-corpus harnesses. Provider-family-agnostic
/// (unlike a provider binding, which is inherently native- or Wasm-shaped),
/// so this exact byte sequence is fed to `generate_rust_calling_consumer`,
/// `generate_c_calling_consumer`, `generate_cxx_calling_consumer`, and
/// `generate_typescript_calling_consumer` alike -- the descriptor-mutation
/// cases below are the one case family that is byte-for-byte identical
/// across all four routes, not merely recipe-identical.
pub fn baseline_descriptor_bytes() -> &'static [u8] {
    use std::sync::OnceLock;

    use semaprax::public_generic_abi::descriptor::{DescriptorV1, InstanceBinding};
    static BASELINE: OnceLock<Vec<u8>> = OnceLock::new();
    BASELINE.get_or_init(|| {
        DescriptorV1::new(
            "issue173.shared.export",
            "shared_export",
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
            format!("sha256:{}", "c".repeat(64)),
            InstanceBinding {
                term: "@13:issue173.pair<bytes,bool>".to_owned(),
                instance_digest: format!("sha256:{}", "d".repeat(64)),
            },
            InstanceBinding {
                term: "@13:issue173.pair<bytes,i64>".to_owned(),
                instance_digest: format!("sha256:{}", "e".repeat(64)),
            },
        )
        .encode()
    })
}

/// Mutations of actual Descriptor-v1 frames. Each entry changes framing,
/// identity, or one presentation field. The Rust reference replay outcome is
/// pinned below before the same bytes enter generated consumers.
pub fn structured_descriptor_cases() -> Vec<(&'static str, Vec<u8>, &'static str, &'static str)> {
    let baseline = baseline_descriptor_bytes();
    let mut frames = Vec::with_capacity(12);
    let mut offset = 0usize;
    for _ in 0..12 {
        let prefix: [u8; 8] = baseline[offset..offset + 8].try_into().unwrap();
        let length = usize::try_from(u64::from_le_bytes(prefix)).unwrap();
        let start = offset + 8;
        frames.push(start..start + length);
        offset = start + length;
    }
    assert_eq!(offset, baseline.len());
    let mut cases = Vec::new();
    let mut changed = baseline.to_vec();
    let schema_end = frames[0].end;
    changed[schema_end - 1] = b'2';
    cases.push((
        "descriptor_unknown_schema",
        changed,
        "SPX-PG701",
        "ae18c7e8d694b441248e75772ca328ab0a2b5c30bd2cc75aed20abdc81a66581",
    ));

    let mut changed = baseline.to_vec();
    changed[frames[3].start] = 0xff;
    cases.push((
        "descriptor_invalid_utf8_export_id",
        changed,
        "SPX-PG701",
        "ed3f8caa5b0db3e4437890b2e634985a0139017e5860de6e75fcf7ee43622188",
    ));

    let mut changed = baseline.to_vec();
    changed[frames[4].start] = b'x';
    cases.push((
        "descriptor_stale_program_root",
        changed,
        "SPX-PG703",
        "4ab9e5a74458a2cbc78ce6a7058b00e07c083f826e073b5e39df7f75b41f449d",
    ));

    let mut changed = baseline.to_vec();
    let root = baseline[frames[4].clone()].to_vec();
    let source = baseline[frames[5].clone()].to_vec();
    assert_eq!(root.len(), source.len());
    changed[frames[4].clone()].copy_from_slice(&source);
    changed[frames[5].clone()].copy_from_slice(&root);
    cases.push((
        "descriptor_reordered_context",
        changed,
        "SPX-PG703",
        "30ffdd3b8914c5a3db02cdacaaecc8d2455ab4ee8104c9370125350555dd5a94",
    ));

    let mut changed = baseline.to_vec();
    changed[frames[5].clone()].copy_from_slice(&root);
    cases.push((
        "descriptor_duplicate_context",
        changed,
        "SPX-PG703",
        "2044d90537fa0489da9a7b91013b21ed8ae761675e638d62aba1e8a3deea1089",
    ));

    let mut changed = baseline.to_vec();
    changed.pop();
    cases.push((
        "descriptor_truncated_final_frame",
        changed,
        "SPX-PG701",
        "63ccea6b140df4018eecb9339e31b087f99aa07106c7e4ad64efc682d825a40f",
    ));

    let mut changed = baseline.to_vec();
    changed.extend_from_slice(&0u64.to_le_bytes());
    cases.push((
        "descriptor_extra_frame",
        changed,
        "SPX-PG701",
        "96db6b09c830f6f74a3dbbd9f24654af0b8f765ec8f61d4c9e7f8e405a0748f2",
    ));

    let mut changed = baseline.to_vec();
    changed[0..8].copy_from_slice(&(65_537u64).to_le_bytes());
    cases.push((
        "descriptor_overlong_schema_claim",
        changed,
        "SPX-PG701",
        "201aed8281fcc24e9e4b414e4c481a7ed295d5704896a747d3c3f8f4b7118496",
    ));

    // Reference identity replay permits this presentation-only change, while
    // the generated calling consumer's frozen pairing contract is byte-exact.
    let mut changed = baseline.to_vec();
    changed[frames[11].start + 4] = b'E';
    cases.push((
        "descriptor_presentation_rename",
        changed,
        "REFERENCE_ACCEPTED",
        "67ef2381b1c7f08c7aaf4f11c960404133b2e477a51e0915a81d2914cf566350",
    ));
    cases
}

/// The twelve canonical Descriptor-v1 frame ranges of
/// [`baseline_descriptor_bytes`], as content ranges (the eight-byte
/// little-endian length prefix of frame `n` occupies
/// `frames[n].start - 8 .. frames[n].start`). Field order is frozen by
/// `src/public_generic_abi/descriptor.rs::identity_preimage` plus the
/// trailing `export_name` frame: 0 schema, 1 boundary_profile,
/// 2 type_grammar_schema, 3 export_id, 4 program_root_digest,
/// 5 source_projection_digest, 6 public_surface_digest, 7 input.term,
/// 8 input.instance_digest, 9 result.term, 10 result.instance_digest,
/// 11 export_name.
fn baseline_frames() -> Vec<std::ops::Range<usize>> {
    let baseline = baseline_descriptor_bytes();
    let mut frames = Vec::with_capacity(12);
    let mut offset = 0usize;
    for _ in 0..12 {
        let prefix: [u8; 8] = baseline[offset..offset + 8].try_into().unwrap();
        let length = usize::try_from(u64::from_le_bytes(prefix)).unwrap();
        let start = offset + 8;
        frames.push(start..start + length);
        offset = start + length;
    }
    assert_eq!(offset, baseline.len());
    frames
}

/// Issue #173: descriptors a generated calling consumer is *configured
/// with*, i.e. the caller submits bytes that are identical to the trusted
/// bytes the consumer embedded at generation time.
///
/// This is the discriminating half of the hostile corpus.
/// [`structured_descriptor_cases`] submits mutated bytes to a consumer
/// generated from the *canonical* baseline, so the consumer's byte-exact
/// pairing check alone already refuses every one of them — a consumer whose
/// structural envelope check were deleted entirely would still pass that
/// family. Here pairing cannot refuse anything, because the submitted and
/// trusted bytes are equal by construction, so only the consumer's own
/// bounded Descriptor-v1 envelope check can fail closed. Each case drives
/// exactly one distinct branch of that check (`canonical_descriptor_v1` in
/// each generated consumer, and its C11/TypeScript transliterations):
///
/// | case | branch it alone exercises |
/// |---|---|
/// | `truncated_final_frame` | a declared frame runs past the end of the document |
/// | `unknown_descriptor_schema` | frame 0 is not the frozen descriptor schema literal |
/// | `stale_boundary_profile_version` | frame 1 is not the frozen boundary-profile literal |
/// | `stale_type_grammar_version` | frame 2 is not the frozen type-grammar literal |
/// | `invalid_utf8_export_id` | a frame's content is not UTF-8 |
/// | `trailing_bytes_after_final_frame` | bytes remain after the twelfth frame |
///
/// Returned tuple: the stable case id, the bytes, the reference
/// `descriptor::decode` refusal code — `None` where the reference decoder
/// deliberately *admits* the document — and the reference
/// `descriptor::replay`-against-the-canonical-baseline refusal code.
///
/// The two `stale_*_version` cases are the reason the third element is an
/// `Option`. `decode` validates framing, bounds, UTF-8 and the descriptor
/// schema literal only; the frozen boundary-profile and type-grammar
/// versions are enforced by `replay` (`SPX-PG704`), not by `decode`. A
/// generated consumer has no trusted peer descriptor to replay against when
/// its own configured bytes are the hostile ones, so it must enforce all
/// three frozen version literals structurally — which is exactly the
/// "allowing a consumer to ignore fields it does not understand in a closed
/// v1 schema" failure issue #173 puts explicitly out of scope. These two
/// cases are the only ones in this corpus a reference-decoder-only reading
/// of the contract would let through.
///
/// Four of these six documents are byte-identical to a
/// [`structured_descriptor_cases`] entry (`truncated_final_frame`,
/// `unknown_descriptor_schema`, `invalid_utf8_export_id`,
/// `trailing_bytes_after_final_frame`). That is deliberate and is not
/// duplicated coverage: the same bytes prove a different property in each
/// family. There they are *submitted* to a consumer generated from the
/// canonical baseline, where pairing refuses them; here they *are* the
/// consumer's configured trusted value, where pairing cannot. Reusing the
/// same bytes is what makes the two results comparable.
pub fn malformed_trusted_descriptor_cases(
) -> Vec<(&'static str, Vec<u8>, Option<&'static str>, &'static str)> {
    let baseline = baseline_descriptor_bytes();
    let frames = baseline_frames();
    let mut cases = Vec::new();

    let mut changed = baseline.to_vec();
    changed.pop().expect("the canonical baseline is non-empty");
    cases.push((
        "truncated_final_frame",
        changed,
        Some("SPX-PG701"),
        "SPX-PG701",
    ));

    // Frames 0, 1 and 2 are the three frozen schema literals. Each mutation
    // rewrites only the trailing version digit, so the document stays
    // well-framed, in-bounds and valid UTF-8 and nothing but the version
    // literal itself can refuse it.
    for (frame, case) in [
        (0usize, "unknown_descriptor_schema"),
        (1, "stale_boundary_profile_version"),
        (2, "stale_type_grammar_version"),
    ] {
        let last = frames[frame].end - 1;
        assert_eq!(baseline[last], b'1', "{case}: expected a v1 literal");
        let mut changed = baseline.to_vec();
        changed[last] = b'2';
        // `decode` checks frame 0 only; frames 1 and 2 reach `replay`.
        let decode_refusal = if frame == 0 { Some("SPX-PG701") } else { None };
        let replay_refusal = if frame == 0 { "SPX-PG701" } else { "SPX-PG704" };
        cases.push((case, changed, decode_refusal, replay_refusal));
    }

    let mut changed = baseline.to_vec();
    changed[frames[3].start] = 0xff;
    cases.push((
        "invalid_utf8_export_id",
        changed,
        Some("SPX-PG701"),
        "SPX-PG701",
    ));

    // A thirteenth, zero-length frame. Every one of the twelve canonical
    // frames still parses; only the "no bytes may remain" rule refuses it.
    let mut changed = baseline.to_vec();
    changed.extend_from_slice(&0u64.to_le_bytes());
    cases.push((
        "trailing_bytes_after_final_frame",
        changed,
        Some("SPX-PG701"),
        "SPX-PG701",
    ));

    cases
}

/// The five malformed-trusted documents used for executable mutation
/// negatives of generated consumer envelope checks.  This intentionally
/// excludes `stale_boundary_profile_version`: that branch remains covered by
/// the closed six-case corpus, but it is not one of issue #173's requested
/// mutation controls.  Keeping this selection next to the bytes prevents a
/// renderer-specific test from silently choosing a different fixture.
pub fn malformed_trusted_descriptor_mutation_cases(
) -> Vec<(&'static str, Vec<u8>, Option<&'static str>, &'static str)> {
    const NAMES: [&str; 5] = [
        "truncated_final_frame",
        "unknown_descriptor_schema",
        "stale_type_grammar_version",
        "invalid_utf8_export_id",
        "trailing_bytes_after_final_frame",
    ];
    let cases = malformed_trusted_descriptor_cases();
    let selected: Vec<_> = cases
        .into_iter()
        .filter(|(name, _, _, _)| NAMES.contains(name))
        .collect();
    assert_eq!(
        selected
            .iter()
            .map(|(name, _, _, _)| *name)
            .collect::<Vec<_>>(),
        NAMES.to_vec(),
        "the executable mutation controls must remain the requested closed set"
    );
    selected
}

/// Versioned identity for the composed hostile corpus owned by issues #160 and
/// #173. The outcome-manifest digest below covers the canonical baseline and
/// every shared consumer case id/outcome. It additionally binds the exact bytes
/// and refusal classes for the structured and malformed-trusted descriptor
/// cases that this shared module itself constructs. Native/Wasm driver-local
/// mutation recipes remain outside this digest and are checked by execution.
pub const HOSTILE_CORPUS_SCHEMA: &str = "semaprax.public-generic-hostile-corpus.v1";

/// SHA-256 of the deterministic manifest assembled by
/// `versioned_manifest_digest_is_stable`. Keep this pinned when the corpus
/// changes; a changed shared id/outcome, shared-module mutation, or baseline
/// must deliberately mint a new corpus version or update this known-answer.
pub const HOSTILE_CORPUS_MANIFEST_DIGEST: &str =
    "sha256:8b9534dd79b5f4e6f3be06b76750d4586eb835b98a064430288f0c53d4fa5214";

pub const HOSTILE_CORPUS_SHARED_CASE_COUNT: usize = 17;
pub const HOSTILE_CORPUS_MALFORMED_TRUSTED_CASE_COUNT: usize = 6;

/// Restates `src/public_generic_abi/boundary_profile.rs::MAX_BYTES_PER_LEAF`
/// (64 KiB), exactly like every generated consumer already restates it
/// rather than depending on the `semaprax` crate (a generated artifact must
/// build standalone). The native shared-corpus harness additionally asserts
/// this literal equals the real constant so a future bound change cannot
/// drift silently -- see `shared_hostile_corpus.rs`'s own assertion.
pub const MAX_BYTES_PER_LEAF: usize = 64 * 1024;

/// One entry per case: a stable id (also the exact prefix each generated
/// driver prints as `SHARED_CORPUS <case_id> <STATUS>`) and the single
/// expected normalized status every route must agree on. `STATUS` is one of
/// `ACCEPTED`, `DESCRIPTOR_REJECTED`, `PROVIDER_MISMATCH`,
/// `CAPACITY_EXCEEDED` -- the closed subset of the shared
/// `DescriptorRejected`/`ProviderMismatch`/`CapacityExceeded`/accepted
/// vocabulary every one of Rust's `Error`, C's `spx_pg_consumer_status`,
/// C++'s `ErrorKind`, and TypeScript's `SemapraxPublicGenericError.kind`
/// already restate identically (see the coverage audit).
pub const EXPECTED: &[(&str, &str)] = &[
    ("success_baseline", "ACCEPTED"),
    ("descriptor_first_byte_flipped", "DESCRIPTOR_REJECTED"),
    ("binding_last_byte_flipped", "PROVIDER_MISMATCH"),
    ("descriptor_names_different_document", "DESCRIPTOR_REJECTED"),
    ("descriptor_unknown_schema", "DESCRIPTOR_REJECTED"),
    ("descriptor_invalid_utf8_export_id", "DESCRIPTOR_REJECTED"),
    ("descriptor_stale_program_root", "DESCRIPTOR_REJECTED"),
    ("descriptor_reordered_context", "DESCRIPTOR_REJECTED"),
    ("descriptor_duplicate_context", "DESCRIPTOR_REJECTED"),
    ("descriptor_truncated_final_frame", "DESCRIPTOR_REJECTED"),
    ("descriptor_extra_frame", "DESCRIPTOR_REJECTED"),
    ("descriptor_overlong_schema_claim", "DESCRIPTOR_REJECTED"),
    ("descriptor_presentation_rename", "DESCRIPTOR_REJECTED"),
    ("exactly_per_leaf_bound_accepted", "ACCEPTED"),
    ("one_byte_over_per_leaf_bound_rejected", "CAPACITY_EXCEEDED"),
    // Issue #173: a fully well-formed alternate `NativeProviderBindingV1` /
    // `WasmProviderBindingV1` (not a corrupted byte string) whose wrapped
    // `CarrierBindingV1` names the OTHER route's `TargetProfile` --
    // `TargetProfile::CoreWasm` submitted to the native route,
    // `TargetProfile::NativeC11` submitted to the Wasm route -- exercising
    // "cross-runtime replay" (issue #173's own term) end to end through the
    // real compiled provider / real generated wasm-provider.ts, not merely
    // through the reference `CarrierBindingV1`/binding codec's own unit
    // tests (which already covered this at the single-route, non-generated
    // level; see this file's module doc for that distinction).
    ("binding_wrong_target_profile", "PROVIDER_MISMATCH"),
    // A fully well-formed alternate binding naming the CORRECT target
    // profile but a different `provider_artifact_digest` and
    // `exported_endpoint_symbol`/`exported_endpoint_export_name` -- i.e. a
    // legitimate-shaped credential for a DIFFERENT deployed provider
    // artifact, not an arbitrary corrupted byte string. Proves the open-time
    // check requires exact agreement with THIS route's own trusted binding
    // rather than merely well-formedness or a plausible embedded digest
    // ("cross-artifact replay" / "independent recomputation rather than
    // trusting embedded digest fields", issue #173).
    ("binding_valid_for_different_artifact", "PROVIDER_MISMATCH"),
];

/// Parse every `SHARED_CORPUS <case_id> <STATUS>` line a spliced driver
/// printed to its own stdout into an ordered list of `(case_id, status)`
/// pairs, in the order printed. Never panics on unrelated output lines (a
/// compiler warning, a libtest summary line, a `console.log`) -- it only
/// looks for its own fixed marker. The marker is located anywhere within a
/// line, not only at its start: `cargo test -- --nocapture` prints a test's
/// own stdout directly after its `test <name> ... ` prefix on the SAME
/// line for the first line a test prints, so a strict line-prefix match
/// would silently drop exactly that first case.
pub fn parse_shared_corpus_lines(stdout: &str) -> Vec<(String, String)> {
    const MARKER: &str = "SHARED_CORPUS ";
    stdout
        .lines()
        .filter_map(|line| line.find(MARKER).map(|at| &line[at + MARKER.len()..]))
        .filter_map(|rest| {
            let mut parts = rest.splitn(2, ' ');
            let case_id = parts.next()?.trim();
            let status = parts.next()?.trim();
            if case_id.is_empty() || status.is_empty() {
                None
            } else {
                Some((case_id.to_owned(), status.to_owned()))
            }
        })
        .collect()
}

/// Assert one route's parsed `(case_id, status)` pairs are exactly the
/// expected set -- same case ids, same order-independent statuses, no
/// missing case, no extra case, no duplicate -- against [`EXPECTED`]. On any
/// mismatch, panics with every case's expected-vs-actual so a human sees the
/// whole picture rather than the first assertion failure.
pub fn assert_matches_expected(route: &str, actual: &[(String, String)]) {
    use std::collections::BTreeMap;

    let actual_map: BTreeMap<&str, &str> = actual
        .iter()
        .map(|(id, status)| (id.as_str(), status.as_str()))
        .collect();
    assert_eq!(
        actual_map.len(),
        actual.len(),
        "{route}: a shared-corpus case id was printed more than once: {actual:?}"
    );

    let mut mismatches = Vec::new();
    for (case_id, expected_status) in EXPECTED {
        match actual_map.get(case_id) {
            None => mismatches.push(format!(
                "{case_id}: {route} never printed a SHARED_CORPUS line for this case"
            )),
            Some(actual_status) if actual_status != expected_status => mismatches.push(format!(
                "{case_id}: {route} reported {actual_status}, expected {expected_status}"
            )),
            Some(_) => {}
        }
    }
    let unexpected: Vec<&str> = actual_map
        .keys()
        .filter(|id| !EXPECTED.iter().any(|(expected_id, _)| expected_id == *id))
        .copied()
        .collect();
    if !unexpected.is_empty() {
        mismatches.push(format!(
            "{route} printed unexpected case id(s) not in the shared manifest: {unexpected:?}"
        ));
    }
    assert!(
        mismatches.is_empty(),
        "{route} disagrees with the shared hostile-corpus manifest:\n{}",
        mismatches.join("\n")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_manifest_payload() -> Vec<u8> {
        use sha2::{Digest as _, Sha256};

        let mut manifest = String::new();
        manifest.push_str(HOSTILE_CORPUS_SCHEMA);
        manifest.push('\n');
        manifest.push_str("baseline\t");
        manifest.push_str(&format!(
            "{:x}",
            semaprax::digest_hex::LowerHex(Sha256::digest(baseline_descriptor_bytes()))
        ));
        manifest.push('\n');
        for (name, status) in EXPECTED {
            manifest.push_str("shared\t");
            manifest.push_str(name);
            manifest.push('\t');
            manifest.push_str(status);
            manifest.push('\n');
        }
        for (name, bytes, replay_refusal, expected_sha256) in structured_descriptor_cases() {
            manifest.push_str("structured\t");
            manifest.push_str(name);
            manifest.push('\t');
            manifest.push_str(replay_refusal);
            manifest.push('\t');
            manifest.push_str(expected_sha256);
            manifest.push('\n');
            assert_eq!(
                format!(
                    "{:x}",
                    semaprax::digest_hex::LowerHex(Sha256::digest(&bytes))
                ),
                expected_sha256,
                "{name}"
            );
        }
        for (name, bytes, decode_refusal, replay_refusal) in malformed_trusted_descriptor_cases() {
            manifest.push_str("malformed-trusted\t");
            manifest.push_str(name);
            manifest.push('\t');
            manifest.push_str(decode_refusal.unwrap_or("ADMITTED"));
            manifest.push('\t');
            manifest.push_str(replay_refusal);
            manifest.push('\t');
            manifest.push_str(&format!(
                "{:x}",
                semaprax::digest_hex::LowerHex(Sha256::digest(&bytes))
            ));
            manifest.push('\n');
        }
        manifest.into_bytes()
    }

    #[test]
    fn versioned_manifest_digest_is_stable() {
        use sha2::{Digest as _, Sha256};

        assert_eq!(EXPECTED.len(), HOSTILE_CORPUS_SHARED_CASE_COUNT);
        assert_eq!(
            malformed_trusted_descriptor_cases().len(),
            HOSTILE_CORPUS_MALFORMED_TRUSTED_CASE_COUNT
        );
        let digest = format!(
            "sha256:{:x}",
            semaprax::digest_hex::LowerHex(Sha256::digest(canonical_manifest_payload()))
        );
        assert_eq!(digest, HOSTILE_CORPUS_MANIFEST_DIGEST);
    }

    #[test]
    fn canonical_descriptor_mutations_have_exact_reference_refusals() {
        use semaprax::public_generic_abi::descriptor::{decode, replay};
        use sha2::{Digest as _, Sha256};

        let trusted = decode(baseline_descriptor_bytes()).unwrap();
        assert_eq!(trusted.encode(), baseline_descriptor_bytes());
        assert_eq!(
            format!(
                "{:x}",
                semaprax::digest_hex::LowerHex(Sha256::digest(baseline_descriptor_bytes()))
            ),
            "2aec79caf3374cbc59c4873679417553e9d8cf5f435eb646fb4dfea999890f30"
        );
        assert_eq!(structured_descriptor_cases().len(), 9);
        for (name, bytes, expected_code, expected_sha256) in structured_descriptor_cases() {
            assert_eq!(
                format!(
                    "{:x}",
                    semaprax::digest_hex::LowerHex(Sha256::digest(&bytes))
                ),
                expected_sha256,
                "{name}"
            );
            if expected_code == "REFERENCE_ACCEPTED" {
                let replayed = replay(&bytes, &trusted).unwrap();
                assert_ne!(replayed.export_name(), trusted.export_name());
            } else {
                let error = replay(&bytes, &trusted).unwrap_err();
                assert_eq!(error.code, expected_code, "{name}");
            }
        }
    }

    /// Issue #173: pin every malformed-trusted case's exact reference
    /// refusal, and pin the two the reference decoder deliberately admits.
    ///
    /// This is the manifest half of the contract: it proves the bytes each
    /// generated consumer is handed really are hostile, independently of
    /// whether any toolchain is installed on the host, so a skipped
    /// clang/node route cannot make the corpus look covered.
    #[test]
    fn malformed_trusted_cases_have_exact_reference_outcomes() {
        use semaprax::public_generic_abi::descriptor::{decode, replay};
        use sha2::{Digest as _, Sha256};

        let trusted = decode(baseline_descriptor_bytes()).unwrap();
        let cases = malformed_trusted_descriptor_cases();
        assert_eq!(cases.len(), 6);

        // Every case is a distinct document, distinct from the baseline, and
        // pinned by digest so a regenerated corpus cannot silently drift.
        let mut digests = std::collections::BTreeMap::new();
        for (name, bytes, decode_refusal, replay_refusal) in &cases {
            assert_ne!(
                bytes.as_slice(),
                baseline_descriptor_bytes(),
                "{name}: a hostile case must differ from the canonical baseline"
            );
            match decode(bytes) {
                Ok(_) => assert_eq!(
                    *decode_refusal, None,
                    "{name}: the reference decoder admitted a document pinned as refused"
                ),
                Err(error) => assert_eq!(
                    Some(error.code),
                    *decode_refusal,
                    "{name}: wrong reference decode refusal"
                ),
            }
            let error = replay(bytes, &trusted)
                .err()
                .unwrap_or_else(|| panic!("{name}: independent replay must fail closed"));
            assert_eq!(error.code, *replay_refusal, "{name}: wrong replay refusal");
            let digest = format!(
                "{:x}",
                semaprax::digest_hex::LowerHex(Sha256::digest(bytes))
            );
            assert!(
                digests.insert(digest, *name).is_none(),
                "{name}: two hostile cases collapsed to the same bytes"
            );
        }

        // The two version cases are the ones a reference-decoder-only
        // reading of the contract would let through; keep that distinction
        // explicit rather than implied by the table above.
        let admitted: Vec<&str> = cases
            .iter()
            .filter(|(_, _, decode_refusal, _)| decode_refusal.is_none())
            .map(|(name, _, _, _)| *name)
            .collect();
        assert_eq!(
            admitted,
            vec![
                "stale_boundary_profile_version",
                "stale_type_grammar_version"
            ]
        );
    }

    #[test]
    fn parses_shared_corpus_lines_and_ignores_unrelated_output() {
        let stdout = "running 1 test\nSHARED_CORPUS success_baseline ACCEPTED\nok - unrelated\nSHARED_CORPUS descriptor_first_byte_flipped DESCRIPTOR_REJECTED\ntest result: ok\n";
        let parsed = parse_shared_corpus_lines(stdout);
        assert_eq!(
            parsed,
            vec![
                ("success_baseline".to_owned(), "ACCEPTED".to_owned()),
                (
                    "descriptor_first_byte_flipped".to_owned(),
                    "DESCRIPTOR_REJECTED".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn finds_the_marker_mid_line_as_cargo_test_nocapture_prints_it() {
        // `cargo test -- --nocapture` prints a test's own first stdout line
        // directly after `test <name> ... ` on the SAME line -- not merely
        // at line start.
        let stdout = "test shared_hostile_corpus ... SHARED_CORPUS success_baseline ACCEPTED\nSHARED_CORPUS descriptor_first_byte_flipped DESCRIPTOR_REJECTED\nok\n";
        let parsed = parse_shared_corpus_lines(stdout);
        assert_eq!(
            parsed,
            vec![
                ("success_baseline".to_owned(), "ACCEPTED".to_owned()),
                (
                    "descriptor_first_byte_flipped".to_owned(),
                    "DESCRIPTOR_REJECTED".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn accepts_the_exact_expected_set_in_any_order() {
        let mut actual: Vec<(String, String)> = EXPECTED
            .iter()
            .map(|(id, status)| ((*id).to_owned(), (*status).to_owned()))
            .collect();
        actual.reverse();
        assert_matches_expected("test-route", &actual);
    }

    #[test]
    #[should_panic(expected = "reported PROVIDER_MISMATCH, expected DESCRIPTOR_REJECTED")]
    fn rejects_a_wrong_status_for_a_known_case() {
        let mut actual: Vec<(String, String)> = EXPECTED
            .iter()
            .map(|(id, status)| ((*id).to_owned(), (*status).to_owned()))
            .collect();
        for entry in &mut actual {
            if entry.0 == "descriptor_first_byte_flipped" {
                entry.1 = "PROVIDER_MISMATCH".to_owned();
            }
        }
        assert_matches_expected("test-route", &actual);
    }

    #[test]
    #[should_panic(expected = "never printed a SHARED_CORPUS line for this case")]
    fn rejects_a_missing_case() {
        let actual: Vec<(String, String)> = EXPECTED
            .iter()
            .skip(1)
            .map(|(id, status)| ((*id).to_owned(), (*status).to_owned()))
            .collect();
        assert_matches_expected("test-route", &actual);
    }

    #[test]
    #[should_panic(expected = "printed unexpected case id(s)")]
    fn rejects_an_unknown_extra_case() {
        let mut actual: Vec<(String, String)> = EXPECTED
            .iter()
            .map(|(id, status)| ((*id).to_owned(), (*status).to_owned()))
            .collect();
        actual.push(("an_unknown_case".to_owned(), "ACCEPTED".to_owned()));
        assert_matches_expected("test-route", &actual);
    }

    #[test]
    #[should_panic(expected = "printed more than once")]
    fn rejects_a_duplicated_case_id() {
        let mut actual: Vec<(String, String)> = EXPECTED
            .iter()
            .map(|(id, status)| ((*id).to_owned(), (*status).to_owned()))
            .collect();
        actual.push(actual[0].clone());
        assert_matches_expected("test-route", &actual);
    }
}
