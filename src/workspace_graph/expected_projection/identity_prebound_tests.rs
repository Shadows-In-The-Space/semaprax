use super::{
    checked_retention_prebound, dependency_identity_max, next_retention_prebound,
    next_retention_prebound_with_uncached_peak, retention_prebound, retention_prebound_mode,
    synthetic_builder_bytes_scoped, uncached_peak_prebound,
};
use crate::ast::Program;
fn fixture(count: usize, padding: usize, reverse: bool) -> Vec<Program> {
    let long = format!("consumer.{}", "x".repeat(padding));
    let mut provider = String::from("module provider;\n");
    for index in 0..count {
        provider.push_str(&format!(
            "@id(\"provider.f{index}\") fn f{index}(seed:i64)->i64 {{ seed+{index} }}\n"
        ));
    }
    let mut consumer = format!("module consumer;\n@id(\"{long}\") fn target()->i64{{0}}\n");
    if reverse {
        consumer = consumer.replacen(
            "module consumer;\n",
            "module consumer;\nuse function @id(\"provider.f0\") from provider as f0;\n",
            1,
        );
    } else {
        provider = provider.replacen(
            "module provider;\n",
            &format!("module provider;\nuse function @id(\"{long}\") from consumer as target;\n"),
            1,
        );
    }
    [provider, consumer]
        .into_iter()
        .enumerate()
        .map(|(index, text)| {
            crate::parse(
                &text,
                std::path::Path::new(if index == 0 {
                    "provider.spx"
                } else {
                    "consumer.spx"
                }),
            )
            .unwrap()
        })
        .collect()
}
#[test]
fn identity_prebound_preserves_every_legacy_accepted_receipt() {
    let programs = fixture(3, 40, true);
    let authored = super::super::index_authored(&programs).unwrap();
    let old = retention_prebound(&programs, &authored, false).unwrap();
    assert_eq!(
        checked_retention_prebound(&programs, &authored).unwrap(),
        old
    );
}
#[test]
fn identity_prebound_excludes_reverse_dependent_names_only_after_refusal() {
    let programs = fixture(310, 220, true);
    let authored = super::super::index_authored(&programs).unwrap();
    assert!(retention_prebound(&programs, &authored, false).is_err());
    assert!(dependency_identity_max(&programs[0], &authored, &programs).unwrap() < 100);
    assert_eq!(
        checked_retention_prebound(&programs, &authored).unwrap(),
        retention_prebound(&programs, &authored, true).unwrap()
    );
}
#[test]
fn identity_prebound_still_charges_reachable_long_identities() {
    let programs = fixture(800, 220, false);
    let authored = super::super::index_authored(&programs).unwrap();
    assert!(dependency_identity_max(&programs[0], &authored, &programs).unwrap() >= 220);
    assert!(checked_retention_prebound(&programs, &authored).is_err());
}

/// Issue #83. Pin the projection term itself instead of comparing complete
/// workspace limits, whose unrelated structural costs legitimately move as
/// the AST grows. Keep `16` literal here so increasing the production copy
/// factor reopens this regression rather than updating the test in lockstep.
#[test]
fn identity_length_uses_sixteen_bytes_per_slot_and_identity_byte() {
    let programs = fixture(24, 32, false);
    let authored = super::super::index_authored(&programs).unwrap();
    let program = &programs[0];
    let identity_slots = super::identity_slots::ast_program_identity_slots(program).unwrap();
    let short = synthetic_builder_bytes_scoped(program, &authored, &programs, Some(16), 0, true)
        .unwrap()
        .retained_hir;
    let long = synthetic_builder_bytes_scoped(program, &authored, &programs, Some(48), 0, true)
        .unwrap()
        .retained_hir;
    assert_eq!(long - short, identity_slots * (48 - 16) * 16);
}
#[test]
fn identity_prebound_json_cursor_package_is_bounded() {
    let programs = [
        (
            "dec.spx",
            include_str!("../../../std/data-json-dec/src/dec.spx"),
        ),
        (
            "examples.spx",
            include_str!("../../../std/data-json-dec/src/examples.spx"),
        ),
        (
            "tests.spx",
            include_str!("../../../std/data-json-dec/src/tests.spx"),
        ),
        ("io.spx", include_str!("../../../std/io/src/io.spx")),
    ]
    .into_iter()
    .map(|(path, text)| crate::parse(text, std::path::Path::new(path)).unwrap())
    .collect::<Vec<_>>();
    let authored = super::super::index_authored(&programs).unwrap();
    checked_retention_prebound(&programs, &authored)
        .expect("complete JSON cursor dependency pre-bound");
}

fn transient_fixture() -> Vec<Program> {
    let sources = [
            "module provider; @id(\"provider.compute\") fn compute(value: i64) -> i64 requires value >= 0 ensures result >= 0 { let first = value + 1; let second = first * 2; second + 3 }",
            "module first; use function @id(\"provider.compute\") from provider as compute; @id(\"first.run\") fn run() -> i64 { compute(1) }",
            "module second; use function @id(\"provider.compute\") from provider as compute; @id(\"second.run\") fn run() -> i64 { compute(2) }",
        ];
    sources
        .iter()
        .enumerate()
        .map(|(index, source)| {
            crate::parse(
                source,
                std::path::Path::new(if index == 0 {
                    "provider.spx"
                } else if index == 1 {
                    "first.spx"
                } else {
                    "second.spx"
                }),
            )
            .unwrap()
        })
        .collect::<Vec<_>>()
}

#[test]
fn transient_import_clones_have_one_sequential_peak_only_in_final_fallback() {
    let programs = transient_fixture();
    let authored = super::super::index_authored(&programs).unwrap();
    assert!(!programs[0].functions[0].requires.is_empty());
    assert!(!programs[0].functions[0].ensures.is_empty());
    for consumer in &programs[1..] {
        let synthetic = super::synthetic_program(consumer, &authored, &programs).unwrap();
        let stub = synthetic
            .functions
            .iter()
            .find(|function| function.name == "compute")
            .unwrap();
        assert!(matches!(stub.body.kind, crate::ast::ExprKind::Int(0)));
        let mut expected = programs[0].functions[0].clone();
        expected.name = stub.name.clone();
        expected.requires = Vec::new();
        expected.ensures = Vec::new();
        expected.body = stub.body.clone();
        assert_eq!(*stub, expected, "ordinary import changed a signature field");
        assert!(stub.requires.is_empty() && stub.ensures.is_empty());
        assert_eq!(stub.requires.capacity(), 0);
        assert_eq!(stub.ensures.capacity(), 0);
    }
    let old = retention_prebound_mode(&programs, &authored, true, 2).unwrap();
    let peak = retention_prebound_mode(&programs, &authored, true, 3).unwrap();
    assert!(
        peak.0 < old.0,
        "two transient full-function clones were summed"
    );
    assert!(peak.1 < old.1);
    assert_eq!(
        retention_prebound_mode(&programs, &authored, true, 3).unwrap(),
        peak,
        "the final fallback receipt must be deterministic"
    );

    struct Restore(usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            super::super::ACTIVE_BUILDER_LIMIT.with(|limit| limit.set(self.0));
        }
    }
    let previous = super::super::ACTIVE_BUILDER_LIMIT.with(|limit| limit.replace(peak.1));
    let _restore = Restore(previous);
    assert!(retention_prebound_mode(&programs, &authored, true, 2).is_err());
    assert_eq!(
        retention_prebound_mode(&programs, &authored, true, 3).unwrap(),
        peak,
        "the new peak receipt admits the same graph at its exact bound"
    );
    super::super::ACTIVE_BUILDER_LIMIT.with(|limit| limit.set(peak.1 - 1));
    let refusal = retention_prebound_mode(&programs, &authored, true, 3).unwrap_err();
    assert!(refusal.iter().all(|error| error.code == "SPX-G171"));
    let signature_only = retention_prebound_mode(&programs, &authored, true, 4).unwrap();
    assert!(signature_only.1 < peak.1);
    super::super::ACTIVE_BUILDER_LIMIT.with(|limit| limit.set(signature_only.1));
    assert_eq!(
        retention_prebound_mode(&programs, &authored, true, 4).unwrap(),
        signature_only
    );
    super::super::ACTIVE_BUILDER_LIMIT.with(|limit| limit.set(signature_only.1 - 1));
    assert!(retention_prebound_mode(&programs, &authored, true, 4)
        .unwrap_err()
        .iter()
        .all(|error| error.code == "SPX-G171"));
}

#[test]
fn next_prebound_skips_non_tighter_receipts_and_exhausts_at_mode_four() {
    let programs = transient_fixture();
    let authored = super::super::index_authored(&programs).unwrap();
    let mode_two = retention_prebound_mode(&programs, &authored, true, 2).unwrap();
    let mode_three = retention_prebound_mode(&programs, &authored, true, 3).unwrap();
    let mut mode = 1;
    assert!(mode_three.0 < mode_two.0);
    assert_eq!(
        next_retention_prebound(&programs, &authored, mode_two.0, &mut mode).unwrap(),
        mode_three
    );
    assert_eq!(mode, 3);
    let mode_four = retention_prebound_mode(&programs, &authored, true, 4).unwrap();
    assert!(mode_four.0 < mode_three.0);
    assert_eq!(
        next_retention_prebound(&programs, &authored, mode_three.0, &mut mode).unwrap(),
        mode_four
    );
    let exhausted =
        next_retention_prebound(&programs, &authored, mode_four.0, &mut mode).unwrap_err();
    assert_eq!(mode, 4);
    assert!(exhausted.iter().all(|error| error.code == "SPX-G171"));
}

#[test]
fn uncached_ast_peak_is_final_only_and_has_an_exact_bound() {
    let programs = transient_fixture();
    let authored = super::super::index_authored(&programs).unwrap();
    let mode_four = retention_prebound_mode(&programs, &authored, true, 4).unwrap();
    let peak = uncached_peak_prebound(&programs, &authored).unwrap();
    assert!(peak.0 < mode_four.0);

    let mut semantic_mode = 4;
    assert!(
        next_retention_prebound(&programs, &authored, mode_four.0, &mut semantic_mode).is_err()
    );
    assert_eq!(semantic_mode, 4);

    let mut uncached_mode = 4;
    assert_eq!(
        next_retention_prebound_with_uncached_peak(
            &programs,
            &authored,
            mode_four.0,
            &mut uncached_mode,
            true,
        )
        .unwrap(),
        peak,
    );
    assert_eq!(uncached_mode, 5);

    struct Restore(usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            super::super::ACTIVE_BUILDER_LIMIT.with(|limit| limit.set(self.0));
        }
    }
    let previous = super::super::ACTIVE_BUILDER_LIMIT.with(|limit| limit.replace(peak.0));
    let _restore = Restore(previous);
    assert_eq!(uncached_peak_prebound(&programs, &authored).unwrap(), peak);
    assert_eq!(
        super::checked_retention_prebound_with_uncached_peak(&programs, &authored, true).unwrap(),
        peak,
    );
    let ordinary_refusal = super::checked_retention_prebound(&programs, &authored).unwrap_err();
    let cached_refusal =
        super::checked_retention_prebound_with_uncached_peak(&programs, &authored, false)
            .unwrap_err();
    assert_eq!(
        ordinary_refusal
            .iter()
            .map(|error| error.code)
            .collect::<Vec<_>>(),
        cached_refusal
            .iter()
            .map(|error| error.code)
            .collect::<Vec<_>>(),
    );
    assert!(cached_refusal.iter().all(|error| error.code == "SPX-G171"));
    super::super::ACTIVE_BUILDER_LIMIT.with(|limit| limit.set(peak.0 - 1));
    let refusal = uncached_peak_prebound(&programs, &authored).unwrap_err();
    assert!(refusal.iter().all(|error| error.code == "SPX-G171"));
}
