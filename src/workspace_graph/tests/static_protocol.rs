use super::*;

#[test]
fn compact_validation_index_preserves_cross_module_signature_and_identity_proof() {
    let sources = super::identity_fact_sources();
    let programs = super::parsed_sources(&sources);
    let authored = index_authored(&programs).unwrap();
    let mut compact = WorkspaceValidationIndex::new(&programs).unwrap();
    let mut resolved_modules = Vec::new();
    for program in &programs {
        let synthetic = synthetic_program(program, &authored, &programs).unwrap();
        let resolved = hir::resolve(&synthetic).unwrap();
        compact
            .record_module(&program.module, &resolved, &programs)
            .unwrap();
        resolved_modules.push((program.module.clone(), resolved));
    }
    compact.validate_stub_signatures(&programs).unwrap();
    let compact_facts = compact.finish(&programs).unwrap();
    let retained = build_owned(sources).unwrap();
    assert_eq!(
        compact_facts,
        workspace_declaration_facts(&resolved_modules, &retained.hir.modules, &programs).unwrap()
    );
}

#[test]
fn dependencies_and_implementations_stay_out_of_runtime_graph_and_operations() {
    let provider = canonical_source(
        "iface/core.spx",
        r#"
module iface.core;
@id("iface.counter") record Counter { @id("iface.counter.value") value: i64, }
@id("iface.readable") protocol Readable {
    @id("iface.readable.read") fn read(receiver: Self) -> i64;
}
@id("iface.read") fn counter_read(receiver: Counter) -> i64 { receiver.value }
"#,
    );
    let sidecar = canonical_source(
        "iface/sidecar.spx",
        r#"
module iface.sidecar;
use protocol @id("iface.readable") from iface.core as Readable;
use type @id("iface.counter") from iface.core as Counter;
use function @id("iface.read") from iface.core as counter_read;
@id("iface.counter.readable") impl "iface.readable" for "iface.counter" {
    "iface.readable.read" = "iface.read";
}
@id("iface.main") fn main() -> i64 { counter_read(Counter { value: 42 }) }
"#,
    );
    let (build, _) = build_owned_retaining_sources_for_operations(
        vec![provider, sidecar],
        MAX_BUILDER_BYTES,
        MAX_CHANGE_BUILDER_BYTES,
    )
    .unwrap();
    let view = build.into_operation_view().unwrap();
    for excluded in [
        "iface.readable",
        "iface.readable.read",
        "iface.counter.readable",
    ] {
        assert!(!view
            .graph
            .declarations
            .iter()
            .any(|declaration| declaration.id == excluded));
        assert!(!view
            .graph
            .edges
            .iter()
            .any(|edge| edge.caller == excluded || edge.target == excluded));
        assert!(!view
            .sidecar
            .declarations
            .iter()
            .any(|declaration| declaration.id == excluded));
        assert!(!view
            .sidecar
            .imports
            .iter()
            .any(|import| import.target_id == excluded));
    }
    assert!(view
        .sidecar
        .imports
        .iter()
        .all(|import| import.kind != "protocol"));
    for retained in ["iface.counter", "iface.read"] {
        assert!(view
            .sidecar
            .imports
            .iter()
            .any(|import| import.target_id == retained));
    }
}
