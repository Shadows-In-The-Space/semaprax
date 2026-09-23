//! Compiler-owned bridge for the private authenticated native identity profile.
//! No body is inferred from a descriptor: replay the selected checked HIR, then
//! use the ordinary native emitter and its own symbols and aggregate layout.

use super::*;
use crate::public_generic_abi::descriptor::verify::{
    verify_public_generic_descriptor, VerificationOptions, VerifiedPublicGenericDescriptor,
};

pub(crate) fn emit_public_generic_identity_bridge(
    program: &ResolvedProgram,
    revision: &str,
    descriptor: &VerifiedPublicGenericDescriptor,
) -> Result<(String, String), Diagnostic> {
    hir::validate(program)?;
    verify_public_generic_descriptor(
        program,
        revision,
        descriptor.export_id(),
        descriptor.program_root_digest(),
        descriptor.accepted_bytes(),
        &VerificationOptions::default(),
    )?;
    let function = program
        .functions
        .iter()
        .find(|f| f.id.as_str() == descriptor.export_id())
        .ok_or_else(|| backend_error("authenticated native identity endpoint is missing"))?;
    let mut body = &function.body;
    while let ResolvedExprKind::Block { statements, tail } = &body.kind {
        if !statements.is_empty() {
            break;
        }
        body = tail;
    }
    let input = &descriptor.input_facts();
    if function.params.len() != 1
        || input.instance_digest != descriptor.result_facts().instance_digest
        || input.fields.is_empty()
        || input.fields.iter().any(|field| field.term != "bytes")
        || !matches!(&body.kind, ResolvedExprKind::Place(place)
            if place.root == function.params[0].id && place.projections.is_empty())
        || function
            .requires
            .iter()
            .chain(&function.ensures)
            .any(|guard| !matches!(guard.kind, ResolvedExprKind::Bool(_)))
    {
        return Err(backend_error("authenticated-native-identity.v1 requires a flat Bytes identity body and literal boolean contracts"));
    }
    let functions = function_index(program)?;
    let symbol = &functions[&FunctionExecutionId::Monomorphic(function.id.clone())].symbol;
    let record = c_record_symbol(&function.params[0].ty);
    let fields: Vec<_> = input
        .fields
        .iter()
        .map(|field| c_field_symbol(&DeclarationId::new(&field.id)))
        .collect();
    let source = format!(
        "#define SPX_NO_ENTRY_WRAPPER\n{}\n#undef SPX_NO_ENTRY_WRAPPER\n",
        // The existing provider-carrier profile emits Bytes even when the
        // selected function only moves an aggregate and contains no byte op.
        emit_hir_c_with_labels(
            program,
            &HashMap::new(),
            NativeOutputProfile::OwnedUtf8Provider,
            None
        )?
    );
    let mut bridge = format!(
        r#"
static spx_pg_status_v1 spx_pg_endpoint_checked_identity_v1(uint32_t leaf_count,
    uint8_t *const *input_leaf_bytes, const size_t *input_leaf_lens,
    uint8_t **out_leaf_bytes, size_t *out_leaf_lens) {{
    if (leaf_count != {}u) return SPX_PG_STATUS_MALFORMED_CARRIER;
    struct {record} input = {{0}}, result = {{0}};
    struct spx_context context = {{0}};
    struct spx_status_entry entries[1];
    if (!spx_context_init(&context, UINT64_C(1), entries, 1, NULL, NULL, NULL))
        return SPX_PG_STATUS_CONTRACT_FAILURE;
    spx_pg_status_v1 status = SPX_PG_STATUS_OK;
    uint32_t completed = 0;
"#,
        fields.len()
    );
    for (i, field) in fields.iter().enumerate() {
        writeln!(bridge, "    input.{field}.len = input_leaf_lens[{i}];\n    input.{field}.ptr = input_leaf_lens[{i}] ? (uint8_t *)malloc(input_leaf_lens[{i}]) : NULL;\n    if (input_leaf_lens[{i}] && !input.{field}.ptr) {{ input.{field}.len = 0; status = SPX_PG_STATUS_ALLOCATION_FAILURE; goto prepare_failed; }}\n    if (input_leaf_lens[{i}]) memcpy(input.{field}.ptr, input_leaf_bytes[{i}], input_leaf_lens[{i}]);").unwrap();
    }
    writeln!(bridge, "    SPX_PG_OBSERVE_ENDPOINT();\n    if ({symbol}(&context, &input, &result) != SPX_STATUS_SUCCESS) return SPX_PG_STATUS_CONTRACT_FAILURE;").unwrap();
    for (i, field) in fields.iter().enumerate() {
        writeln!(bridge, "    if (spx_pg_physical_phase(SPX_PG_PHASE_RESULT_ALLOCATION_STARTED, 1, {i})) {{ status = SPX_PG_STATUS_ALLOCATION_FAILURE; goto result_failed; }}\n    out_leaf_lens[{i}] = (size_t)result.{field}.len;\n    out_leaf_bytes[{i}] = result.{field}.len ? (uint8_t *)spx_pg_alloc((size_t)result.{field}.len) : NULL;\n    if (result.{field}.len && !out_leaf_bytes[{i}]) {{ status = SPX_PG_STATUS_ALLOCATION_FAILURE; goto result_failed; }}\n    completed = {i} + 1;\n    if (spx_pg_physical_phase(SPX_PG_PHASE_RESULT_ALLOCATION_COMMITTED, 1, {i})) {{ status = SPX_PG_STATUS_ALLOCATION_FAILURE; goto result_failed; }}\n    if (result.{field}.len) memcpy(out_leaf_bytes[{i}], result.{field}.ptr, (size_t)result.{field}.len);\n    SPX_PG_OBSERVE_RESULT_PAYLOAD({i}, out_leaf_bytes[{i}], out_leaf_lens[{i}]);\n    if (spx_pg_physical_phase(SPX_PG_PHASE_RESULT_PAYLOAD_COPIED, 1, {i})) {{ status = SPX_PG_STATUS_CONTRACT_FAILURE; goto result_failed; }}").unwrap();
    }
    bridge.push_str("result_failed:\n    if (status != SPX_PG_STATUS_OK) {\n        spx_pg_select_primary_failure(status);\n        for (uint32_t i = completed; i-- > 0;) spx_pg_release_payload(out_leaf_bytes, out_leaf_lens, i, 1);\n    }\n");
    for field in fields.iter().rev() {
        writeln!(bridge, "    spx_bytes_drop(&result.{field});").unwrap();
    }
    bridge.push_str("    return status;\nprepare_failed:\n");
    for field in fields.iter().rev() {
        writeln!(bridge, "    spx_bytes_drop(&input.{field});").unwrap();
    }
    bridge.push_str("    return status;\n}\n");
    Ok((source, bridge))
}
