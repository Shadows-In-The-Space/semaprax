//! Separate, private reservation-backed checked Bytes profile. Admission closes
//! every reached body; evaluation and canonical cleanup remain compiler-owned.
use super::*;

mod admission;

fn admitted_endpoint<'a>(
    program: &'a ResolvedProgram,
    revision: &str,
    descriptor: &VerifiedPublicGenericDescriptor,
) -> Result<&'a ResolvedFunction, Diagnostic> {
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
        .find(|function| function.id.as_str() == descriptor.export_id())
        .ok_or_else(admission::refusal)?;
    let input = descriptor.input_facts();
    if function.params.len() != 1
        || input.instance_digest != descriptor.result_facts().instance_digest
        || input.fields.is_empty()
        || input.fields.iter().any(|field| field.term != "bytes")
    {
        return Err(admission::refusal());
    }
    admission::check(program, function)?;
    Ok(function)
}

pub(crate) fn emit_public_generic_allocating_bridge(
    program: &ResolvedProgram,
    revision: &str,
    descriptor: &VerifiedPublicGenericDescriptor,
) -> Result<(String, String), Diagnostic> {
    let function = admitted_endpoint(program, revision, descriptor)?;
    let capacity = hir::analyze_byte_data_capacity(program)?;
    let capacity = capacity
        .function(function.id.as_str())
        .ok_or_else(admission::refusal)?;
    let functions = function_index(program)?;
    let symbol = &functions[&FunctionExecutionId::Monomorphic(function.id.clone())].symbol;
    let record = c_record_symbol(&function.params[0].ty);
    let fields: Vec<_> = descriptor
        .input_facts()
        .fields
        .iter()
        .map(|field| c_field_symbol(&DeclarationId::new(&field.id)))
        .collect();
    let source = format!(
        "#define SPX_NO_ENTRY_WRAPPER\n{}\n#undef SPX_NO_ENTRY_WRAPPER\n",
        emit_hir_c_with_labels(
            program,
            &HashMap::new(),
            NativeOutputProfile::ReservedBytesProvider,
            None
        )?
    );
    let mut bridge = format!(
        r#"
static spx_pg_status_v1 spx_pg_endpoint_checked_allocating_v1(uint32_t leaf_count,
    uint8_t *const *input_leaf_bytes, const size_t *input_leaf_lens,
    uint8_t **out_leaf_bytes, size_t *out_leaf_lens) {{
    if (leaf_count != {}u) return SPX_PG_STATUS_MALFORMED_CARRIER;
    struct {record} input = {{0}}, result = {{0}};
    struct spx_context context = {{0}};
    struct spx_status_entry entries[1];
    const size_t slots = {}u + leaf_count;
    const size_t overhead = sizeof(union spx_bytes_lease) + _Alignof(union spx_bytes_lease) - 1;
    size_t reservation = {}u;
    size_t total = 0;
    if (slots > (SIZE_MAX - reservation) / overhead) return SPX_PG_STATUS_CARRIER_CAPACITY;
    reservation += slots * overhead;
    for (uint32_t i = 0; i < leaf_count; ++i) {{
        if (input_leaf_lens[i] > SPX_PG_MAX_BYTES_PER_LEAF ||
            input_leaf_lens[i] > SPX_PG_MAX_TOTAL_PAYLOAD_BYTES - total ||
            input_leaf_lens[i] > SIZE_MAX - reservation) return SPX_PG_STATUS_CARRIER_CAPACITY;
        total += input_leaf_lens[i];
        reservation += input_leaf_lens[i];
    }}
    uint8_t *storage = (uint8_t *)spx_pg_alloc(reservation);
    if (storage == NULL) return SPX_PG_STATUS_ALLOCATION_FAILURE;
    struct spx_bytes_arena arena = {{ &context, storage, reservation, 0, slots, 0, 0 }};
    spx_pg_status_v1 status = SPX_PG_STATUS_OK;
    uint32_t completed = 0;
    if (!spx_context_init(&context, UINT64_C(1), entries, 1, NULL, NULL, &arena)) {{
        status = SPX_PG_STATUS_CONTRACT_FAILURE;
        goto settle_arena;
    }}
"#,
        fields.len(),
        capacity.bytes_copy_sites,
        capacity.owned_byte_payload_bytes
    );
    for (i, field) in fields.iter().enumerate() {
        writeln!(bridge, "    input.{field} = spx_bytes_copy_in(&context, (spx_slice_u8_v1){{ input_leaf_bytes[{i}], input_leaf_lens[{i}] }});").unwrap();
    }
    writeln!(bridge, "    SPX_PG_OBSERVE_ENDPOINT();\n    if ({symbol}(&context, &input, &result) != SPX_STATUS_SUCCESS) {{\n        status = SPX_PG_STATUS_CONTRACT_FAILURE;\n        goto settle_arena;\n    }}\n    total = 0;").unwrap();
    // ALL leaves pass the carrier limit before the first result payload hook.
    for field in &fields {
        writeln!(bridge, "    if (result.{field}.len > SPX_PG_MAX_BYTES_PER_LEAF || result.{field}.len > SPX_PG_MAX_TOTAL_PAYLOAD_BYTES - total) {{ status = SPX_PG_STATUS_CARRIER_CAPACITY; goto settle_result; }}\n    total += (size_t)result.{field}.len;").unwrap();
    }
    for (i, field) in fields.iter().enumerate() {
        writeln!(bridge, "    if (spx_pg_physical_phase(SPX_PG_PHASE_RESULT_ALLOCATION_STARTED, 1, {i})) {{ status = SPX_PG_STATUS_ALLOCATION_FAILURE; goto settle_result; }}\n    out_leaf_lens[{i}] = (size_t)result.{field}.len;\n    out_leaf_bytes[{i}] = result.{field}.len ? (uint8_t *)spx_pg_alloc((size_t)result.{field}.len) : NULL;\n    if (result.{field}.len && !out_leaf_bytes[{i}]) {{ status = SPX_PG_STATUS_ALLOCATION_FAILURE; goto settle_result; }}\n    completed = {i} + 1;\n    if (spx_pg_physical_phase(SPX_PG_PHASE_RESULT_ALLOCATION_COMMITTED, 1, {i})) {{ status = SPX_PG_STATUS_ALLOCATION_FAILURE; goto settle_result; }}\n    if (result.{field}.len) memcpy(out_leaf_bytes[{i}], result.{field}.ptr, (size_t)result.{field}.len);\n    SPX_PG_OBSERVE_RESULT_PAYLOAD({i}, out_leaf_bytes[{i}], out_leaf_lens[{i}]);\n    if (spx_pg_physical_phase(SPX_PG_PHASE_RESULT_PAYLOAD_COPIED, 1, {i})) {{ status = SPX_PG_STATUS_CONTRACT_FAILURE; goto settle_result; }}").unwrap();
    }
    bridge.push_str("settle_result:\n    if (status != SPX_PG_STATUS_OK) spx_pg_select_primary_failure(status);\n");
    for field in fields.iter().rev() {
        writeln!(bridge, "    spx_bytes_drop(&result.{field});").unwrap();
    }
    bridge.push_str(r#"settle_arena:
    /* This is a refusal, not synthesized canonical cleanup. The bridge still
       owns backing storage even if a compiler defect left a semantic lease. */
    if (arena.live != 0 && status == SPX_PG_STATUS_OK) status = SPX_PG_STATUS_CONTRACT_FAILURE;
    if (status != SPX_PG_STATUS_OK) {
        spx_pg_select_primary_failure(status);
        for (uint32_t i = completed; i-- > 0;) spx_pg_release_payload(out_leaf_bytes, out_leaf_lens, i, 1);
    }
    context.target_state = NULL;
    spx_pg_dealloc(storage, reservation);
    return status;
}
"#);
    Ok((source, bridge))
}
