/* Test-only multi-call Core Wasm transport around the UNCHANGED native
 * reference provider, compiled into this instance. Not the frozen Wasm v1
 * adapter, a compiler target, or a public ABI. The source-derived reference
 * artifact remains distinct from a checked Semaprax generic programme.
 *
 * Return lanes: low u32 = status, high u32 = minted handle or exact length.
 * The host writes only the scratch window. No raw heap/registry pointer is
 * accepted; handles are non-recycled indices into the provider's own identity
 * inventory, and all lifecycle/pairing checks remain in the original provider.
 */
#undef malloc
#undef free
#define PG_REF_FRAME_MAX (16u * 1024u * 1024u + 2056u)
#define PG_REF_RANGE 256u
#define PG_REF_OPTION 257u
#define PG_REF_LIVE_OBSERVATION 258u
static uint8_t pg_transport_scratch[PG_REF_FRAME_MAX + 1u];
static uint64_t pg_lane(uint32_t status, uint32_t value) { return ((uint64_t)value << 32) | status; }
static uint32_t pg_range(uint32_t pointer, uint32_t length, uint32_t bound) {
    if (length > bound) return SPX_PG_STATUS_CARRIER_CAPACITY;
    if (pointer == 0 && length == 0) return 0;
    uint32_t base = (uint32_t)(uintptr_t)pg_transport_scratch;
    if (pointer < base || pointer - base > sizeof(pg_transport_scratch) ||
        length > sizeof(pg_transport_scratch) - (pointer - base)) return PG_REF_RANGE;
    return 0;
}
static uint32_t pg_identity_index(const void *pointer) {
    if (pointer == NULL) return 0;
    uintptr_t base = (uintptr_t)g_spx_pg_identities, address = (uintptr_t)pointer;
    REQUIRE(address >= base && address - base < sizeof(g_spx_pg_identities));
    REQUIRE((address - base) % sizeof(g_spx_pg_identities[0]) == 0);
    return (uint32_t)((address - base) / sizeof(g_spx_pg_identities[0]) + 1);
}
/* Bounds checked BEFORE constructing any pointer. Selecting a wrong kind's
 * union member grants nothing; provider registries validate the live kind. */
static spx_pg_provider_v1 *pg_provider(uint32_t id) {
    return id && id <= g_spx_pg_identities_used ? &g_spx_pg_identities[id - 1].provider : NULL;
}
static spx_pg_value_v1 *pg_input(uint32_t id) {
    return id && id <= g_spx_pg_identities_used ? &g_spx_pg_identities[id - 1].value : NULL;
}
static spx_pg_result_v1 *pg_result(uint32_t id) {
    return id && id <= g_spx_pg_identities_used ? &g_spx_pg_identities[id - 1].result : NULL;
}
PG_WASM_EXPORT("pg_scratch_pointer") uint32_t pg_scratch_pointer(void) {
    return (uint32_t)(uintptr_t)pg_transport_scratch;
}
PG_WASM_EXPORT("pg_scratch_capacity") uint32_t pg_scratch_capacity(void) { return sizeof(pg_transport_scratch); }
PG_WASM_EXPORT("pg_open") uint64_t pg_transport_open(uint32_t dp, uint32_t dn, uint32_t bp, uint32_t bn) {
    uint32_t status = pg_range(dp, dn, 65536u);
    if (status == 0) status = pg_range(bp, bn, 65536u);
    if (status) return pg_lane(status, 0);
    spx_pg_provider_v1 *provider = NULL;
    status = (uint32_t)spx_pg_provider_open_v1((const uint8_t *)(uintptr_t)dp, dn,
        (const uint8_t *)(uintptr_t)bp, bn, &provider);
    return pg_lane(status, pg_identity_index(provider));
}
PG_WASM_EXPORT("pg_prepare") uint64_t pg_transport_prepare(uint32_t provider_id, uint32_t pointer, uint32_t length) {
    uint32_t status = pg_range(pointer, length, PG_REF_FRAME_MAX);
    if (status) return pg_lane(status, 0);
    if (!pg_provider(provider_id)) return pg_lane(SPX_PG_STATUS_HANDLE_INVALID, 0);
    spx_pg_value_v1 *input = NULL;
    status = (uint32_t)spx_pg_input_prepare_v1(pg_provider(provider_id), (const uint8_t *)(uintptr_t)pointer, length, &input);
    return pg_lane(status, pg_identity_index(input));
}
PG_WASM_EXPORT("pg_call") uint64_t pg_transport_call(uint32_t provider_id, uint32_t input_id) {
    if (!pg_provider(provider_id) || !pg_input(input_id)) return pg_lane(SPX_PG_STATUS_HANDLE_INVALID, 0);
    spx_pg_result_v1 *result = NULL;
    uint32_t status = (uint32_t)spx_pg_call_v1(pg_provider(provider_id), pg_input(input_id), &result);
    return pg_lane(status, pg_identity_index(result));
}
PG_WASM_EXPORT("pg_export") uint64_t pg_transport_export(uint32_t result_id, uint32_t pointer, uint32_t capacity) {
    uint32_t status = pg_range(pointer, capacity, PG_REF_FRAME_MAX);
    if (status) return pg_lane(status, 0);
    if (!pg_result(result_id)) return pg_lane(SPX_PG_STATUS_HANDLE_INVALID, 0);
    size_t required = 0;
    status = (uint32_t)spx_pg_result_export_v1(pg_result(result_id), (uint8_t *)(uintptr_t)pointer, capacity, &required);
    REQUIRE(required <= PG_REF_FRAME_MAX);
    return pg_lane(status, (uint32_t)required);
}
PG_WASM_EXPORT("pg_input_release") uint32_t pg_transport_input_release(uint32_t id) {
    spx_pg_value_v1 *input = pg_input(id);
    if (id && !input) return SPX_PG_STATUS_HANDLE_INVALID;
    return (uint32_t)spx_pg_value_release_v1(&input);
}
PG_WASM_EXPORT("pg_result_release") uint32_t pg_transport_result_release(uint32_t id) {
    spx_pg_result_v1 *result = pg_result(id);
    if (id && !result) return SPX_PG_STATUS_HANDLE_INVALID;
    return (uint32_t)spx_pg_result_release_v1(&result);
}
PG_WASM_EXPORT("pg_close") uint32_t pg_transport_close(uint32_t id) {
    spx_pg_provider_v1 *provider = pg_provider(id);
    if (id && !provider) return SPX_PG_STATUS_HANDLE_INVALID;
    return (uint32_t)spx_pg_provider_close_v1(&provider);
}
PG_WASM_EXPORT("pg_inject") uint32_t pg_transport_inject(uint32_t label) {
    if (label > 13) return PG_REF_OPTION;
    spx_pg_test_inject_failure_v1(label); return 0;
}
PG_WASM_EXPORT("pg_phase_inject") uint32_t pg_transport_phase_inject(uint32_t phase, uint32_t direction, uint32_t leaf) {
    if (phase > 7 || direction > 1 || (leaf >= 256 && leaf != UINT32_MAX)) return PG_REF_OPTION;
    if ((phase != 7 && direction != 1) ||
        ((phase >= 3 && phase <= 5) != (leaf == UINT32_MAX))) return PG_REF_OPTION;
    for (size_t i = 0; i < 2; ++i) if (!pg_phase_injections[i].armed) {
        pg_phase_injections[i] = (struct pg_phase_injection){phase, direction, leaf, 1};
        return 0;
    }
    return PG_REF_OPTION;
}
/* Reuse the existing phase observer without inventing expected payload bytes.
 * The host independently validates complete copy-out against the shared case.
 * Result-phase C probes additionally check bytes at each physical copy hook. */
static void pg_transport_payload(uint32_t leaf, const uint8_t *bytes, size_t length) {
    REQUIRE(leaf < 256 && length <= 65536 && ((bytes == NULL) == (length == 0)));
}
PG_WASM_EXPORT("pg_reset_observations") uint32_t pg_transport_reset(void) {
    if (g_spx_pg_live_allocations || pg_heap_live || fixture_live || pg_live_handles) return PG_REF_LIVE_OBSERVATION;
    for (size_t i = 0; i < SPX_PG_REGISTRY_CAPACITY; ++i)
        if (g_spx_pg_providers[i].identity) return PG_REF_LIVE_OBSERVATION;
    pg_observe_reset(); g_spx_pg_trace_len = 0;
    spx_pg_test_clear_failure_injection_v1();
    pg_phase_enabled = 1; pg_phase_payload_check = pg_transport_payload;
    return 0;
}
PG_WASM_EXPORT("pg_observe") uint64_t pg_transport_observe(uint32_t field) {
    switch (field) {
    case 0: return g_spx_pg_live_allocations;
    case 1: return g_spx_pg_live_bytes;
    case 2: return pg_live_handles;
    case 3: return pg_endpoint_invocations;
    case 4: return pg_peak_alloc;
    case 5: return pg_peak_bytes;
    case 6: return pg_peak_handles;
    case 7: return pg_release_count;
    case 8: return pg_secondary_count;
    case 9: return g_spx_pg_trace_len;
    case 10: return pg_heap_live;
    case 11: return pg_heap_live_bytes;
    case 12: return pg_phase_event_count;
    case 13: return g_spx_pg_settlement_overwrites;
    default: return UINT64_MAX;
    }
}
PG_WASM_EXPORT("pg_trace") uint32_t pg_transport_trace(uint32_t i) {
    return i < g_spx_pg_trace_len ? g_spx_pg_trace[i] : UINT32_MAX;
}
PG_WASM_EXPORT("pg_release_observation") uint64_t pg_transport_release(uint32_t i) {
    return i < pg_release_count ? ((uint64_t)pg_release_order[i].direction << 32) | pg_release_order[i].leaf : UINT64_MAX;
}
PG_WASM_EXPORT("pg_cleanup_observation") uint32_t pg_transport_cleanup(uint32_t i) {
    return i < pg_secondary_count ? (uint32_t)pg_secondary_cleanup[i] : UINT32_MAX;
}
/* Runs the existing, unmodified C assertion corpus under a real Wasm engine.
 * Every lifecycle selector starts in a fresh instance, like a native process;
 * otherwise the intentionally terminal identity-exhaustion cases interfere. */
PG_WASM_EXPORT("pg_run") int pg_transport_run(uint32_t selector) {
    static const char *const names[] = {"result-phases", "reuse", "stale_children", "recreation",
        "hostile_providers", "sibling_settlement", "live_providers", "live_children",
        "identity_provider", "identity_input", "identity_result", "identity_result_over", "stress"};
    if (selector > sizeof(names) / sizeof(names[0])) return PG_REF_OPTION;
    if (g_spx_pg_live_allocations || pg_heap_live || g_spx_pg_identities_used) return PG_REF_LIVE_OBSERVATION;
    pg_log_size = 0;
    if (selector == 0) pg_runtime_self_test();
    char *args[2] = {"reference-wasm", NULL};
    if (selector) args[1] = (char *)names[selector - 1];
    int status = main(selector ? 2 : 1, args);
    REQUIRE(pg_heap_live == 0 && pg_heap_live_bytes == 0);
    return status;
}
