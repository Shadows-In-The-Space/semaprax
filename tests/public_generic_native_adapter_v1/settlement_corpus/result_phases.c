/* Issue #162: failures at REAL result allocation/copy boundaries, not the
 * historical post-hoc logical labels. All paths use the ordinary native ABI.
 * The literal assertions below are independent of the retained Python receipt
 * expectations, so two optimized builds agreeing on a bug cannot pass. */
static uint8_t pg_phase_buffer[16u * 1024u * 1024u + 2056u];
static size_t pg_phase_cases_run;
static int pg_phase_shape;

static void pg_phase_arm(size_t slot, uint32_t phase, uint32_t direction, uint32_t leaf) {
    REQUIRE(slot < 2);
    pg_phase_injections[slot] = (struct pg_phase_injection){phase, direction, leaf, 1};
}

/* Exact trusted recipes. Shape 0 contains embedded zeros; shape 1 starts
 * with a genuinely empty owned leaf; shape 2 reaches all three simultaneous
 * bounds: 256 leaves * 65,536 bytes = 16 MiB. No giant binary fixture. */
static size_t pg_phase_length(int shape, uint32_t leaf) {
    return shape == 2 ? 65536u : leaf == 0 ? (shape == 1 ? 0u : 2u) : 3u;
}
static uint8_t pg_phase_byte(int shape, uint32_t leaf, size_t offset) {
    if (shape == 2) return (uint8_t)((offset * 17u + leaf) & 255u);
    static const uint8_t first[] = {'A','B'}, second[] = {'C',0,'D'};
    return leaf == 0 ? first[offset] : second[offset];
}
/* This observes bytes before an injected post-copy failure can free them.
 * Failed calls therefore prove exact content too, not only their counters. */
static void pg_phase_check_payload(uint32_t leaf, const uint8_t *bytes, size_t length) {
    REQUIRE(length == pg_phase_length(pg_phase_shape, leaf));
    REQUIRE((bytes == NULL) == (length == 0));
    for (size_t at = 0; at < length; ++at)
        REQUIRE(bytes[at] == pg_phase_byte(pg_phase_shape, leaf, length - 1 - at));
}
static size_t pg_phase_carrier(int shape) {
    pg_phase_shape = shape;
    uint32_t count = shape == 2 ? 256u : 2u;
    size_t offset = 8;
    spx_pg_write_u64le(pg_phase_buffer, count);
    for (uint32_t leaf = 0; leaf < count; ++leaf) {
        size_t length = pg_phase_length(shape, leaf);
        spx_pg_write_u64le(pg_phase_buffer + offset, length);
        offset += 8;
        REQUIRE(offset + length <= sizeof(pg_phase_buffer));
        for (size_t at = 0; at < length; ++at) pg_phase_buffer[offset + at] = pg_phase_byte(shape, leaf, at);
        offset += length;
    }
    return offset;
}
static void pg_phase_verify_result(int shape, size_t size) {
    uint32_t count = shape == 2 ? 256u : 2u;
    REQUIRE(size <= sizeof(pg_phase_buffer) && size >= 8);
    REQUIRE(spx_pg_read_u64le(pg_phase_buffer) == count);
    size_t offset = 8;
    for (uint32_t leaf = 0; leaf < count; ++leaf) {
        size_t length = pg_phase_length(shape, leaf);
        REQUIRE(size - offset >= 8 && spx_pg_read_u64le(pg_phase_buffer + offset) == length);
        offset += 8;
        REQUIRE(size - offset >= length);
        for (size_t at = 0; at < length; ++at)
            REQUIRE(pg_phase_buffer[offset + at] == pg_phase_byte(shape, leaf, length - 1 - at));
        offset += length;
    }
    REQUIRE(offset == size);
}
static void pg_phase_start(void) {
    pg_observe_reset();
    g_spx_pg_trace_len = 0;
    pg_phase_enabled = 1;
    pg_phase_payload_check = pg_phase_check_payload;
}
static void pg_phase_report(const char *id, int report, int status, int result_verified,
                            int release_status, int retry_count) {
    REQUIRE(pg_phase_event_count < 4096 && g_spx_pg_trace_len < SPX_PG_TRACE_CAPACITY);
    REQUIRE(!pg_phase_injections[0].armed && !pg_phase_injections[1].armed);
    REQUIRE(fixture_live == 0 && fixture_allocations == fixture_frees);
    REQUIRE(g_spx_pg_live_allocations == 0 && pg_live_handles == 0 && g_spx_pg_live_bytes == 0);
    for (size_t slot = 0; slot < SPX_PG_REGISTRY_CAPACITY; ++slot)
        REQUIRE(g_spx_pg_providers[slot].identity == NULL);
    ++pg_phase_cases_run;
    if (!report) return;
    printf("PHASE case_id=%s status=%d result_verified=%d release_status=%d retries=%d "
           "endpoints=%zu copies_checked=%zu peak_alloc=%zu peak_handles=%zu peak_bytes=%zu "
           "live_alloc=%zu live_handles=%zu live_bytes=%zu secondary=",
        id, status, result_verified, release_status, retry_count, pg_endpoint_invocations, pg_phase_copies_checked,
        pg_peak_alloc, pg_peak_handles, pg_peak_bytes,
        g_spx_pg_live_allocations, pg_live_handles, g_spx_pg_live_bytes);
    for (size_t i = 0; i < pg_secondary_count; ++i)
        printf("%d%s", (int)pg_secondary_cleanup[i], i + 1 < pg_secondary_count ? "," : "");
    printf(" releases=");
    for (size_t i = 0; i < pg_release_count; ++i)
        printf("%u:%u%s", pg_release_order[i].direction, pg_release_order[i].leaf,
               i + 1 < pg_release_count ? "," : "");
    printf(" events=");
    for (size_t i = 0; i < pg_phase_event_count; ++i) {
        struct pg_phase_observation *e = &pg_phase_events[i];
        printf("%u:%u:%u:%zu:%zu:%d%s", e->phase, e->direction, e->leaf,
               e->allocations, e->handles, e->injected, i + 1 < pg_phase_event_count ? "," : "");
    }
    puts("");
}
static spx_pg_result_v1 *pg_phase_call(spx_pg_provider_v1 *provider, int shape) {
    size_t size = pg_phase_carrier(shape);
    spx_pg_value_v1 *input = NULL;
    spx_pg_result_v1 *result = NULL;
    REQUIRE(spx_pg_input_prepare_v1(provider, pg_phase_buffer, size, &input) == SPX_PG_STATUS_OK);
    /* Destroy the host source: provider leaves must be exact independent copies. */
    memset(pg_phase_buffer, 0xa5, size);
    REQUIRE(spx_pg_call_v1(provider, input, &result) == SPX_PG_STATUS_OK && result != NULL);
    REQUIRE(pg_endpoint_invocations == 1);
    return result;
}
static void pg_phase_export(spx_pg_result_v1 *result, int shape) {
    size_t required = 0;
    REQUIRE(spx_pg_result_export_v1(result, NULL, 0, &required) == SPX_PG_STATUS_BUFFER_TOO_SMALL);
    REQUIRE(required <= sizeof(pg_phase_buffer));
    REQUIRE(spx_pg_result_export_v1(result, pg_phase_buffer, required, &required) == SPX_PG_STATUS_OK);
    pg_phase_verify_result(shape, required);
}

static void pg_phase_success(const char *id, int shape, int report) {
    pg_phase_start();
    spx_pg_provider_v1 *provider = open_trusted_provider();
    spx_pg_result_v1 *result = pg_phase_call(provider, shape);
    pg_phase_export(result, shape);
    REQUIRE(spx_pg_result_release_v1(&result) == SPX_PG_STATUS_OK && result == NULL);
    pg_check_reverse(shape == 2 ? 256 : 2, shape == 2 ? 256 : 2);
    /* Exact empty-leaf accounting: no allocation for either input or result
     * empty payload, unlike an arbitrary malloc(1) placeholder. */
    REQUIRE(pg_peak_alloc == (shape == 2 ? 518u : shape == 1 ? 8u : 10u));
    pg_check_zero_and_close(&provider);
    pg_phase_report(id, report, 0, 1, 0, 0);
}

static void pg_phase_staging(int shape, uint32_t phase, uint32_t leaf,
                              int cleanup_dir, uint32_t cleanup_leaf, int report) {
    pg_phase_start();
    spx_pg_provider_v1 *provider = open_trusted_provider();
    size_t size = pg_phase_carrier(shape);
    spx_pg_value_v1 *input = NULL;
    spx_pg_result_v1 *result = NULL;
    REQUIRE(spx_pg_input_prepare_v1(provider, pg_phase_buffer, size, &input) == SPX_PG_STATUS_OK);
    pg_phase_arm(0, phase, 1, leaf);
    if (cleanup_dir >= 0) pg_phase_arm(1, SPX_PG_PHASE_LEAF_RELEASED, (uint32_t)cleanup_dir, cleanup_leaf);
    int status = spx_pg_call_v1(provider, input, &result);
    REQUIRE(status == (phase <= 1 ? SPX_PG_STATUS_ALLOCATION_FAILURE : SPX_PG_STATUS_CONTRACT_FAILURE));
    REQUIRE(result == NULL && pg_endpoint_invocations == 1 && pg_peak_handles == 1);
    uint32_t completed = phase <= 2 ? leaf + (phase != 0 ? 1u : 0u) : 2;
    REQUIRE(pg_release_count == (size_t)completed + 2);
    REQUIRE(pg_phase_copies_checked == (phase <= 2 ? leaf + (phase == 2 ? 1u : 0u) : 2));
    size_t pos = 0;
    if (phase <= 2) {
        for (uint32_t i = completed; i-- > 0; ++pos)
            REQUIRE(pg_release_order[pos].direction == 1 && pg_release_order[pos].leaf == i);
    }
    for (uint32_t i = 2; i-- > 0; ++pos)
        REQUIRE(pg_release_order[pos].direction == 0 && pg_release_order[pos].leaf == i);
    if (phase > 2) {
        for (uint32_t i = completed; i-- > 0; ++pos)
            REQUIRE(pg_release_order[pos].direction == 1 && pg_release_order[pos].leaf == i);
    }
    REQUIRE(pg_secondary_count == (cleanup_dir >= 0 ? 1u : 0u));
    if (cleanup_dir >= 0) REQUIRE(pg_secondary_cleanup[0] == SPX_PG_STATUS_CONTRACT_FAILURE);
    /* Every physical event up to failure is the exact per-leaf prefix; no
     * later result leaf can have been allocated or copied behind the trace. */
    size_t event = 0;
    for (uint32_t i = 0; i < 2; ++i) {
        for (uint32_t point = 0; point < 3; ++point) {
            if (phase <= 2 && (i > leaf || (i == leaf && point > phase))) break;
            REQUIRE(event < pg_phase_event_count);
            const struct pg_phase_observation *e = &pg_phase_events[event++];
            REQUIRE(e->phase == point && e->direction == 1 && e->leaf == i && e->handles == 0);
            size_t baseline = shape == 1 ? 7u : 8u; /* provider + input + result arrays */
            size_t allocated = (i != 0 && shape != 1 ? 1u : 0u) +
                (point > 0 && !(shape == 1 && i == 0) ? 1u : 0u);
            REQUIRE(e->allocations == baseline + allocated);
            REQUIRE(e->injected == (phase <= 2 && i == leaf && point == phase));
        }
        if (phase <= 2 && i >= leaf) break;
    }
    pg_check_zero_and_close(&provider);
    char id[100];
    (void)snprintf(id, sizeof(id), "%s_phase%u_leaf%u_cleanup%d_leaf%u", shape == 1 ? "zero" : "stage",
                   phase, leaf, cleanup_dir, cleanup_leaf);
    pg_phase_report(id, report, status, 0, 0, 0);
}

static void pg_phase_export_failure(uint32_t phase, uint32_t leaf, int cleanup_leaf, int report) {
    pg_phase_start();
    spx_pg_provider_v1 *provider = open_trusted_provider();
    spx_pg_result_v1 *result = pg_phase_call(provider, 0), *alias = result;
    pg_phase_arm(0, phase, 1, leaf);
    size_t required = 0;
    REQUIRE(spx_pg_result_export_v1(result, NULL, 0, &required) == SPX_PG_STATUS_BUFFER_TOO_SMALL);
    REQUIRE(pg_phase_injections[0].armed); /* size query cannot consume injection */
    memset(pg_phase_buffer, 0xa5, required);
    size_t size = 0;
    REQUIRE(spx_pg_result_export_v1(result, pg_phase_buffer, required - 1, &size) == SPX_PG_STATUS_BUFFER_TOO_SMALL);
    REQUIRE(pg_phase_injections[0].armed && size == required);
    int status = spx_pg_result_export_v1(result, pg_phase_buffer, required, &size);
    REQUIRE(status == SPX_PG_STATUS_CONTRACT_FAILURE && size == required);
    for (size_t i = 0; i < required; ++i) REQUIRE(pg_phase_buffer[i] == 0xa5);
    REQUIRE(spx_pg_test_live_handles_v1(provider) == 1 && pg_endpoint_invocations == 1);
    /* Retry only the nonconsuming export, never the committed call. */
    pg_phase_export(result, 0);
    REQUIRE(pg_endpoint_invocations == 1 && spx_pg_test_live_handles_v1(provider) == 1);
    if (cleanup_leaf >= 0) pg_phase_arm(1, SPX_PG_PHASE_LEAF_RELEASED, 1, (uint32_t)cleanup_leaf);
    int released = spx_pg_result_release_v1(&result);
    REQUIRE(released == (cleanup_leaf >= 0 ? SPX_PG_STATUS_CONTRACT_FAILURE : SPX_PG_STATUS_OK));
    REQUIRE(result == NULL && status == SPX_PG_STATUS_CONTRACT_FAILURE);
    REQUIRE(spx_pg_result_release_v1(&alias) == SPX_PG_STATUS_HANDLE_INVALID && alias == NULL);
    /* The calling operation retains the export failure as primary; the
     * explicit release is independent and supplies its own secondary status. */
    REQUIRE(pg_secondary_count == 0);
    pg_check_reverse(2, 2);
    pg_check_zero_and_close(&provider);
    char id[100];
    (void)snprintf(id, sizeof(id), "export_phase%u_leaf%u_cleanup%d", phase, leaf, cleanup_leaf);
    pg_phase_report(id, report, status, 1, released, 1);
}

static void pg_phase_explicit_release(uint32_t direction, uint32_t mode, int report) {
    pg_phase_start();
    spx_pg_provider_v1 *provider = open_trusted_provider();
    spx_pg_value_v1 *input = NULL;
    spx_pg_result_v1 *result = NULL;
    size_t size = pg_phase_carrier(0);
    REQUIRE(spx_pg_input_prepare_v1(provider, pg_phase_buffer, size, &input) == SPX_PG_STATUS_OK);
    if (direction == 1) {
        REQUIRE(spx_pg_call_v1(provider, input, &result) == SPX_PG_STATUS_OK);
        pg_phase_export(result, 0);
    }
    /* Modes 0/1: each physical leaf; 2: both; 3..5: each logical leaf/root
     * position; 6: carrier release. All are genuine discharge failures. */
    if (mode <= 2) {
        pg_phase_arm(0, SPX_PG_PHASE_LEAF_RELEASED, direction, mode == 1 ? 1 : 0);
        if (mode == 2) pg_phase_arm(1, SPX_PG_PHASE_LEAF_RELEASED, direction, 1);
    } else {
        pg_occurrence_label[0] = mode == 6 ? SPX_PG_TRACE_CARRIER_RELEASE : SPX_PG_TRACE_LEAF_RELEASE;
        pg_occurrence_remaining[0] = mode == 6 ? 1 : mode - 2;
    }
    int saved_selected = g_spx_pg_settlement_selected;
    spx_pg_status_v1 saved_status = g_spx_pg_settlement_status;
    int status = direction == 1 ? spx_pg_result_release_v1(&result) : spx_pg_value_release_v1(&input);
    REQUIRE(status == SPX_PG_STATUS_CONTRACT_FAILURE);
    REQUIRE((direction == 1 ? (void *)result : (void *)input) == NULL);
    REQUIRE(g_spx_pg_settlement_selected == saved_selected && g_spx_pg_settlement_status == saved_status);
    REQUIRE(pg_secondary_count == (mode == 2 ? 1u : 0u));
    REQUIRE(pg_occurrence_remaining[0] == 0);
    pg_check_reverse(2, direction == 1 ? 2 : 0);
    REQUIRE((direction == 1 ? spx_pg_result_release_v1(&result) : spx_pg_value_release_v1(&input)) == SPX_PG_STATUS_OK);
    pg_check_zero_and_close(&provider);
    char id[100];
    (void)snprintf(id, sizeof(id), "release_direction%u_mode%u", direction, mode);
    pg_phase_report(id, report, status, direction == 1, status, 0);
}

static void pg_phase_late_rollback(int physical_allocation, uint32_t point, uint32_t leaf, int report) {
    pg_phase_start();
    spx_pg_provider_v1 *provider = open_trusted_provider();
    spx_pg_value_v1 *input = NULL;
    spx_pg_result_v1 *result = NULL;
    pg_phase_shape = 0;
    REQUIRE(spx_pg_input_prepare_v1(provider, pg_two_leaf_carrier, sizeof(pg_two_leaf_carrier), &input) == SPX_PG_STATUS_OK);
    if (physical_allocation) pg_fail_allocation_at = point;
    else spx_pg_test_inject_failure_v1(point);
    pg_phase_arm(0, SPX_PG_PHASE_LEAF_RELEASED, 1, leaf);
    int status = spx_pg_call_v1(provider, input, &result);
    REQUIRE(status == SPX_PG_STATUS_ALLOCATION_FAILURE && result == NULL && pg_endpoint_invocations == 1);
    REQUIRE(pg_secondary_count == 1 && pg_secondary_cleanup[0] == SPX_PG_STATUS_CONTRACT_FAILURE);
    pg_check_zero_and_close(&provider);
    char id[100];
    (void)snprintf(id, sizeof(id), "%s_point%u_cleanup%u", physical_allocation ? "malloc" : "legacy", point, leaf);
    pg_phase_report(id, report, status, 0, 0, 0);
}

static void check_result_phase_regressions(int report) {
    pg_phase_cases_run = 0;
    pg_phase_success("success", 0, report);
    pg_phase_success("zero_success", 1, report);
    pg_phase_success("max_success", 2, report);
    for (uint32_t phase = 0; phase <= 4; ++phase) {
        for (uint32_t index = 0; index < (phase <= 2 ? 2u : 1u); ++index) {
            uint32_t leaf = phase <= 2 ? index : UINT32_MAX;
            uint32_t completed = phase <= 2 ? leaf + (phase != 0 ? 1u : 0u) : 2;
            pg_phase_staging(0, phase, leaf, -1, 0, report);
            pg_phase_staging(1, phase, leaf, -1, 0, report);
            if (phase <= 2) for (uint32_t release = 0; release < 2; ++release)
                pg_phase_staging(0, phase, leaf, 0, release, report);
            for (uint32_t release = 0; release < completed; ++release)
                pg_phase_staging(0, phase, leaf, 1, release, report);
        }
    }
    for (uint32_t phase = 5; phase <= 6; ++phase)
        for (uint32_t index = 0; index < (phase == 5 ? 1u : 2u); ++index)
            for (int cleanup = -1; cleanup < 2; ++cleanup)
                pg_phase_export_failure(phase, phase == 5 ? UINT32_MAX : index, cleanup, report);
    for (uint32_t direction = 0; direction < 2; ++direction)
        for (uint32_t mode = 0; mode < 7; ++mode) pg_phase_explicit_release(direction, mode, report);
    for (uint32_t label = 8; label <= 9; ++label)
        for (uint32_t leaf = 0; leaf < 2; ++leaf) pg_phase_late_rollback(0, label, leaf, report);
    pg_phase_late_rollback(1, 10, 0, report);
    pg_phase_late_rollback(1, 11, 0, report);
    pg_phase_late_rollback(1, 11, 1, report);
    REQUIRE(pg_phase_cases_run == 72);
    pg_phase_enabled = 0;
}
