/* --- settlement-corpus driver (issue #162): one function per case,
 * generated from the identical Rust `Case` table `run_interpreter_case`/
 * `run_wasm_case` consume. --- */
static size_t g_prev_overwrite_total = 0;
/* Trace capture is per-case in this test translation unit. A capacity
 * overflow is a failed probe, never silently missing evidence. */
/* Fixed scratch, deliberately never routed through `malloc`/`free`
 * (tracked by `allocations.c` above): this driver's OWN copy of the
 * exported result bytes must not appear in either counter this function
 * reports, or it would compare the provider's real settlement against a
 * count polluted by test-harness bookkeeping rather than the provider
 * itself. Sized for the corpus's own maximum case (one
 * `MAX_BYTES_PER_LEAF`-sized leaf plus the small fixed header). */
static uint8_t g_result_scratch[1 << 18];

static spx_pg_provider_v1 *open_trusted_provider(void) {
    spx_pg_provider_v1 *provider = NULL;
    spx_pg_status_v1 status =
        spx_pg_provider_open_v1(SPX_PG_TRUSTED_DESCRIPTOR_BYTES, SPX_PG_TRUSTED_DESCRIPTOR_LEN,
                                 SPX_PG_TRUSTED_BINDING_BYTES, SPX_PG_TRUSTED_BINDING_LEN, &provider);
    REQUIRE(status == SPX_PG_STATUS_OK);
    REQUIRE(provider != NULL);
    return provider;
}

static void run_one_case(const char *case_id, const uint8_t *carrier, size_t carrier_len,
                          int32_t injection_ordinal, int32_t injection_ordinal2) {
    pg_observe_reset();
    g_spx_pg_trace_len = 0;
    spx_pg_provider_v1 *provider = open_trusted_provider();
    if (injection_ordinal >= 0) {
        spx_pg_test_inject_failure_v1((uint32_t)injection_ordinal);
    }
    if (injection_ordinal2 >= 0) {
        spx_pg_test_inject_failure_v1((uint32_t)injection_ordinal2);
    }
    spx_pg_value_v1 *input = NULL;
    spx_pg_status_v1 status = spx_pg_input_prepare_v1(provider, carrier, carrier_len, &input);
    spx_pg_result_v1 *result = NULL;
    if (status == SPX_PG_STATUS_OK) {
        if (injection_ordinal >= 0) {
            spx_pg_test_inject_failure_v1((uint32_t)injection_ordinal);
        }
        if (injection_ordinal2 >= 0) {
            spx_pg_test_inject_failure_v1((uint32_t)injection_ordinal2);
        }
        status = spx_pg_call_v1(provider, input, &result);
    }
    int has_result = 0;
    size_t result_len = 0;
    if (status == SPX_PG_STATUS_OK) {
        REQUIRE(result != NULL);
        size_t required = 0;
        spx_pg_status_v1 sized = spx_pg_result_export_v1(result, NULL, 0, &required);
        REQUIRE(sized == SPX_PG_STATUS_BUFFER_TOO_SMALL || sized == SPX_PG_STATUS_OK);
        REQUIRE(required <= sizeof(g_result_scratch));
        size_t reported = 0;
        memset(g_result_scratch, 0xa5, required);
        REQUIRE(spx_pg_result_export_v1(result, g_result_scratch, required - 1, &reported) ==
                SPX_PG_STATUS_BUFFER_TOO_SMALL);
        REQUIRE(reported == required);
        for (size_t index = 0; index < required; ++index) REQUIRE(g_result_scratch[index] == 0xa5);
        REQUIRE(pg_endpoint_invocations == 1);
        REQUIRE(spx_pg_result_export_v1(result, g_result_scratch, required, &reported) ==
                SPX_PG_STATUS_OK);
        result_len = reported;
        has_result = 1;
        spx_pg_result_v1 *alias = result;
        REQUIRE(spx_pg_result_release_v1(&result) == SPX_PG_STATUS_OK);
        REQUIRE(result == NULL);
        REQUIRE(spx_pg_result_release_v1(&result) == SPX_PG_STATUS_OK); /* null is idempotent */
        REQUIRE(spx_pg_result_release_v1(&alias) == SPX_PG_STATUS_HANDLE_INVALID);
        REQUIRE(alias == NULL);
        REQUIRE(pg_endpoint_invocations == 1);
    } else {
        REQUIRE(result == NULL);
    }
    /* Handle count is meaningful only while `provider` is still a live
     * pointer; alloc/byte counters are read AFTER close instead, exactly
     * like every existing `assert_fully_settled()` call in probe.c, so
     * the provider's own control-block allocation (freed by close) does
     * not read as a false "still live" resource. */
    size_t live_handles = spx_pg_test_live_handles_v1(provider);
    size_t trace_total = spx_pg_test_trace_len_v1();
    size_t trace_start = 0;
    REQUIRE(trace_total < SPX_PG_TRACE_CAPACITY);
    size_t overwrite_total = spx_pg_test_settlement_overwrite_attempts_v1();
    size_t overwrite_delta = overwrite_total - g_prev_overwrite_total;
    g_prev_overwrite_total = overwrite_total;
    spx_pg_test_clear_failure_injection_v1();
    REQUIRE(spx_pg_provider_close_v1(&provider) == SPX_PG_STATUS_OK);
    size_t live_alloc = spx_pg_test_live_allocations_v1();

    printf("CASE case_id=%s accepted=%d status=%d live_alloc=%zu live_handles=%zu "
           "fixture_live=%zu fixture_peak=%zu overwrite=%zu trace=",
           case_id, status == SPX_PG_STATUS_OK ? 1 : 0, (int)status, live_alloc, live_handles,
           fixture_live, fixture_peak, overwrite_delta);
    for (size_t index = trace_start; index < trace_total; ++index) {
        printf("%u%s", spx_pg_test_trace_label_v1(index), (index + 1 < trace_total) ? "," : "");
    }
    printf(" result=");
    if (has_result) {
        for (size_t index = 0; index < result_len; ++index) {
            printf("%02x", g_result_scratch[index]);
        }
    } else {
        printf("-");
    }
    printf(" live_bytes=%zu peak_alloc=%zu peak_bytes=%zu peak_handles=%zu endpoint_invoked=%zu release_order=",
           g_spx_pg_live_bytes, pg_peak_alloc, pg_peak_bytes, pg_peak_handles, pg_endpoint_invocations);
    for (size_t index = 0; index < pg_release_count; ++index) {
        printf("%u:%u%s", pg_release_order[index].direction, pg_release_order[index].leaf,
               index + 1 < pg_release_count ? "," : "");
    }
    printf(" secondary_cleanup=");
    for (size_t index = 0; index < pg_secondary_count; ++index) {
        printf("%d%s", (int)pg_secondary_cleanup[index], index + 1 < pg_secondary_count ? "," : "");
    }
    printf("\n");
}
