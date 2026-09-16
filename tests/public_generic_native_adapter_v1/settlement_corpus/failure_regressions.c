/* These checks run in the SAME compiled provider as the shared corpus. They
 * are not synthetic settlement calls: both failures occur on the real path. */
static const uint8_t pg_two_leaf_carrier[] = {
    2,0,0,0,0,0,0,0, 2,0,0,0,0,0,0,0, 'A','B',
    3,0,0,0,0,0,0,0, 'C',0,'D'
};

static void pg_check_zero_and_close(spx_pg_provider_v1 **provider) {
    REQUIRE(spx_pg_test_live_handles_v1(*provider) == 0);
    REQUIRE(spx_pg_provider_close_v1(provider) == SPX_PG_STATUS_OK);
    REQUIRE(*provider == NULL);
    REQUIRE(spx_pg_test_live_allocations_v1() == 0);
    REQUIRE(g_spx_pg_live_bytes == 0 && fixture_live == 0 && pg_live_handles == 0);
    spx_pg_test_clear_failure_injection_v1();
}

static void pg_check_reverse(uint32_t input_count, uint32_t result_count) {
    REQUIRE(pg_release_count == (size_t)input_count + result_count);
    for (uint32_t index = 0; index < input_count; ++index) {
        REQUIRE(pg_release_order[index].direction == 0);
        REQUIRE(pg_release_order[index].leaf == input_count - index - 1);
    }
    for (uint32_t index = 0; index < result_count; ++index) {
        REQUIRE(pg_release_order[input_count + index].direction == 1);
        REQUIRE(pg_release_order[input_count + index].leaf == result_count - index - 1);
    }
}

static void check_physical_allocation_failures(void) {
    /* Eleven nonempty allocations on this exact two-leaf native route:
     * provider; two input arrays, two leaves, input handle; two result
     * arrays, two result leaves, result handle. Fail each real allocation,
     * both alone and with an independently armed cleanup failure. */
    for (size_t ordinal = 1; ordinal <= 11; ++ordinal) {
        for (int compound = 0; compound <= 1; ++compound) {
            pg_observe_reset();
            g_spx_pg_trace_len = 0;
            pg_fail_allocation_at = ordinal;
            spx_pg_provider_v1 *provider = NULL;
            spx_pg_status_v1 status = spx_pg_provider_open_v1(
                SPX_PG_TRUSTED_DESCRIPTOR_BYTES, SPX_PG_TRUSTED_DESCRIPTOR_LEN,
                SPX_PG_TRUSTED_BINDING_BYTES, SPX_PG_TRUSTED_BINDING_LEN, &provider);
            spx_pg_value_v1 *input = NULL;
            spx_pg_result_v1 *result = NULL;
            if (status == SPX_PG_STATUS_OK) {
                if (compound) spx_pg_test_inject_failure_v1(SPX_PG_TRACE_LEAF_RELEASE);
                status = spx_pg_input_prepare_v1(provider, pg_two_leaf_carrier,
                                                sizeof(pg_two_leaf_carrier), &input);
                if (status == SPX_PG_STATUS_OK) status = spx_pg_call_v1(provider, input, &result);
            }
            /* At ordinal 11, input cleanup precedes result-handle allocation.
             * A cleanup failure there is genuinely FIRST and must stay primary. */
            REQUIRE(status == (compound && ordinal == 11 ? SPX_PG_STATUS_CONTRACT_FAILURE :
                                                            SPX_PG_STATUS_ALLOCATION_FAILURE));
            REQUIRE(result == NULL);
            REQUIRE(pg_endpoint_invocations == (ordinal >= 9 ? 1u : 0u));
            REQUIRE(pg_secondary_count == (compound && ordinal >= 4 && ordinal <= 10 ? 1u : 0u));
            pg_check_zero_and_close(&provider);
        }
    }
}

static void check_failure_regressions(void) {
    check_physical_allocation_failures();
    /* First and second input leaf failures, followed by each reachable safe
     * cleanup position, including root and carrier release. */
    for (uint32_t primary = 1; primary <= 7; ++primary) {
        uint32_t occurrences = primary <= 3 ? 2 : 1;
        for (uint32_t occurrence = 1; occurrence <= occurrences; ++occurrence) {
            uint32_t completed = primary == 1 ? occurrence - 1 : primary <= 3 ? occurrence : 2;
            for (uint32_t cleanup = 12; cleanup <= 13; ++cleanup) {
                uint32_t release_positions = cleanup == 12 ? completed + 1 : 1;
                for (uint32_t position = 1; position <= release_positions; ++position) {
                    pg_observe_reset();
                    g_spx_pg_trace_len = 0;
                    spx_pg_provider_v1 *provider = open_trusted_provider();
                    pg_occurrence_label[0] = primary;
                    pg_occurrence_remaining[0] = occurrence;
                    pg_occurrence_label[1] = cleanup;
                    pg_occurrence_remaining[1] = position;
                    spx_pg_value_v1 *input = NULL;
                    spx_pg_result_v1 *result = NULL;
                    spx_pg_status_v1 status = spx_pg_input_prepare_v1(provider, pg_two_leaf_carrier,
                                                                sizeof(pg_two_leaf_carrier), &input);
                    if (status == SPX_PG_STATUS_OK) status = spx_pg_call_v1(provider, input, &result);
                    spx_pg_status_v1 expected = primary <= 4 ? SPX_PG_STATUS_ALLOCATION_FAILURE :
                        primary == 5 ? SPX_PG_STATUS_ILLEGAL_TRANSITION : SPX_PG_STATUS_CONTRACT_FAILURE;
                    REQUIRE(status == expected);
                    REQUIRE(result == NULL);
                    REQUIRE(pg_endpoint_invocations == (primary == 7 ? 1u : 0u));
                    REQUIRE(pg_secondary_count == 1 && pg_secondary_cleanup[0] == SPX_PG_STATUS_CONTRACT_FAILURE);
                    REQUIRE(pg_occurrence_remaining[0] == 0 && pg_occurrence_remaining[1] == 0);
                    pg_check_reverse(completed, primary == 7 ? 2 : 0);
                    pg_check_zero_and_close(&provider);
                }
            }
        }
    }
    /* Rollback of every privately staged result is reverse, not forward.
     * Current native staging injection is post-hoc: both leaves already
     * exist. That implementation detail is asserted, not passed off as a
     * complete logical per-leaf result-allocation failure matrix. */
    for (uint32_t label = 8; label <= 11; ++label) {
        pg_observe_reset();
        g_spx_pg_trace_len = 0;
        spx_pg_provider_v1 *provider = open_trusted_provider();
        spx_pg_value_v1 *input = NULL;
        spx_pg_result_v1 *result = NULL;
        REQUIRE(spx_pg_input_prepare_v1(provider, pg_two_leaf_carrier,
                                           sizeof(pg_two_leaf_carrier), &input) == SPX_PG_STATUS_OK);
        spx_pg_test_inject_failure_v1(label);
        spx_pg_status_v1 status = spx_pg_call_v1(provider, input, &result);
        REQUIRE(status == (label <= 9 ? SPX_PG_STATUS_ALLOCATION_FAILURE : SPX_PG_STATUS_CONTRACT_FAILURE));
        REQUIRE(result == NULL && pg_endpoint_invocations == 1);
        pg_check_reverse(2, 2);
        pg_check_zero_and_close(&provider);
    }
}
