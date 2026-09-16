/* #162 continuation: real opaque-handle lifecycles, not invented addresses
 * passed off as resources. Uses the same provider, allocator and observers as
 * the shared settlement corpus. Identity exhaustion runs in fresh processes:
 * no test resets or repairs the production monotonic identity counter. */
static const uint8_t pg_empty_carrier[8] = {0};
static const uint8_t pg_two_leaf_result[] = {
    2,0,0,0,0,0,0,0, 2,0,0,0,0,0,0,0, 'B','A',
    3,0,0,0,0,0,0,0, 'D',0,'C'
};
static size_t pg_lifecycle_rejections;

static void pg_lifecycle_rejected(spx_pg_status_v1 actual, spx_pg_status_v1 expected) {
    REQUIRE(actual == expected);
    ++pg_lifecycle_rejections;
}

static void pg_lifecycle_begin(void) {
    pg_observe_reset();
    g_spx_pg_trace_len = 0;
    pg_lifecycle_rejections = 0;
    spx_pg_test_clear_failure_injection_v1();
}

static void pg_lifecycle_next_call(void) {
    /* Only reset bounded observation buffers, never identities/registries,
     * allocation counts, endpoint counts or the authoritative settlement. */
    REQUIRE(pg_live_handles == 0);
    pg_release_count = 0;
    g_spx_pg_trace_len = 0;
}

static void pg_lifecycle_zero(void) {
    REQUIRE(g_spx_pg_live_allocations == 0 && g_spx_pg_live_bytes == 0);
    REQUIRE(fixture_live == 0 && fixture_allocations == fixture_frees);
    REQUIRE(pg_live_handles == 0);
    for (size_t slot = 0; slot < SPX_PG_REGISTRY_CAPACITY; ++slot) {
        REQUIRE(g_spx_pg_registry[slot].kind == SPX_PG_KIND_NONE);
        REQUIRE(g_spx_pg_registry[slot].object == NULL);
        REQUIRE(g_spx_pg_providers[slot].identity == NULL);
        REQUIRE(g_spx_pg_providers[slot].object == NULL);
    }
}

static spx_pg_value_v1 *pg_lifecycle_prepare(spx_pg_provider_v1 *provider) {
    uint8_t copy[sizeof(pg_two_leaf_carrier)];
    memcpy(copy, pg_two_leaf_carrier, sizeof(copy));
    spx_pg_value_v1 *input = NULL;
    REQUIRE(spx_pg_input_prepare_v1(provider, copy, sizeof(copy), &input) == SPX_PG_STATUS_OK);
    /* Caller buffer mutations must not change private, already copied input. */
    memset(copy, 0xa5, sizeof(copy));
    return input;
}

static spx_pg_result_v1 *pg_lifecycle_call(spx_pg_provider_v1 *provider, spx_pg_value_v1 *input) {
    spx_pg_result_v1 *result = NULL;
    REQUIRE(spx_pg_call_v1(provider, input, &result) == SPX_PG_STATUS_OK);
    REQUIRE(result != NULL);
    return result;
}

static void pg_lifecycle_export(spx_pg_result_v1 *result) {
    uint8_t output[sizeof(pg_two_leaf_result)];
    size_t required = 0;
    size_t endpoints = pg_endpoint_invocations;
    memset(output, 0xa5, sizeof(output));
    REQUIRE(spx_pg_result_export_v1(result, output, sizeof(output) - 1, &required) ==
            SPX_PG_STATUS_BUFFER_TOO_SMALL);
    REQUIRE(required == sizeof(output));
    for (size_t index = 0; index < sizeof(output); ++index) REQUIRE(output[index] == 0xa5);
    for (unsigned iteration = 0; iteration < 2; ++iteration) {
        REQUIRE(spx_pg_result_export_v1(result, output, sizeof(output), &required) == SPX_PG_STATUS_OK);
        REQUIRE(required == sizeof(output));
        REQUIRE(memcmp(output, pg_two_leaf_result, sizeof(output)) == 0);
    }
    REQUIRE(pg_endpoint_invocations == endpoints); /* no hidden retry */
}

static void pg_lifecycle_reuse(size_t iterations) {
    spx_pg_provider_v1 *provider = open_trusted_provider();
    for (size_t iteration = 0; iteration < iterations; ++iteration) {
        pg_lifecycle_next_call();
        spx_pg_value_v1 *input = pg_lifecycle_prepare(provider);
        spx_pg_result_v1 *result = pg_lifecycle_call(provider, input);
        pg_lifecycle_export(result);
        pg_lifecycle_rejected(spx_pg_value_release_v1(&input), SPX_PG_STATUS_HANDLE_INVALID);
        REQUIRE(input == NULL);
        REQUIRE(spx_pg_result_release_v1(&result) == SPX_PG_STATUS_OK);
        REQUIRE(result == NULL);
        pg_check_reverse(2, 2);
        REQUIRE(g_spx_pg_live_allocations == 1 && fixture_live == 1);
        REQUIRE(g_spx_pg_live_bytes == sizeof(spx_pg_provider_state));
        REQUIRE(spx_pg_test_live_handles_v1(provider) == 0);
    }
    pg_check_zero_and_close(&provider);
}

static void pg_lifecycle_stale_children(void) {
    spx_pg_provider_v1 *provider = open_trusted_provider();
    spx_pg_value_v1 *old_input = pg_lifecycle_prepare(provider);
    spx_pg_value_v1 *stale_input = old_input;
    REQUIRE(spx_pg_value_release_v1(&old_input) == SPX_PG_STATUS_OK);
    spx_pg_value_v1 *input = pg_lifecycle_prepare(provider);
    REQUIRE(input != stale_input); /* fails when malloc recycles the old handle */
    spx_pg_result_v1 *result = NULL;
    pg_lifecycle_rejected(spx_pg_call_v1(provider, stale_input, &result), SPX_PG_STATUS_HANDLE_INVALID);
    REQUIRE(result == NULL && pg_endpoint_invocations == 0);
    result = pg_lifecycle_call(provider, input);
    spx_pg_result_v1 *stale_result = result;
    REQUIRE(spx_pg_result_release_v1(&result) == SPX_PG_STATUS_OK);
    for (unsigned iteration = 0; iteration < 64; ++iteration) {
        pg_lifecycle_next_call();
        input = pg_lifecycle_prepare(provider);
        REQUIRE(input != stale_input);
        result = pg_lifecycle_call(provider, input);
        REQUIRE(result != stale_result);
        uint8_t poison[32];
        memset(poison, 0xa5, sizeof(poison));
        size_t required = 123;
        pg_lifecycle_rejected(spx_pg_result_export_v1(stale_result, poison, sizeof(poison), &required),
                             SPX_PG_STATUS_HANDLE_INVALID);
        REQUIRE(required == 0);
        for (size_t index = 0; index < sizeof(poison); ++index) REQUIRE(poison[index] == 0xa5);
        spx_pg_result_v1 *alias = stale_result;
        pg_lifecycle_rejected(spx_pg_result_release_v1(&alias), SPX_PG_STATUS_HANDLE_INVALID);
        REQUIRE(alias == NULL && spx_pg_test_live_handles_v1(provider) == 1);
        pg_lifecycle_export(result);
        REQUIRE(spx_pg_result_release_v1(&result) == SPX_PG_STATUS_OK);
        pg_check_reverse(2, 2);
    }
    pg_check_zero_and_close(&provider);
}

static void pg_lifecycle_recreation(void) {
    spx_pg_provider_v1 *provider = open_trusted_provider();
    spx_pg_provider_v1 *stale_provider = provider;
    spx_pg_value_v1 *stale_input = pg_lifecycle_prepare(provider);
    spx_pg_result_v1 *result = pg_lifecycle_call(provider, stale_input);
    spx_pg_result_v1 *stale_result = result;
    REQUIRE(spx_pg_result_release_v1(&result) == SPX_PG_STATUS_OK);
    pg_check_zero_and_close(&provider);
    for (unsigned iteration = 0; iteration < 64; ++iteration) {
        pg_lifecycle_next_call();
        provider = open_trusted_provider();
        REQUIRE(provider != stale_provider);
        spx_pg_value_v1 *input = pg_lifecycle_prepare(provider);
        spx_pg_provider_v1 *alias = stale_provider;
        pg_lifecycle_rejected(spx_pg_provider_close_v1(&alias), SPX_PG_STATUS_HANDLE_INVALID);
        REQUIRE(alias == NULL && spx_pg_test_live_handles_v1(provider) == 1);
        spx_pg_value_v1 *refused = input;
        pg_lifecycle_rejected(spx_pg_input_prepare_v1(stale_provider, pg_empty_carrier,
                             sizeof(pg_empty_carrier), &refused), SPX_PG_STATUS_HANDLE_INVALID);
        REQUIRE(refused == NULL);
        pg_lifecycle_rejected(spx_pg_call_v1(stale_provider, input, &result), SPX_PG_STATUS_HANDLE_INVALID);
        REQUIRE(result == NULL);
        pg_lifecycle_rejected(spx_pg_call_v1(provider, stale_input, &result), SPX_PG_STATUS_HANDLE_INVALID);
        REQUIRE(result == NULL);
        size_t required = 123;
        pg_lifecycle_rejected(spx_pg_result_export_v1(stale_result, NULL, 0, &required),
                             SPX_PG_STATUS_HANDLE_INVALID);
        REQUIRE(required == 0);
        result = pg_lifecycle_call(provider, input);
        pg_lifecycle_export(result);
        REQUIRE(spx_pg_result_release_v1(&result) == SPX_PG_STATUS_OK);
        pg_check_reverse(2, 2);
        pg_check_zero_and_close(&provider);
    }
}

static void pg_lifecycle_hostile_providers(void) {
    spx_pg_provider_v1 *provider = open_trusted_provider();
    spx_pg_provider_v1 *other = open_trusted_provider();
    spx_pg_value_v1 *input = pg_lifecycle_prepare(provider);
    max_align_t foreign_object;
    spx_pg_provider_v1 *candidates[] = {
        (spx_pg_provider_v1 *)(void *)&foreign_object,
        (spx_pg_provider_v1 *)(void *)input
    };
    for (size_t index = 0; index < 2; ++index) {
        spx_pg_value_v1 *out = input;
        size_t before = pg_alloc_attempts;
        pg_lifecycle_rejected(spx_pg_input_prepare_v1(candidates[index], pg_empty_carrier,
                             sizeof(pg_empty_carrier), &out), SPX_PG_STATUS_HANDLE_INVALID);
        REQUIRE(out == NULL);
        spx_pg_result_v1 *result = NULL;
        pg_lifecycle_rejected(spx_pg_call_v1(candidates[index], input, &result), SPX_PG_STATUS_HANDLE_INVALID);
        REQUIRE(result == NULL);
        spx_pg_provider_v1 *alias = candidates[index];
        pg_lifecycle_rejected(spx_pg_provider_close_v1(&alias), SPX_PG_STATUS_HANDLE_INVALID);
        REQUIRE(alias == NULL && pg_alloc_attempts == before);
    }
    spx_pg_result_v1 *result = NULL;
    pg_lifecycle_rejected(spx_pg_call_v1(other, input, &result), SPX_PG_STATUS_HANDLE_INVALID);
    REQUIRE(result == NULL && pg_endpoint_invocations == 0);
    pg_lifecycle_rejected(spx_pg_provider_close_v1(&provider), SPX_PG_STATUS_ILLEGAL_TRANSITION);
    REQUIRE(provider != NULL);
    result = pg_lifecycle_call(provider, input);
    spx_pg_value_v1 *wrong_kind = (spx_pg_value_v1 *)(void *)result;
    pg_lifecycle_rejected(spx_pg_value_release_v1(&wrong_kind), SPX_PG_STATUS_ILLEGAL_TRANSITION);
    REQUIRE(wrong_kind == NULL);
    pg_lifecycle_export(result);
    REQUIRE(spx_pg_result_release_v1(&result) == SPX_PG_STATUS_OK);
    REQUIRE(spx_pg_provider_close_v1(&other) == SPX_PG_STATUS_OK);
    pg_check_zero_and_close(&provider);
}

/* Multiple prepared inputs are admitted by the registry. A sibling's
 * success/failure or a rejected prepare cannot select this call's status. */
static void pg_lifecycle_sibling_settlement(void) {
    spx_pg_provider_v1 *provider = open_trusted_provider();
    for (unsigned scenario = 0; scenario < 3; ++scenario) {
        pg_lifecycle_next_call();
        spx_pg_value_v1 *a = pg_lifecycle_prepare(provider);
        spx_pg_result_v1 *retained = NULL;
        if (scenario == 2) {
            uint8_t too_many[8];
            spx_pg_write_u64le(too_many, SPX_PG_MAX_OWNED_LEAVES + 1);
            spx_pg_value_v1 *refused = NULL;
            pg_lifecycle_rejected(spx_pg_input_prepare_v1(provider, too_many, sizeof(too_many), &refused),
                                 SPX_PG_STATUS_CARRIER_CAPACITY);
            REQUIRE(refused == NULL);
        } else {
            spx_pg_value_v1 *b = pg_lifecycle_prepare(provider);
            if (scenario == 0) {
                retained = pg_lifecycle_call(provider, b);
                spx_pg_test_inject_failure_v1(SPX_PG_TRACE_EXECUTION_STARTED);
            } else {
                spx_pg_test_inject_failure_v1(SPX_PG_TRACE_EXECUTION_STARTED);
                pg_lifecycle_rejected(spx_pg_call_v1(provider, b, &retained), SPX_PG_STATUS_CONTRACT_FAILURE);
                REQUIRE(retained == NULL);
            }
        }
        spx_pg_result_v1 *result = NULL;
        spx_pg_status_v1 status = spx_pg_call_v1(provider, a, &result);
        if (scenario == 0) {
            pg_lifecycle_rejected(status, SPX_PG_STATUS_CONTRACT_FAILURE);
            REQUIRE(result == NULL);
            pg_lifecycle_export(retained);
            REQUIRE(spx_pg_result_release_v1(&retained) == 0);
        } else {
            REQUIRE(status == SPX_PG_STATUS_OK && result != NULL);
            pg_lifecycle_export(result);
            REQUIRE(spx_pg_result_release_v1(&result) == 0);
        }
        REQUIRE(pg_live_handles == 0 && fixture_live == 1);
        REQUIRE(g_spx_pg_live_allocations == 1);
    }
    pg_check_zero_and_close(&provider);
}

static void pg_lifecycle_live_limit(int providers) {
    spx_pg_provider_v1 *roots[SPX_PG_REGISTRY_CAPACITY];
    spx_pg_value_v1 *children[SPX_PG_REGISTRY_CAPACITY];
    spx_pg_provider_v1 *provider = providers ? NULL : open_trusted_provider();
    for (size_t index = 0; index < SPX_PG_REGISTRY_CAPACITY; ++index) {
        if (providers) roots[index] = open_trusted_provider();
        else REQUIRE(spx_pg_input_prepare_v1(provider, pg_empty_carrier, sizeof(pg_empty_carrier),
                                              &children[index]) == SPX_PG_STATUS_OK);
    }
    size_t attempts = pg_alloc_attempts, identities = g_spx_pg_identities_used;
    if (providers) {
        spx_pg_provider_v1 *out = roots[0];
        pg_lifecycle_rejected(spx_pg_provider_open_v1(SPX_PG_TRUSTED_DESCRIPTOR_BYTES,
            SPX_PG_TRUSTED_DESCRIPTOR_LEN, SPX_PG_TRUSTED_BINDING_BYTES,
            SPX_PG_TRUSTED_BINDING_LEN, &out), SPX_PG_STATUS_CARRIER_CAPACITY);
        REQUIRE(out == NULL);
    } else {
        spx_pg_value_v1 *out = children[0];
        pg_lifecycle_rejected(spx_pg_input_prepare_v1(provider, pg_empty_carrier,
            sizeof(pg_empty_carrier), &out), SPX_PG_STATUS_CARRIER_CAPACITY);
        REQUIRE(out == NULL && pg_live_handles == SPX_PG_REGISTRY_CAPACITY);
    }
    REQUIRE(pg_alloc_attempts == attempts && g_spx_pg_identities_used == identities);
    for (size_t index = SPX_PG_REGISTRY_CAPACITY; index-- > 0;) {
        if (providers) REQUIRE(spx_pg_provider_close_v1(&roots[index]) == SPX_PG_STATUS_OK);
        else REQUIRE(spx_pg_value_release_v1(&children[index]) == SPX_PG_STATUS_OK);
    }
    if (!providers) pg_check_zero_and_close(&provider);
    /* Closing/settling returns live capacity, never a prior identity. */
    provider = open_trusted_provider();
    spx_pg_value_v1 *child = NULL;
    REQUIRE(spx_pg_input_prepare_v1(provider, pg_empty_carrier, sizeof(pg_empty_carrier), &child) == 0);
    REQUIRE(spx_pg_value_release_v1(&child) == 0);
    pg_check_zero_and_close(&provider);
}

static void pg_lifecycle_burn_to(size_t count) {
    REQUIRE(count <= SPX_PG_IDENTITY_CAPACITY);
    while (g_spx_pg_identities_used < count) {
        spx_pg_provider_v1 *provider = open_trusted_provider();
        REQUIRE(spx_pg_provider_close_v1(&provider) == SPX_PG_STATUS_OK);
    }
}

static void pg_lifecycle_identity_limit(unsigned kind) {
    REQUIRE(g_spx_pg_identities_used == 0); /* fresh process is mandatory */
    REQUIRE(SPX_PG_IDENTITY_CAPACITY == 65536u);
    pg_lifecycle_burn_to(SPX_PG_IDENTITY_CAPACITY - (kind == 0 ? 1 : kind == 1 ? 2 : 3));
    spx_pg_provider_v1 *provider = open_trusted_provider();
    spx_pg_value_v1 *input = NULL;
    spx_pg_result_v1 *result = NULL;
    if (kind != 0) input = pg_lifecycle_prepare(provider);
    if (kind >= 2) {
        if (kind == 3) {
            pg_lifecycle_burn_to(SPX_PG_IDENTITY_CAPACITY);
            size_t attempts = pg_alloc_attempts;
            pg_lifecycle_rejected(spx_pg_call_v1(provider, input, &result), SPX_PG_STATUS_CARRIER_CAPACITY);
            REQUIRE(result == NULL && pg_endpoint_invocations == 0 && pg_alloc_attempts == attempts);
            pg_lifecycle_rejected(spx_pg_value_release_v1(&input), SPX_PG_STATUS_HANDLE_INVALID);
            REQUIRE(input == NULL);
        } else {
            result = pg_lifecycle_call(provider, input);
            input = NULL;
            pg_lifecycle_export(result); /* export/release remain usable at capacity */
        }
    }
    REQUIRE(g_spx_pg_identities_used == SPX_PG_IDENTITY_CAPACITY);
    size_t attempts = pg_alloc_attempts;
    spx_pg_provider_v1 *extra = provider;
    pg_lifecycle_rejected(spx_pg_provider_open_v1(SPX_PG_TRUSTED_DESCRIPTOR_BYTES,
        SPX_PG_TRUSTED_DESCRIPTOR_LEN, SPX_PG_TRUSTED_BINDING_BYTES,
        SPX_PG_TRUSTED_BINDING_LEN, &extra), SPX_PG_STATUS_CARRIER_CAPACITY);
    REQUIRE(extra == NULL);
    spx_pg_value_v1 *extra_input = input;
    pg_lifecycle_rejected(spx_pg_input_prepare_v1(provider, pg_empty_carrier,
        sizeof(pg_empty_carrier), &extra_input), SPX_PG_STATUS_CARRIER_CAPACITY);
    REQUIRE(extra_input == NULL && pg_alloc_attempts == attempts);
    if (input != NULL) REQUIRE(spx_pg_value_release_v1(&input) == 0);
    if (result != NULL) REQUIRE(spx_pg_result_release_v1(&result) == 0);
    pg_check_zero_and_close(&provider);
    /* Reopening cannot rewind the identity serial even after all resources settle. */
    attempts = pg_alloc_attempts;
    pg_lifecycle_rejected(spx_pg_provider_open_v1(SPX_PG_TRUSTED_DESCRIPTOR_BYTES,
        SPX_PG_TRUSTED_DESCRIPTOR_LEN, SPX_PG_TRUSTED_BINDING_BYTES,
        SPX_PG_TRUSTED_BINDING_LEN, &extra), SPX_PG_STATUS_CARRIER_CAPACITY);
    REQUIRE(extra == NULL && pg_alloc_attempts == attempts);
}

static int pg_lifecycle_run(const char *id, int report) {
    pg_lifecycle_begin();
    size_t before = g_spx_pg_identities_used;
    if (strcmp(id, "reuse") == 0) pg_lifecycle_reuse(128);
    else if (strcmp(id, "stress") == 0) pg_lifecycle_reuse(8192);
    else if (strcmp(id, "stale_children") == 0) pg_lifecycle_stale_children();
    else if (strcmp(id, "recreation") == 0) pg_lifecycle_recreation();
    else if (strcmp(id, "hostile_providers") == 0) pg_lifecycle_hostile_providers();
    else if (strcmp(id, "sibling_settlement") == 0) pg_lifecycle_sibling_settlement();
    else if (strcmp(id, "live_providers") == 0) pg_lifecycle_live_limit(1);
    else if (strcmp(id, "live_children") == 0) pg_lifecycle_live_limit(0);
    else if (strcmp(id, "identity_provider") == 0) pg_lifecycle_identity_limit(0);
    else if (strcmp(id, "identity_input") == 0) pg_lifecycle_identity_limit(1);
    else if (strcmp(id, "identity_result") == 0) pg_lifecycle_identity_limit(2);
    else if (strcmp(id, "identity_result_over") == 0) pg_lifecycle_identity_limit(3);
    else return 0;
    pg_lifecycle_zero();
    if (report) printf("LIFECYCLE case_id=%s endpoints=%zu rejections=%zu identities=%zu "
        "peak_alloc=%zu peak_handles=%zu live_alloc=%zu live_handles=%zu live_bytes=%zu\n",
        id, pg_endpoint_invocations, pg_lifecycle_rejections, g_spx_pg_identities_used - before,
        pg_peak_alloc, pg_peak_handles, g_spx_pg_live_allocations, pg_live_handles, g_spx_pg_live_bytes);
    return 1;
}

static void check_lifecycle_regressions(void) {
    const char *ids[] = {"reuse", "stale_children", "recreation", "hostile_providers", "sibling_settlement", "live_providers", "live_children"};
    for (size_t index = 0; index < sizeof(ids) / sizeof(ids[0]); ++index) {
        REQUIRE(pg_lifecycle_run(ids[index], 0));
    }
}
