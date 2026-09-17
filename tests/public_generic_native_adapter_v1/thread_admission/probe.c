/* Real pthread misuse against the native provider. Private test hooks make
 * races deterministic; no sleeps, timeout-based retry, or thread IDs enter
 * the normalized evidence. Each selected case runs in a fresh process. */
static const unsigned char thread_carrier[] = {
    1,0,0,0,0,0,0,0, 4,0,0,0,0,0,0,0, 1,0,2,3
};
static const unsigned char thread_result[] = {
    1,0,0,0,0,0,0,0, 4,0,0,0,0,0,0,0, 3,2,0,1
};
static spx_pg_provider_v1 *thread_provider;
static spx_pg_value_v1 *thread_input;
static spx_pg_result_v1 *thread_output;
static atomic_uint thread_refusals;
static atomic_uint thread_endpoints;
static unsigned thread_checks;
static _Thread_local unsigned hook_point;
static _Thread_local unsigned hook_mode;
static _Thread_local unsigned hook_hits;

/* Portable pthread barrier (macOS has no pthread_barrier_t). The admission
 * implementation itself has no dependency on this or any other OS thread API. */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned expected, arrived, generation;
} probe_barrier;
static void barrier_init(probe_barrier *barrier, unsigned expected) {
    REQUIRE(pthread_mutex_init(&barrier->mutex, NULL) == 0);
    REQUIRE(pthread_cond_init(&barrier->condition, NULL) == 0);
    barrier->expected = expected; barrier->arrived = 0; barrier->generation = 0;
}
static void barrier_wait(probe_barrier *barrier) {
    REQUIRE(pthread_mutex_lock(&barrier->mutex) == 0);
    unsigned generation = barrier->generation;
    if (++barrier->arrived == barrier->expected) {
        barrier->arrived = 0; ++barrier->generation;
        REQUIRE(pthread_cond_broadcast(&barrier->condition) == 0);
    } else {
        while (generation == barrier->generation)
            REQUIRE(pthread_cond_wait(&barrier->condition, &barrier->mutex) == 0);
    }
    REQUIRE(pthread_mutex_unlock(&barrier->mutex) == 0);
}
static void barrier_destroy(probe_barrier *barrier) {
    REQUIRE(pthread_cond_destroy(&barrier->condition) == 0);
    REQUIRE(pthread_mutex_destroy(&barrier->mutex) == 0);
}
static probe_barrier pause_barrier;

static spx_pg_status_v1 probe_open(spx_pg_provider_v1 **provider) {
    return spx_pg_provider_open_v1(SPX_PG_TRUSTED_DESCRIPTOR_BYTES,
        SPX_PG_TRUSTED_DESCRIPTOR_LEN, SPX_PG_TRUSTED_BINDING_BYTES,
        SPX_PG_TRUSTED_BINDING_LEN, provider);
}
static void probe_prepare(void) {
    REQUIRE(spx_pg_input_prepare_v1(thread_provider, thread_carrier,
        sizeof thread_carrier, &thread_input) == SPX_PG_STATUS_OK);
    REQUIRE(thread_input != NULL);
}
static void probe_call(void) {
    REQUIRE(spx_pg_call_v1(thread_provider, thread_input, &thread_output) == SPX_PG_STATUS_OK);
    thread_input = NULL;
    REQUIRE(thread_output != NULL);
    unsigned char bytes[sizeof thread_result];
    size_t required = 0;
    REQUIRE(spx_pg_result_export_v1(thread_output, bytes, sizeof bytes, &required) == SPX_PG_STATUS_OK);
    REQUIRE(required == sizeof thread_result);
    REQUIRE(memcmp(bytes, thread_result, sizeof bytes) == 0);
}
static void probe_close(void) {
    if (thread_input != NULL) REQUIRE(spx_pg_value_release_v1(&thread_input) == 0);
    if (thread_output != NULL) REQUIRE(spx_pg_result_release_v1(&thread_output) == 0);
    REQUIRE(spx_pg_test_live_handles_v1(thread_provider) == 0);
    REQUIRE(spx_pg_provider_close_v1(&thread_provider) == 0);
    REQUIRE(thread_provider == NULL);
    REQUIRE(spx_pg_test_live_allocations_v1() == 0);
    REQUIRE(fixture_live == 0);
    REQUIRE(g_spx_pg_live_bytes == 0);
}
static void run_thread(void *(*fn)(void *), void *arg) {
    pthread_t thread;
    REQUIRE(pthread_create(&thread, NULL, fn, arg) == 0);
    REQUIRE(pthread_join(thread, NULL) == 0);
}
static void refusal(spx_pg_status_v1 actual, spx_pg_status_v1 expected) {
    REQUIRE(actual == expected);
    atomic_fetch_add(&thread_refusals, 1);
}

/* Caller storage is valid but marked. Refusal must not touch output slots,
 * buffers, or owning aliases, even when the owner is mid-allocation/free. */
static void refused_surface(spx_pg_status_v1 expected) {
    spx_pg_provider_v1 marker_provider = {0};
    spx_pg_value_v1 marker_input = {0};
    spx_pg_result_v1 marker_result = {0};
    spx_pg_provider_v1 *provider = &marker_provider;
    spx_pg_value_v1 *input = &marker_input;
    spx_pg_result_v1 *result = &marker_result;
    refusal(probe_open(&provider), expected);
    REQUIRE(provider == &marker_provider);
    refusal(spx_pg_input_prepare_v1(thread_provider, thread_carrier,
        sizeof thread_carrier, &input), expected);
    REQUIRE(input == &marker_input);
    refusal(spx_pg_call_v1(thread_provider, thread_input, &result), expected);
    REQUIRE(result == &marker_result);
    unsigned char bytes[sizeof thread_result];
    memset(bytes, 0xa5, sizeof bytes);
    size_t required = 123;
    refusal(spx_pg_result_export_v1(thread_output, bytes, sizeof bytes, &required), expected);
    REQUIRE(required == 123);
    for (size_t i = 0; i < sizeof bytes; ++i) REQUIRE(bytes[i] == 0xa5);
    provider = thread_provider; input = thread_input; result = thread_output;
    refusal(spx_pg_value_release_v1(&input), expected);
    REQUIRE(input == thread_input);
    refusal(spx_pg_result_release_v1(&result), expected);
    REQUIRE(result == thread_output);
    refusal(spx_pg_provider_close_v1(&provider), expected);
    REQUIRE(provider == thread_provider);
    /* Admission precedes null/framing/pairing validation. */
    refusal(spx_pg_provider_open_v1(NULL, SIZE_MAX, NULL, SIZE_MAX, NULL), expected);
    refusal(spx_pg_input_prepare_v1(NULL, NULL, SIZE_MAX, NULL), expected);
    refusal(spx_pg_call_v1(NULL, NULL, NULL), expected);
    refusal(spx_pg_result_export_v1(NULL, NULL, SIZE_MAX, NULL), expected);
    refusal(spx_pg_value_release_v1(NULL), expected);
    refusal(spx_pg_result_release_v1(NULL), expected);
    refusal(spx_pg_provider_close_v1(NULL), expected);
    refusal(spx_pg_test_force_settlement_conflict_v1(SPX_PG_STATUS_CONTRACT_FAILURE), expected);
    REQUIRE(spx_pg_test_live_allocations_v1() == SIZE_MAX);
    REQUIRE(spx_pg_test_live_handles_v1(thread_provider) == SIZE_MAX);
}
static void *foreign_surface(void *arg) {
    (void)arg;
    REQUIRE(spx_pg_test_trace_len_v1() == 0);
    REQUIRE(spx_pg_test_trace_label_v1(0) == SPX_PG_TEST_NO_INJECTION);
    REQUIRE(spx_pg_test_settlement_overwrite_attempts_v1() == 0);
    refused_surface(SPX_PG_STATUS_ILLEGAL_TRANSITION);
    REQUIRE(spx_pg_test_trace_len_v1() == 0);
    REQUIRE(spx_pg_test_settlement_overwrite_attempts_v1() == 0);
    return NULL;
}
static void *foreign_arm(void *arg) {
    (void)arg;
    spx_pg_test_inject_failure_v1(SPX_PG_TRACE_EXECUTION_STARTED);
    return NULL;
}
static void *foreign_clear(void *arg) {
    (void)arg;
    spx_pg_test_clear_failure_injection_v1();
    return NULL;
}
static void *foreign_during_entry(void *arg) {
    unsigned repeats = *(unsigned *)arg;
    barrier_wait(&pause_barrier);
    for (unsigned i = 0; i < repeats; ++i) refused_surface(SPX_PG_STATUS_ILLEGAL_TRANSITION);
    barrier_wait(&pause_barrier);
    return NULL;
}
static void thread_probe_hook(unsigned point) {
    if (point == 3) atomic_fetch_add(&thread_endpoints, 1);
    if (point != hook_point || hook_mode == 0) return;
    unsigned mode = hook_mode;
    hook_mode = 0; ++hook_hits;
    if (mode == 1) {
        uint64_t before = spx_pg_atomic_load(&g_spx_pg_entry_state);
        REQUIRE((before & 1) == 1);
        size_t trace_len = g_spx_pg_trace_len;
        refused_surface(SPX_PG_STATUS_ILLEGAL_TRANSITION);
        /* Reentrant test setters must not mutate an active call's own plan. */
        uint32_t first = g_spx_pg_injected_ordinals[0];
        uint32_t second = g_spx_pg_injected_ordinals[1];
        spx_pg_test_clear_failure_injection_v1();
        spx_pg_test_inject_failure_v1(SPX_PG_TRACE_EXECUTION_STARTED);
        REQUIRE(first == g_spx_pg_injected_ordinals[0]);
        REQUIRE(second == g_spx_pg_injected_ordinals[1]);
        REQUIRE(trace_len == g_spx_pg_trace_len);
        REQUIRE(spx_pg_atomic_load(&g_spx_pg_entry_state) == before);
    } else {
        REQUIRE(mode == 2);
        uint64_t before = spx_pg_atomic_load(&g_spx_pg_entry_state);
        size_t allocations = fixture_allocations, frees = fixture_frees;
        size_t identities = g_spx_pg_identities_used, trace = g_spx_pg_trace_len;
        barrier_wait(&pause_barrier);
        barrier_wait(&pause_barrier);
        REQUIRE(spx_pg_atomic_load(&g_spx_pg_entry_state) == before);
        REQUIRE(fixture_allocations == allocations && fixture_frees == frees);
        REQUIRE(g_spx_pg_identities_used == identities && g_spx_pg_trace_len == trace);
    }
}

static void case_foreign(int result_live) {
    REQUIRE(probe_open(&thread_provider) == 0);
    probe_prepare();
    if (result_live) probe_call();
    size_t trace = spx_pg_test_trace_len_v1();
    size_t allocations = spx_pg_test_live_allocations_v1();
    run_thread(foreign_surface, NULL);
    REQUIRE(trace == spx_pg_test_trace_len_v1());
    REQUIRE(allocations == spx_pg_test_live_allocations_v1());
    if (!result_live) probe_call();
    probe_close();
    ++thread_checks;
}
static void case_injection(int clear) {
    REQUIRE(probe_open(&thread_provider) == 0);
    probe_prepare();
    if (clear) {
        spx_pg_test_inject_failure_v1(SPX_PG_TRACE_EXECUTION_STARTED);
        spx_pg_test_inject_failure_v1(SPX_PG_TRACE_LEAF_RELEASE);
        run_thread(foreign_clear, NULL);
        REQUIRE(spx_pg_call_v1(thread_provider, thread_input, &thread_output) == SPX_PG_STATUS_CONTRACT_FAILURE);
        thread_input = NULL;
        REQUIRE(thread_output == NULL);
        REQUIRE(spx_pg_test_settlement_overwrite_attempts_v1() == 0);
    } else {
        run_thread(foreign_arm, NULL);
        probe_call();
    }
    spx_pg_test_clear_failure_injection_v1();
    probe_close();
    ++thread_checks;
}
static void case_reentry(unsigned operation) {
    if (operation != 0) REQUIRE(probe_open(&thread_provider) == 0);
    if (operation >= 2 && operation <= 5) probe_prepare();
    if (operation == 3 || operation == 5) probe_call();
    const unsigned points[] = {1,1,3,5,4,4,6};
    hook_point = points[operation]; hook_mode = 1;
    switch (operation) {
    case 0: REQUIRE(probe_open(&thread_provider) == 0); break;
    case 1: probe_prepare(); break;
    case 2: probe_call(); break;
    case 3: {
        size_t required = 0; unsigned char bytes[sizeof thread_result];
        REQUIRE(spx_pg_result_export_v1(thread_output, bytes, sizeof bytes, &required) == 0);
        REQUIRE(required == sizeof bytes && memcmp(bytes, thread_result, sizeof bytes) == 0);
        break;
    }
    case 4: REQUIRE(spx_pg_value_release_v1(&thread_input) == 0); break;
    case 5: REQUIRE(spx_pg_result_release_v1(&thread_output) == 0); break;
    case 6: REQUIRE(spx_pg_provider_close_v1(&thread_provider) == 0); break;
    default: REQUIRE(0);
    }
    REQUIRE(hook_hits == 1);
    probe_close();
    ++thread_checks;
}
static void case_paused(unsigned operation, unsigned repeats) {
    if (operation != 0) REQUIRE(probe_open(&thread_provider) == 0);
    if (operation >= 2 && operation <= 4) probe_prepare();
    if (operation == 3 || operation == 4) probe_call();
    barrier_init(&pause_barrier, 2);
    pthread_t thread;
    REQUIRE(pthread_create(&thread, NULL, foreign_during_entry, &repeats) == 0);
    const unsigned points[] = {1,1,3,5,4,6};
    hook_point = points[operation]; hook_mode = 2;
    switch (operation) {
    case 0: REQUIRE(probe_open(&thread_provider) == 0); break;
    case 1: probe_prepare(); break;
    case 2: probe_call(); break;
    case 3: {
        size_t required; unsigned char bytes[sizeof thread_result];
        REQUIRE(spx_pg_result_export_v1(thread_output, bytes, sizeof bytes, &required) == 0);
        REQUIRE(required == sizeof bytes && memcmp(bytes, thread_result, sizeof bytes) == 0);
        break;
    }
    case 4: REQUIRE(spx_pg_result_release_v1(&thread_output) == 0); break;
    case 5: REQUIRE(spx_pg_provider_close_v1(&thread_provider) == 0); break;
    default: REQUIRE(0);
    }
    REQUIRE(pthread_join(thread, NULL) == 0);
    barrier_destroy(&pause_barrier);
    REQUIRE(hook_hits == 1);
    probe_close();
    ++thread_checks;
}
