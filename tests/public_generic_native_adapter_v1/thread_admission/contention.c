/* Included after probe.c. Contenders are test infrastructure only. */
#define CONTENDERS 8u
static probe_barrier contender_barrier;
static atomic_uint contender_successes;
static atomic_uint contender_failures;
static void *contender(void *arg) {
    (void)arg;
    spx_pg_provider_v1 *provider = NULL;
    barrier_wait(&contender_barrier);
    spx_pg_status_v1 status = probe_open(&provider);
    if (status == SPX_PG_STATUS_OK) {
        REQUIRE(provider != NULL);
        atomic_fetch_add(&contender_successes, 1);
    } else {
        REQUIRE(status == SPX_PG_STATUS_ILLEGAL_TRANSITION);
        REQUIRE(provider == NULL);
        atomic_fetch_add(&contender_failures, 1);
    }
    /* The winner keeps the provider live until EVERY competing open returns.
     * Exactly one may succeed; timing/which thread won is not evidence. */
    barrier_wait(&contender_barrier);
    if (status == SPX_PG_STATUS_OK) REQUIRE(spx_pg_provider_close_v1(&provider) == 0);
    return NULL;
}
static void case_contention(unsigned rounds) {
    barrier_init(&contender_barrier, CONTENDERS);
    for (unsigned round = 0; round < rounds; ++round) {
        pthread_t threads[CONTENDERS];
        for (unsigned i = 0; i < CONTENDERS; ++i)
            REQUIRE(pthread_create(&threads[i], NULL, contender, NULL) == 0);
        for (unsigned i = 0; i < CONTENDERS; ++i)
            REQUIRE(pthread_join(threads[i], NULL) == 0);
        REQUIRE(atomic_load(&contender_successes) == round + 1);
        REQUIRE(atomic_load(&contender_failures) == (round + 1) * (CONTENDERS - 1));
        REQUIRE(spx_pg_test_live_allocations_v1() == 0);
        REQUIRE(fixture_live == 0);
        REQUIRE(spx_pg_atomic_load(&g_spx_pg_entry_state) == 0);
    }
    barrier_destroy(&contender_barrier);
    REQUIRE(probe_open(&thread_provider) == 0);
    probe_prepare(); probe_call(); probe_close();
    ++thread_checks;
}
static spx_pg_provider_v1 *old_provider;
static spx_pg_value_v1 *old_input;
static spx_pg_result_v1 *old_result;
static void *previous_owner(void *arg) {
    (void)arg;
    REQUIRE(probe_open(&thread_provider) == 0);
    old_provider = thread_provider;
    probe_prepare(); old_input = thread_input;
    probe_call(); old_result = thread_output;
    probe_close();
    REQUIRE(spx_pg_test_force_settlement_conflict_v1(SPX_PG_STATUS_CONTRACT_FAILURE) == 0);
    REQUIRE(spx_pg_test_settlement_overwrite_attempts_v1() == 1);
    REQUIRE(spx_pg_test_trace_len_v1() != 0);
    spx_pg_test_inject_failure_v1(SPX_PG_TRACE_EXECUTION_STARTED);
    return NULL;
}
static void case_handoff(void) {
    run_thread(previous_owner, NULL);
    REQUIRE(spx_pg_test_trace_len_v1() == 0);
    REQUIRE(spx_pg_test_settlement_overwrite_attempts_v1() == 0);
    REQUIRE(probe_open(&thread_provider) == 0);
    REQUIRE(thread_provider != old_provider);
    probe_prepare();
    spx_pg_result_v1 *output = NULL;
    REQUIRE(spx_pg_call_v1(old_provider, thread_input, &output) == SPX_PG_STATUS_HANDLE_INVALID);
    REQUIRE(output == NULL);
    REQUIRE(spx_pg_call_v1(thread_provider, old_input, &output) == SPX_PG_STATUS_HANDLE_INVALID);
    size_t required = 99;
    REQUIRE(spx_pg_result_export_v1(old_result, NULL, 0, &required) == SPX_PG_STATUS_HANDLE_INVALID);
    REQUIRE(required == 0);
    probe_call(); probe_close();
    ++thread_checks;
}
static void *new_owner(void *arg) {
    (void)arg;
    REQUIRE(probe_open(&thread_provider) == 0);
    probe_prepare(); probe_call(); probe_close();
    return NULL;
}
static void case_multiple_providers(void) {
    spx_pg_provider_v1 *other = NULL;
    REQUIRE(probe_open(&thread_provider) == 0);
    REQUIRE(probe_open(&other) == 0);
    REQUIRE(spx_pg_provider_close_v1(&other) == 0);
    run_thread(foreign_surface, NULL);
    REQUIRE(spx_pg_atomic_load(&g_spx_pg_entry_state) != 0);
    probe_close();
    run_thread(new_owner, NULL);
    REQUIRE(spx_pg_test_live_allocations_v1() == 0);
    ++thread_checks;
}
static void *failed_open(void *arg) {
    (void)arg;
    spx_pg_provider_v1 *provider = NULL;
    unsigned char wrong[] = {0};
    REQUIRE(spx_pg_provider_open_v1(wrong, sizeof wrong, SPX_PG_TRUSTED_BINDING_BYTES,
        SPX_PG_TRUSTED_BINDING_LEN, &provider) == SPX_PG_STATUS_DESCRIPTOR_REPLAY_MISMATCH);
    REQUIRE(provider == NULL);
    REQUIRE(spx_pg_test_live_allocations_v1() == 0);
    return NULL;
}
static void case_failed_open(void) {
    run_thread(failed_open, NULL);
    REQUIRE(spx_pg_atomic_load(&g_spx_pg_entry_state) == 0);
    REQUIRE(probe_open(&thread_provider) == 0);
    probe_prepare(); probe_call(); probe_close();
    ++thread_checks;
}
static void *exhausted_thread(void *arg) {
    (void)arg;
    refused_surface(SPX_PG_STATUS_CARRIER_CAPACITY);
    REQUIRE(g_spx_pg_thread_id == 0);
    return NULL;
}
static void case_thread_capacity(void) {
    /* Test-only first-over control; production never exposes these counters. */
    REQUIRE(spx_pg_test_live_allocations_v1() == 0); /* retain an existing identity */
    spx_pg_atomic_store(&g_spx_pg_thread_ids, SPX_PG_THREAD_ID_LIMIT - 1);
    run_thread(new_owner, NULL); /* exactly the last admitted thread identity */
    REQUIRE(spx_pg_atomic_load(&g_spx_pg_thread_ids) == SPX_PG_THREAD_ID_LIMIT);
    REQUIRE(probe_open(&thread_provider) == 0);
    probe_prepare();
    run_thread(exhausted_thread, NULL);
    REQUIRE(spx_pg_atomic_load(&g_spx_pg_thread_ids) == SPX_PG_THREAD_ID_LIMIT);
    probe_call(); probe_close(); /* existing identity can always finish cleanup */
    run_thread(exhausted_thread, NULL); /* remains exhausted, never wraps */
    ++thread_checks;
}
static void case_cleanup_reentry(void) {
    REQUIRE(probe_open(&thread_provider) == 0);
    probe_prepare();
    spx_pg_test_inject_failure_v1(SPX_PG_TRACE_EXECUTION_STARTED);
    spx_pg_test_inject_failure_v1(SPX_PG_TRACE_LEAF_RELEASE);
    hook_point = 4; hook_mode = 1;
    REQUIRE(spx_pg_call_v1(thread_provider, thread_input, &thread_output) == SPX_PG_STATUS_CONTRACT_FAILURE);
    thread_input = NULL;
    REQUIRE(thread_output == NULL && hook_hits == 1);
    REQUIRE(spx_pg_test_settlement_overwrite_attempts_v1() == 0);
    spx_pg_test_clear_failure_injection_v1();
    probe_prepare(); probe_call(); probe_close();
    ++thread_checks;
}
/* These threads overlap in lifetime. A relaxed turn flag controls the test
 * schedule but deliberately DOES NOT publish provider state. Publication must
 * come from the provider's own acquire/release admission word, not a test mutex
 * or pthread_join that could conceal missing memory ordering from TSan. */
#include <sched.h>
static atomic_uint handoff_turn;
static void *overlapping_owner(void *arg) {
    unsigned id = *(unsigned *)arg;
    for (unsigned round = 0; round < 64; ++round) {
        while (atomic_load_explicit(&handoff_turn, memory_order_relaxed) != id)
            (void)sched_yield();
        spx_pg_provider_v1 *provider = NULL;
        unsigned attempts = 0;
        for (;;) {
            spx_pg_status_v1 status = probe_open(&provider);
            if (status == SPX_PG_STATUS_OK) break;
            REQUIRE(status == SPX_PG_STATUS_ILLEGAL_TRANSITION);
            REQUIRE(provider == NULL && ++attempts < 1000000);
            /* Explicit test-only open retry, before any input or execution;
             * weakly ordered hosts may observe the turn before quiescence. */
            (void)sched_yield();
        }
        spx_pg_value_v1 *input = NULL;
        spx_pg_result_v1 *result = NULL;
        REQUIRE(spx_pg_input_prepare_v1(provider, thread_carrier, sizeof thread_carrier, &input) == 0);
        REQUIRE(spx_pg_call_v1(provider, input, &result) == 0);
        unsigned char bytes[sizeof thread_result];
        size_t required = 0;
        REQUIRE(spx_pg_result_export_v1(result, bytes, sizeof bytes, &required) == 0);
        REQUIRE(required == sizeof bytes && memcmp(bytes, thread_result, sizeof bytes) == 0);
        REQUIRE(spx_pg_result_release_v1(&result) == 0);
        /* Read private counters while this provider still pins our ownership.
         * Reading after close would itself race with the next owner's open,
         * since the relaxed scheduling flag intentionally provides no HB. */
        REQUIRE(fixture_live == 1 && g_spx_pg_live_bytes == sizeof(spx_pg_provider_state));
        REQUIRE(spx_pg_provider_close_v1(&provider) == 0);
        atomic_store_explicit(&handoff_turn, 1u - id, memory_order_relaxed);
    }
    return NULL;
}
static void case_overlapping_handoff(void) {
    pthread_t actors[2];
    unsigned identities[] = {0, 1};
    for (unsigned i = 0; i < 2; ++i)
        REQUIRE(pthread_create(&actors[i], NULL, overlapping_owner, &identities[i]) == 0);
    for (unsigned i = 0; i < 2; ++i) REQUIRE(pthread_join(actors[i], NULL) == 0);
    REQUIRE(atomic_load(&thread_endpoints) == 128);
    REQUIRE(spx_pg_test_live_allocations_v1() == 0);
    ++thread_checks;
}

static int run_admission_case(const char *id) {
    if (strcmp(id, "foreign-input") == 0) case_foreign(0);
    else if (strcmp(id, "foreign-result") == 0) case_foreign(1);
    else if (strcmp(id, "foreign-fault-arm") == 0) case_injection(0);
    else if (strcmp(id, "foreign-fault-clear") == 0) case_injection(1);
    else if (strcmp(id, "reentry-open") == 0) case_reentry(0);
    else if (strcmp(id, "reentry-prepare") == 0) case_reentry(1);
    else if (strcmp(id, "reentry-call") == 0) case_reentry(2);
    else if (strcmp(id, "reentry-export") == 0) case_reentry(3);
    else if (strcmp(id, "reentry-input-release") == 0) case_reentry(4);
    else if (strcmp(id, "reentry-result-release") == 0) case_reentry(5);
    else if (strcmp(id, "reentry-close") == 0) case_reentry(6);
    else if (strcmp(id, "reentry-cleanup-failure") == 0) case_cleanup_reentry();
    else if (strcmp(id, "paused-open") == 0) case_paused(0, 1);
    else if (strcmp(id, "paused-prepare") == 0) case_paused(1, 1);
    else if (strcmp(id, "paused-call") == 0) case_paused(2, 1);
    else if (strcmp(id, "paused-export") == 0) case_paused(3, 1);
    else if (strcmp(id, "paused-release") == 0) case_paused(4, 1);
    else if (strcmp(id, "paused-close") == 0) case_paused(5, 1);
    else if (strcmp(id, "refusal-stress") == 0) case_paused(2, 1024);
    else if (strcmp(id, "contended-first-open") == 0) case_contention(1);
    else if (strcmp(id, "contended-epochs") == 0) case_contention(64);
    else if (strcmp(id, "overlapping-owner-handoff") == 0) case_overlapping_handoff();
    else if (strcmp(id, "owner-handoff") == 0) case_handoff();
    else if (strcmp(id, "last-provider-close") == 0) case_multiple_providers();
    else if (strcmp(id, "failed-open-unpins") == 0) case_failed_open();
    else if (strcmp(id, "thread-identity-bound") == 0) case_thread_capacity();
    else return 2;
    REQUIRE(thread_checks == 1);
    REQUIRE(spx_pg_test_live_allocations_v1() == 0);
    REQUIRE(g_spx_pg_live_bytes == 0 && fixture_live == 0);
    REQUIRE(spx_pg_atomic_load(&g_spx_pg_entry_state) == 0);
    REQUIRE(g_spx_pg_entry_active == 0);
    printf("THREAD case=%s checks=%u refusals=%u endpoints=%u winners=%u losers=%u peak_alloc=%zu live=0 bytes=0 fixture_live=0 owner_released=1\n",
        id, thread_checks, atomic_load(&thread_refusals), atomic_load(&thread_endpoints),
        atomic_load(&contender_successes), atomic_load(&contender_failures), fixture_peak);
    return 0;
}
