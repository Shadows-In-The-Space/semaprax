/* Appended to the actual rendered native provider after observation hooks.
 * Only hostile-export and close-refusal shims intercept public operations;
 * all allocation, transfer, execution, and release happen in provider_body.c. */
#undef malloc
#undef free
#undef spx_pg_result_export_v1
#undef spx_pg_provider_close_v1
#include "hooks.h"
static const struct consumer_case *consumer_case;
static size_t consumer_fields, consumer_exports;
static int consumer_cpp, close_refusal;
static size_t validated_release_count;
extern void consumer_test_client_print(void);
extern void consumer_test_client_begin(int cpp, int recipe, size_t fields);
extern void consumer_test_client_decode_begin(int recipe, size_t fields, int hostile);
extern void consumer_test_client_check(void);
static void consumer_payload(uint32_t leaf, const uint8_t *data, size_t len) {
    CHECK(len == consumer_test_length(consumer_case->recipe, leaf));
    for (size_t i = 0; i < len; ++i) CHECK(data[i] == consumer_test_byte(leaf, len - 1 - i));
}
void consumer_test_reset_observations(void) {
    pg_observe_reset();
    g_spx_pg_trace_len = 0;
}
void consumer_test_start(const struct consumer_case *test, int cpp, size_t fields) {
    consumer_test_reset_observations();
    consumer_case = test; consumer_cpp = cpp; consumer_fields = fields;
    pg_phase_enabled = 1;
    pg_phase_payload_check = consumer_payload;
}
void consumer_test_arm(void) {
    consumer_test_client_begin(consumer_cpp, consumer_case->recipe, consumer_fields);
    if (consumer_case->phase >= 0) {
        pg_phase_injections[0] = (struct pg_phase_injection){(uint32_t)consumer_case->phase, 1,
            consumer_case->phase_leaf < 0 ? UINT32_MAX : (uint32_t)consumer_case->phase_leaf, 1};
    }
    if (consumer_case->release_leaf >= 0) {
        pg_phase_injections[1] = (struct pg_phase_injection){SPX_PG_PHASE_LEAF_RELEASED, 1,
            (uint32_t)consumer_case->release_leaf, 1};
    }
    if (consumer_case->client_failure == 1) consumer_test_client_fail_after(1 + (consumer_cpp ? consumer_fields : 0));
    if (consumer_case->client_failure >= 100) consumer_test_client_fail_after((size_t)(consumer_case->client_failure - 99));
}
void consumer_test_close_refusal(void) { close_refusal = 1; }
spx_pg_status_v1 spx_pg_provider_close_v1(spx_pg_provider_v1 **provider) {
    if (close_refusal && provider != NULL && *provider != NULL) { close_refusal = 0; return SPX_PG_STATUS_ILLEGAL_TRANSITION; }
    return consumer_real_close(provider);
}
spx_pg_status_v1 spx_pg_result_export_v1(spx_pg_result_v1 *result, uint8_t *out, size_t capacity, size_t *required) {
    ++consumer_exports;
    spx_pg_status_v1 status = consumer_real_export(result, out, capacity, required);
    if (out == NULL) {
        if (consumer_case->export_mutation == 1) *required = 0;
        if (consumer_case->export_mutation == 2) *required = 16777216u + 8u * consumer_fields + 9u;
        if (consumer_case->export_mutation == 3) *required = SIZE_MAX;
        if (consumer_case->export_mutation == 8) ++*required;
        if (consumer_case->client_failure == 2) consumer_test_client_fail_after(1);
    } else if (status == SPX_PG_STATUS_OK) {
        consumer_test_client_decode_begin(consumer_case->recipe, consumer_fields, consumer_case->export_mutation != 0);
        if (consumer_case->export_mutation == 4) ++*required;
        if (consumer_case->export_mutation == 5) out[0] ^= 1;
        if (consumer_case->export_mutation == 6) spx_pg_write_u64le(out + 8, 65537);
        if (consumer_case->export_mutation == 7) spx_pg_write_u64le(out + 8, UINT64_MAX);
        if (consumer_case->export_mutation == 8) { CHECK(*required < capacity); out[(*required)++] = 0; }
        if (consumer_case->export_mutation == 9 || consumer_case->export_mutation == 10) {
            size_t offset = 8;
            for (size_t leaf = 0; leaf + 1 < consumer_fields; ++leaf) {
                offset += 8 + consumer_test_length(consumer_case->recipe, leaf);
            }
            spx_pg_write_u64le(out + offset, consumer_case->export_mutation == 9 ? 65537 : UINT64_MAX);
        }
        if (consumer_case->client_failure >= 3 && consumer_case->client_failure < 100) {
            consumer_test_client_fail_after((size_t)(consumer_case->client_failure - 2));
        }
    }
    return status;
}
void consumer_test_assert_empty_children(void) {
    CHECK(pg_live_handles == 0);
    consumer_test_client_check();
    /* Literal structural order per invocation, not agreement-only evidence. */
    size_t previous[2] = {SIZE_MAX, SIZE_MAX};
    for (size_t i = validated_release_count; i < pg_release_count; ++i) {
        struct pg_release_observation event = pg_release_order[i];
        CHECK(event.direction < 2 && event.leaf < previous[event.direction]);
        previous[event.direction] = event.leaf;
    }
    validated_release_count = pg_release_count;
}
void consumer_test_finish(int status, int native_status, int release_status) {
    CHECK(status == consumer_case->expected_status);
    CHECK(native_status == consumer_case->expected_native);
    CHECK(release_status == consumer_case->expected_release);
    CHECK(pg_endpoint_invocations == (size_t)consumer_case->endpoint);
    CHECK(pg_live_handles == 0 && fixture_live == 0 && g_spx_pg_live_allocations == 0 && g_spx_pg_live_bytes == 0);
    CHECK(g_spx_pg_trace_len < SPX_PG_TRACE_CAPACITY);
    CHECK(validated_release_count == pg_release_count);
    printf("CASE case_id=%s status=%d native=%d release=%d endpoint=%zu exports=%zu native_peak=%zu native_peak_bytes=%zu native_peak_handles=%zu native_live=%zu native_live_bytes=%zu native_live_handles=%zu trace=",
        consumer_case->id, status, native_status, release_status, pg_endpoint_invocations, consumer_exports,
        pg_peak_alloc, pg_peak_bytes, pg_peak_handles, g_spx_pg_live_allocations, g_spx_pg_live_bytes, pg_live_handles);
    for (size_t i = 0; i < g_spx_pg_trace_len; ++i) printf("%s%u", i ? "," : "", g_spx_pg_trace[i]);
    printf(" native_release=");
    for (size_t i = 0; i < pg_release_count; ++i) printf("%s%u:%u", i ? "," : "", pg_release_order[i].direction, pg_release_order[i].leaf);
    printf(" secondary=");
    for (size_t i = 0; i < pg_secondary_count; ++i) printf("%s%d", i ? "," : "", (int)pg_secondary_cleanup[i]);
    consumer_test_client_print();
    puts("");
}
