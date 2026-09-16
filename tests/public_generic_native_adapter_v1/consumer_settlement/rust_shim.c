/* Test-only shim appended to the actual rendered provider. Rust remains the
 * caller: allocation/transfer/endpoint/release all execute provider_body.c. */
#undef malloc
#undef free
#undef spx_pg_result_export_v1
#undef spx_pg_provider_close_v1
static uint32_t rs_case;
static size_t rs_exports;
static int rs_refuse_close;
static void rs_payload(uint32_t leaf, const uint8_t *bytes, size_t length) {
    (void)leaf; (void)bytes; REQUIRE(length <= 65536);
}
void spx_pg_rs_case_v1(uint32_t id) {
    REQUIRE(pg_live_handles == 0);
    if (fixture_live == 0) pg_observe_reset();
    spx_pg_test_clear_failure_injection_v1();
    rs_case = id; rs_exports = 0; rs_refuse_close = (id == 6);
    pg_endpoint_invocations = 0;
    pg_release_count = pg_secondary_count = pg_phase_event_count = 0;
    pg_phase_enabled = 1; pg_phase_payload_check = rs_payload;
    memset(pg_phase_injections, 0, sizeof(pg_phase_injections));
    if (id >= 1 && id <= 5) {
        pg_phase_injections[1] = (struct pg_phase_injection){7, 1, id == 5 ? 0 : 1, 1};
    }
    if (id == 2) pg_phase_injections[0] = (struct pg_phase_injection){5,1,UINT32_MAX,1};
    if (id == 5) pg_phase_injections[0] = (struct pg_phase_injection){0,1,1,1};
    if (id == 7 || id == 8) {
        pg_phase_injections[0] = (struct pg_phase_injection){id == 7 ? 2 : 6,1,1,1};
        pg_phase_injections[1] = (struct pg_phase_injection){7,1,1,1};
    }
}
size_t spx_pg_rs_live_v1(void) { return fixture_live; }
size_t spx_pg_rs_endpoint_v1(void) { return pg_endpoint_invocations; }
size_t spx_pg_rs_exports_v1(void) { return rs_exports; }
void spx_pg_rs_assert_order_v1(void) {
    size_t previous[2] = {SIZE_MAX,SIZE_MAX};
    for (size_t i = 0; i < pg_release_count; ++i) {
        struct pg_release_observation event = pg_release_order[i];
        REQUIRE(event.direction < 2 && event.leaf < previous[event.direction]);
        previous[event.direction] = event.leaf;
    }
}
spx_pg_status_v1 spx_pg_result_export_v1(spx_pg_result_v1 *result, uint8_t *out, size_t capacity, size_t *required) {
    ++rs_exports;
    spx_pg_status_v1 status = rs_real_export(result, out, capacity, required);
    if (out == NULL && rs_case == 3) *required = SIZE_MAX;
    if (out != NULL && status == SPX_PG_STATUS_OK && rs_case == 4) out[0] ^= 1;
    return status;
}
spx_pg_status_v1 spx_pg_provider_close_v1(spx_pg_provider_v1 **provider) {
    if (rs_refuse_close) { rs_refuse_close = 0; return SPX_PG_STATUS_ILLEGAL_TRANSITION; }
    return rs_real_close(provider);
}
