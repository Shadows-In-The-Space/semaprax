/* Test-only integration of the existing settlement-corpus observers. No new
 * production hook or ABI: the recipe uses only SPX_PG_PHYSICAL_PHASE. */
static void auth_check_payload(uint32_t leaf, const uint8_t *bytes, size_t length) {
    static const uint8_t first[] = {1, 7, 13}, second[] = {2, 11, 17, 23};
    REQUIRE(leaf < 2);
    REQUIRE(length == (leaf == 0 ? sizeof(first) : sizeof(second)));
    REQUIRE(memcmp(bytes, leaf == 0 ? first : second, length) == 0);
}
void auth_recipe(uint32_t mode) {
    REQUIRE(mode < 3);
    pg_observe_reset();
    pg_phase_enabled = 1;
    pg_phase_payload_check = auth_check_payload;
    if (mode == 1) {
        pg_phase_injections[0] = (struct pg_phase_injection){SPX_PG_PHASE_EXPORT_PENDING, 1, UINT32_MAX, 1};
        pg_phase_injections[1] = (struct pg_phase_injection){SPX_PG_PHASE_LEAF_RELEASED, 1, 1, 1};
    } else if (mode == 2) {
        /* Wrong phase must remain armed, not fail the next arbitrary event. */
        pg_phase_injections[0] = (struct pg_phase_injection){UINT32_MAX, 1, UINT32_MAX, 1};
    }
    fixture_peak = 0;
}
void auth_receipt(uint32_t mode, int32_t primary, int32_t secondary) {
    REQUIRE(primary == (mode == 1 ? 11 : 0));
    REQUIRE(secondary == (mode == 1 ? 11 : 0));
    REQUIRE(pg_endpoint_invocations == 1 && pg_phase_copies_checked == 2);
    REQUIRE(pg_release_count == 4);
    for (size_t i = 0; i < 4; ++i) {
        REQUIRE(pg_release_order[i].direction == (i < 2 ? 0u : 1u));
        REQUIRE(pg_release_order[i].leaf == (i % 2 == 0 ? 1u : 0u));
    }
    size_t injected = 0, export_count = 0, released = 0, first_release_allocations = 0;
    for (size_t i = 0; i < pg_phase_event_count; ++i) {
        const struct pg_phase_observation event = pg_phase_events[i];
        injected += event.injected != 0;
        if (event.phase == SPX_PG_PHASE_EXPORT_PENDING) {
            ++export_count;
            REQUIRE(event.direction == 1 && event.handles == 1);
            REQUIRE(event.injected == (mode == 1));
        }
        if (event.phase == SPX_PG_PHASE_LEAF_RELEASED && event.direction == 1) {
            REQUIRE(event.handles == 0);
            REQUIRE(event.leaf == (released == 0 ? 1u : 0u));
            REQUIRE(event.injected == (mode == 1 && released == 0));
            if (released == 0) first_release_allocations = event.allocations;
            else REQUIRE(event.allocations + 1 == first_release_allocations);
            ++released;
        }
    }
    REQUIRE(export_count == 1 && released == 2);
    REQUIRE(injected == (mode == 1 ? 2u : 0u));
    REQUIRE(pg_phase_injections[0].armed == (mode == 2));
    REQUIRE(pg_phase_injections[1].armed == 0);
    REQUIRE(pg_peak_alloc > 1 && pg_peak_bytes > 7 && pg_peak_handles > 0);
    REQUIRE(fixture_peak >= pg_peak_alloc);
    REQUIRE(fixture_live == 0 && pg_live_handles == 0);
    REQUIRE(spx_pg_test_live_allocations_v1() == 0);
    /* Exact provider-local receipt; host Vec/malloc peaks are NOT compared. */
    printf("%u %d %d %zu %zu %zu %zu %zu %zu %zu 0 0\n", mode, primary, secondary,
        pg_endpoint_invocations, injected, pg_peak_alloc, pg_peak_bytes,
        pg_peak_handles, fixture_peak, first_release_allocations);
}
