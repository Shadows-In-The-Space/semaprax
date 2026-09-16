/* Test-only observers, included BEFORE the rendered provider. They observe
 * actual successful allocations, handle transitions, endpoint entry and
 * physical leaf discharge. No production symbols or carrier bytes change. */
struct pg_release_observation { uint32_t direction, leaf; };
static struct pg_release_observation pg_release_order[1024];
static size_t pg_release_count, pg_peak_alloc, pg_peak_bytes;
static size_t pg_live_handles, pg_peak_handles, pg_endpoint_invocations;
static int32_t pg_secondary_cleanup[16];
static size_t pg_secondary_count;
static size_t pg_alloc_attempts, pg_fail_allocation_at;
static int pg_fail_allocation(void) {
    ++pg_alloc_attempts;
    return pg_fail_allocation_at != 0 && pg_alloc_attempts == pg_fail_allocation_at;
}
static uint32_t pg_occurrence_label[2], pg_occurrence_remaining[2];

static void pg_observe_allocation(size_t count, size_t bytes) {
    if (count > pg_peak_alloc) pg_peak_alloc = count;
    if (bytes > pg_peak_bytes) pg_peak_bytes = bytes;
}
static void pg_observe_handle(int delta) {
    if (delta < 0) {
        REQUIRE(pg_live_handles > 0);
        --pg_live_handles;
    } else {
        ++pg_live_handles;
        if (pg_live_handles > pg_peak_handles) pg_peak_handles = pg_live_handles;
    }
}
static void pg_observe_release(uint32_t direction, uint32_t index) {
    REQUIRE(pg_release_count < 1024);
    pg_release_order[pg_release_count++] = (struct pg_release_observation){direction, index};
}
static void pg_observe_cleanup(int selected, int32_t status) {
    if (selected) {
        REQUIRE(pg_secondary_count < 16);
        pg_secondary_cleanup[pg_secondary_count++] = status;
    }
}
static int pg_inject_occurrence(uint32_t label) {
    for (size_t slot = 0; slot < 2; ++slot) {
        if (pg_occurrence_remaining[slot] != 0 && pg_occurrence_label[slot] == label) {
            --pg_occurrence_remaining[slot];
            if (pg_occurrence_remaining[slot] == 0) return 1;
        }
    }
    return 0;
}
/* Physical phase observation is opt-in per case; no payload or pointer is
 * retained. The absence of room is a hard failure, not a truncated receipt. */
struct pg_phase_observation {
    uint32_t phase, direction, leaf;
    size_t allocations, handles;
    int injected;
};
struct pg_phase_injection { uint32_t phase, direction, leaf; int armed; };
static struct pg_phase_observation pg_phase_events[4096];
static struct pg_phase_injection pg_phase_injections[2];
static size_t pg_phase_event_count;
static int pg_phase_enabled;
static size_t pg_phase_copies_checked;
static void (*pg_phase_payload_check)(uint32_t, const uint8_t *, size_t);
static void pg_observe_result_payload(uint32_t leaf, const uint8_t *bytes, size_t length) {
    if (pg_phase_enabled) {
        REQUIRE(pg_phase_payload_check != NULL);
        pg_phase_payload_check(leaf, bytes, length);
        ++pg_phase_copies_checked;
    }
}
static int pg_observe_phase(uint32_t phase, uint32_t direction, uint32_t leaf,
                            size_t allocations, size_t bytes) {
    (void)bytes; /* target-local requested-byte peaks are observed separately */
    if (!pg_phase_enabled) return 0;
    int injected = 0;
    for (size_t slot = 0; slot < 2; ++slot) {
        struct pg_phase_injection *item = &pg_phase_injections[slot];
        if (item->armed && item->phase == phase && item->direction == direction && item->leaf == leaf) {
            item->armed = 0;
            injected = 1;
        }
    }
    REQUIRE(pg_phase_event_count < 4096);
    pg_phase_events[pg_phase_event_count++] = (struct pg_phase_observation){
        phase, direction, leaf, allocations, pg_live_handles, injected};
    return injected;
}
static void pg_observe_reset(void) {
    REQUIRE(fixture_live == 0 && pg_live_handles == 0);
    pg_release_count = pg_peak_alloc = pg_peak_bytes = pg_peak_handles = 0;
    pg_endpoint_invocations = pg_secondary_count = 0;
    pg_alloc_attempts = pg_fail_allocation_at = 0;
    pg_occurrence_remaining[0] = pg_occurrence_remaining[1] = 0;
    pg_phase_enabled = 0;
    pg_phase_event_count = pg_phase_copies_checked = 0;
    pg_phase_payload_check = NULL;
    memset(pg_phase_injections, 0, sizeof(pg_phase_injections));
}
#define SPX_PG_OBSERVE_ALLOCATION(count, bytes) pg_observe_allocation((count), (bytes))
#define SPX_PG_OBSERVE_HANDLE(delta) pg_observe_handle(delta)
#define SPX_PG_OBSERVE_ENDPOINT() (++pg_endpoint_invocations)
#define SPX_PG_OBSERVE_LEAF_RELEASE(direction, index) pg_observe_release((direction), (index))
#define SPX_PG_OBSERVE_CLEANUP_FAILURE(selected, status) pg_observe_cleanup((selected), (status))
#define SPX_PG_OCCURRENCE_INJECTION(label) pg_inject_occurrence(label)

#define SPX_PG_ALLOCATION_FAILURE() pg_fail_allocation()

#define SPX_PG_PHYSICAL_PHASE(phase, direction, leaf, allocations, bytes) \
    pg_observe_phase((phase), (direction), (leaf), (allocations), (bytes))

#define SPX_PG_OBSERVE_RESULT_PAYLOAD(leaf, bytes, length) \
    pg_observe_result_payload((leaf), (bytes), (length))
