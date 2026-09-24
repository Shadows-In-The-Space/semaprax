static size_t observed_issued, observed_drops, observed_peak, observed_live;
static size_t observed_settled, observed_calls, observed_payload_hooks;
static unsigned observed_mode, observed_allocation_countdown;
static int observed_occurrence(uint32_t label);
static int observed_allocation_failure(void);
static int observed_phase(uint32_t phase);
#define SPX_PG_OBSERVE_ENDPOINT() (++observed_calls)
#define SPX_PG_OCCURRENCE_INJECTION(label) observed_occurrence(label)
#define SPX_PG_ALLOCATION_FAILURE() observed_allocation_failure()
#define SPX_PG_PHYSICAL_PHASE(phase, direction, leaf, allocations, bytes) observed_phase(phase)
