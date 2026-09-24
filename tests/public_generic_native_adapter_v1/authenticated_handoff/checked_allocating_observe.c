#undef malloc
#undef free
static int observed_occurrence(uint32_t label) {
    if (label == SPX_PG_TRACE_EXECUTION_STARTED && observed_mode != 0)
        observed_allocation_countdown = observed_mode == 1 ? 3 : 4;
    return 0;
}
static int observed_allocation_failure(void) {
    if (observed_allocation_countdown == 0) return 0;
    return --observed_allocation_countdown == 0;
}
static int observed_phase(uint32_t phase) {
    if (phase == SPX_PG_PHASE_RESULT_ALLOCATION_STARTED) ++observed_payload_hooks;
    return 0;
}
void auth_arm(unsigned mode) {
    observed_mode = mode;
    observed_issued = observed_drops = observed_peak = observed_live = 0;
    observed_settled = observed_payload_hooks = 0;
}
int auth_receipt(size_t issued, size_t peak, size_t live, size_t hooks) {
    return observed_issued == issued && observed_drops == issued - live &&
        observed_peak == peak && observed_live == live &&
        observed_payload_hooks == hooks && observed_settled == (issued != 0);
}
size_t auth_live(void) { return fixture_live; }
size_t auth_calls(void) { return observed_calls; }
