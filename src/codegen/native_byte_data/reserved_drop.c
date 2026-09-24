static __attribute__((unused)) void spx_bytes_drop(spx_bytes_v1 *value) {
    if (value == NULL) spx_runtime_invariant_failure("owned byte drop has a null carrier");
    spx_bytes_require_valid(*value);
    if (value->ptr != NULL) {
        /* Only checked Bytes produced by this profile enter the body. The
           authenticated carrier never supplies a pointer or lease header. */
        union spx_bytes_lease *lease = ((union spx_bytes_lease *)value->ptr) - 1;
        struct spx_bytes_arena *arena = lease->value.arena;
        if (arena == NULL || arena->context == NULL ||
            arena->context->target_state != arena || !lease->value.live ||
            lease->value.payload != value->ptr || lease->value.length != value->len ||
            lease->value.ordinal >= arena->issued || arena->live == 0) {
            spx_runtime_invariant_failure("reserved byte drop has no live exact lease");
        }
        lease->value.live = false;
        arena->live -= 1;
    }
    value->ptr = NULL;
    value->len = UINT64_C(0);
}
