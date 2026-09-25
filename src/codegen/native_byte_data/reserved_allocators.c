/* Private checked-body profile. The bridge owns one reservation; semantic
   Bytes own individual leases, not malloc pointers. No current-arena global. */
struct spx_bytes_arena;
union spx_bytes_lease {
    max_align_t alignment;
    struct {
        struct spx_bytes_arena *arena;
        uint8_t *payload;
        uint64_t length;
        size_t ordinal;
        bool live;
    } value;
};
struct spx_bytes_arena {
    struct spx_context *context;
    uint8_t *storage;
    size_t capacity;
    size_t used;
    size_t slots;
    size_t issued;
    size_t live;
};

static __attribute__((unused)) spx_bytes_v1 spx_bytes_reserve_in(
    struct spx_context *context, uint64_t length
) {
    if (context == NULL || context->target_state == NULL ||
        length > SPX_OWNED_BYTES_MAX_BYTES) {
        spx_runtime_invariant_failure("reserved byte allocation has no checked authority");
    }
    struct spx_bytes_arena *arena = (struct spx_bytes_arena *)context->target_state;
    if (arena->context != context) {
        spx_runtime_invariant_failure("reserved byte allocation context mismatch");
    }
    if (length == 0) return (spx_bytes_v1){ .ptr = NULL, .len = 0 };
    const size_t alignment = _Alignof(union spx_bytes_lease);
    const size_t padding = (alignment - arena->used % alignment) % alignment;
    const size_t header = sizeof(union spx_bytes_lease);
    /* Admission binds cumulative payload AND site count, including callees.
       Exhaustion here is a compiler/bridge defect, never an allocator failure
       or a new unproved cleanup-plan failure edge. Check before any write. */
    if (arena->issued >= arena->slots || arena->used > arena->capacity ||
        padding > arena->capacity - arena->used ||
        header > arena->capacity - arena->used - padding ||
        length > arena->capacity - arena->used - padding - header) {
        spx_runtime_invariant_failure("checked byte reservation exhausted before write");
    }
    union spx_bytes_lease *lease = (union spx_bytes_lease *)(
        arena->storage + arena->used + padding);
    uint8_t *payload = (uint8_t *)(lease + 1);
    lease->value.arena = arena;
    lease->value.payload = payload;
    lease->value.length = length;
    lease->value.ordinal = arena->issued++;
    lease->value.live = true;
    arena->used += padding + header + (size_t)length;
    arena->live += 1;
    return (spx_bytes_v1){ .ptr = payload, .len = length };
}

static __attribute__((unused)) spx_bytes_v1 spx_bytes_copy_in(
    struct spx_context *context, spx_slice_u8_v1 value
) {
    spx_slice_u8_require_owned_view_valid(value);
    spx_bytes_v1 result = spx_bytes_reserve_in(context, value.len);
    if (value.len != 0) memcpy(result.ptr, value.ptr, (size_t)value.len);
    return result;
}

static __attribute__((unused)) spx_bytes_v1 spx_bytes_zeroed_in(
    struct spx_context *context, uint64_t count
) {
    spx_bytes_v1 result = spx_bytes_reserve_in(context, count);
    if (count != 0) memset(result.ptr, 0, (size_t)count);
    return result;
}
