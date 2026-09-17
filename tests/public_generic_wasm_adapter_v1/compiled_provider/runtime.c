/* PRIVATE reference harness, not a language runtime or a published allocator.
 * No WASI, imports, host allocator, host handle table or downloaded sysroot.
 * The SAME native provider/observer/probe bytes are compiled below this file.
 * All pointer-returning storage is bounded and lives inside the Wasm instance.
 * Host code may write only the separately exported transport scratch window.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PG_WASM_EXPORT(name) __attribute__((export_name(name)))
#define PG_HEAP_BYTES (40u * 1024u * 1024u)
#define PG_HEAP_BLOCKS 4096u
#define PG_LOG_BYTES (4u * 1024u * 1024u)
static _Alignas(16) uint8_t pg_heap[PG_HEAP_BYTES];
/* Metadata is separate from payload, so allocation/free never follows a
 * caller-controlled header. First-fit gaps support arbitrary release order
 * and reuse; each search is bounded by the fixed number of live blocks. */
struct pg_heap_block { size_t offset, size, requested, next; };
static size_t pg_heap_head = PG_HEAP_BLOCKS;
static struct pg_heap_block pg_blocks[PG_HEAP_BLOCKS];
static size_t pg_heap_live, pg_heap_live_bytes, pg_heap_peak, pg_blocks_high;
static char pg_log[PG_LOG_BYTES];
static size_t pg_log_size;

_Noreturn void abort(void) { __builtin_trap(); }
static void pg_runtime_require(int condition) { if (!condition) abort(); }
void *memcpy(void *restrict dst, const void *restrict src, size_t size) {
    uint8_t *d = dst; const uint8_t *s = src;
    for (size_t i = 0; i < size; ++i) d[i] = s[i];
    return dst;
}
void *memset(void *dst, int byte, size_t size) {
    uint8_t *d = dst;
    for (size_t i = 0; i < size; ++i) d[i] = (uint8_t)byte;
    return dst;
}
int memcmp(const void *left, const void *right, size_t size) {
    const uint8_t *a = left, *b = right;
    for (size_t i = 0; i < size; ++i) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}
int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return (unsigned char)*a - (unsigned char)*b;
}
size_t strlen(const char *text) { size_t n = 0; while (text[n]) ++n; return n; }
void *malloc(size_t size) {
    if (size == 0 || size > PG_HEAP_BYTES || pg_heap_live == PG_HEAP_BLOCKS) return NULL;
    size_t aligned = (size + 15u) & ~(size_t)15u;
    size_t candidate = 0, previous = PG_HEAP_BLOCKS, current = pg_heap_head;
    size_t slot = 0;
    while (slot < pg_blocks_high && pg_blocks[slot].size != 0) ++slot;
    pg_runtime_require(slot < PG_HEAP_BLOCKS);
    /* Address-sorted live records: two linear bounded walks, never a scan
     * proportional to heap bytes or a quadratic search for a single gap. */
    for (size_t steps = 0; current != PG_HEAP_BLOCKS; ++steps) {
        pg_runtime_require(steps < PG_HEAP_BLOCKS && current < pg_blocks_high);
        struct pg_heap_block b = pg_blocks[current];
        pg_runtime_require(b.size != 0 && candidate <= b.offset);
        if (aligned <= b.offset - candidate) break;
        candidate = b.offset + b.size;
        previous = current;
        current = b.next;
    }
    if (candidate > PG_HEAP_BYTES - aligned) return NULL;
    pg_blocks[slot] = (struct pg_heap_block){candidate, aligned, size, current};
    if (previous == PG_HEAP_BLOCKS) pg_heap_head = slot;
    else pg_blocks[previous].next = slot;
    if (slot == pg_blocks_high) ++pg_blocks_high;
    ++pg_heap_live;
    pg_heap_live_bytes += size;
    if (pg_heap_live > pg_heap_peak) pg_heap_peak = pg_heap_live;
    return pg_heap + candidate;
}
void free(void *pointer) {
    if (pointer == NULL) return;
    size_t previous = PG_HEAP_BLOCKS, current = pg_heap_head;
    for (size_t steps = 0; current != PG_HEAP_BLOCKS; ++steps) {
        pg_runtime_require(steps < PG_HEAP_BLOCKS && current < pg_blocks_high);
        struct pg_heap_block b = pg_blocks[current];
        if (pointer == pg_heap + b.offset) {
            /* Scrub padding as well, unlink, and invalidate before reuse. */
            memset(pointer, 0, b.size);
            if (previous == PG_HEAP_BLOCKS) pg_heap_head = b.next;
            else pg_blocks[previous].next = b.next;
            pg_blocks[current] = (struct pg_heap_block){0};
            --pg_heap_live;
            pg_heap_live_bytes -= b.requested;
            while (pg_blocks_high && pg_blocks[pg_blocks_high - 1].size == 0) --pg_blocks_high;
            return;
        }
        previous = current;
        current = b.next;
    }
    abort(); /* double/interior/foreign free is a failed private fixture */
}

/* Executes before the provider corpus, without minting provider identities.
 * Every assertion is independent of the provider observer. No public allocator
 * export is introduced, and none of these synthetic allocations is evidence
 * of compiler-created generic values. */
static void pg_runtime_self_test(void) {
    pg_runtime_require(pg_heap_live == 0 && pg_heap_live_bytes == 0);
    pg_runtime_require(malloc(0) == NULL && malloc(PG_HEAP_BYTES + 1u) == NULL);
    pg_runtime_require(malloc(SIZE_MAX) == NULL);
    uint8_t *whole = malloc(PG_HEAP_BYTES);
    pg_runtime_require(whole != NULL && (uintptr_t)whole % 16 == 0);
    whole[0] = 93; whole[PG_HEAP_BYTES - 1] = 197;
    pg_runtime_require(malloc(1) == NULL);
    free(whole);
    pg_runtime_require(pg_heap[0] == 0 && pg_heap[PG_HEAP_BYTES - 1] == 0);
    void *items[PG_HEAP_BLOCKS];
    for (size_t i = 0; i < PG_HEAP_BLOCKS; ++i) {
        items[i] = malloc(1);
        pg_runtime_require(items[i] != NULL && (uintptr_t)items[i] % 16 == 0);
        *(uint8_t *)items[i] = 42;
    }
    pg_runtime_require(pg_heap_live == PG_HEAP_BLOCKS && malloc(1) == NULL);
    /* Free alternating slots: first-fit must reuse holes without overlap. */
    for (size_t i = 0; i < PG_HEAP_BLOCKS; i += 2) free(items[i]);
    for (size_t i = 0; i < PG_HEAP_BLOCKS; i += 2) {
        void *replacement = malloc(1);
        pg_runtime_require(replacement == items[i] && *(uint8_t *)replacement == 0);
        items[i] = replacement;
    }
    for (size_t i = PG_HEAP_BLOCKS; i > 0; --i) free(items[i - 1]);
    free(NULL);
    pg_runtime_require(pg_heap_live == 0 && pg_heap_live_bytes == 0 && pg_blocks_high == 0);
    pg_runtime_require(pg_heap_head == PG_HEAP_BLOCKS);
}

struct pg_writer { char *buffer; size_t capacity, used; int log; };
static void pg_put(struct pg_writer *w, char c) {
    if (w->log) {
        pg_runtime_require(pg_log_size < PG_LOG_BYTES);
        pg_log[pg_log_size++] = c;
    } else if (w->used + 1 < w->capacity) w->buffer[w->used] = c;
    ++w->used;
}
static void pg_number(struct pg_writer *w, uint64_t n, unsigned radix, unsigned width) {
    char tmp[32]; unsigned count = 0;
    do { tmp[count++] = "0123456789abcdef"[n % radix]; n /= radix; } while (n != 0);
    while (count < width) tmp[count++] = '0';
    while (count) pg_put(w, tmp[--count]);
}
static int pg_format(struct pg_writer *w, const char *format, va_list args) {
    while (*format) {
        if (*format != '%') { pg_put(w, *format++); continue; }
        ++format;
        if (*format == '%') { pg_put(w, *format++); continue; }
        unsigned width = 0;
        if (format[0] == '0' && format[1] == '2') { width = 2; format += 2; }
        int sized = *format == 'z'; if (sized) ++format;
        char spec = *format++;
        if (spec == 's' && !sized && !width) {
            const char *s = va_arg(args, const char *);
            while (*s) pg_put(w, *s++);
        } else if (spec == 'd' && !sized) {
            int n = va_arg(args, int);
            if (n < 0) pg_put(w, '-');
            pg_number(w, n < 0 ? (uint64_t)(-(int64_t)n) : (uint64_t)n, 10, width);
        } else if (spec == 'u' || (spec == 'x' && !sized)) {
            uint64_t n = sized ? (uint64_t)va_arg(args, size_t) : (uint64_t)va_arg(args, unsigned);
            pg_number(w, n, spec == 'x' ? 16 : 10, width);
        } else abort(); /* no silent format approximation */
    }
    if (!w->log && w->capacity) w->buffer[w->used < w->capacity ? w->used : w->capacity - 1] = 0;
    pg_runtime_require(w->used <= INT32_MAX);
    return (int)w->used;
}
int printf(const char *format, ...) {
    va_list args; va_start(args, format);
    struct pg_writer w = {NULL, 0, 0, 1}; int n = pg_format(&w, format, args);
    va_end(args); return n;
}
int fprintf(FILE *stream, const char *format, ...) {
    (void)stream; va_list args; va_start(args, format);
    struct pg_writer w = {NULL, 0, 0, 1}; int n = pg_format(&w, format, args);
    va_end(args); return n;
}
int snprintf(char *buffer, size_t capacity, const char *format, ...) {
    va_list args; va_start(args, format);
    struct pg_writer w = {buffer, capacity, 0, 0}; int n = pg_format(&w, format, args);
    va_end(args); return n;
}
int puts(const char *text) { return printf("%s\n", text); }
PG_WASM_EXPORT("pg_log_pointer") uint32_t pg_log_pointer(void) { return (uint32_t)(uintptr_t)pg_log; }
PG_WASM_EXPORT("pg_log_length") uint32_t pg_log_length(void) { return (uint32_t)pg_log_size; }
PG_WASM_EXPORT("pg_heap_live") uint32_t pg_heap_live_count(void) { return (uint32_t)pg_heap_live; }
PG_WASM_EXPORT("pg_heap_bytes") uint32_t pg_heap_byte_count(void) { return (uint32_t)pg_heap_live_bytes; }
