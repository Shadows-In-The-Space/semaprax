/* Caller-side allocator: no provider allocation is freed through this table.
 * Independently observes every C client owner and C++-to-C staging owner. */
#include "hooks.h"
struct client_allocation { void *pointer; size_t size, id, leaf; int input; };
static struct client_allocation client_table[2048];
static size_t client_live, client_bytes, client_peak, client_peak_bytes, client_next_id;
static size_t client_attempts, client_failure_at;
static size_t client_release_ids[4096], client_release_count;
static size_t input_release_indices[256], input_release_count;
static int observing_input, allocation_role, allocation_recipe, decode_forbidden;
static size_t allocation_fields, allocation_leaf, last_result_leaf, last_staged_leaf;
void consumer_test_require(int ok, const char *expression, unsigned line) {
    if (!ok) { fprintf(stderr, "consumer settlement line %u: %s\n", line, expression); abort(); }
}
static void *client_allocate(size_t size, int input, size_t leaf) {
    CHECK(size > 0 && size <= 16779272u);
    if (!input && allocation_role == 2) CHECK(!decode_forbidden);
    if (!input && ++client_attempts == client_failure_at) return NULL;
    if (!input && allocation_role != 0) {
        while (allocation_leaf < allocation_fields && consumer_test_length(allocation_recipe, allocation_leaf) == 0) ++allocation_leaf;
        if (allocation_leaf < allocation_fields) {
            CHECK(size == consumer_test_length(allocation_recipe, allocation_leaf));
            input = allocation_role;
            leaf = allocation_leaf++;
        } else {
            allocation_role = 0;
        }
    }
    void *pointer = malloc(size);
    CHECK(pointer != NULL);
    size_t slot = 0;
    while (slot < 2048 && client_table[slot].pointer != NULL) ++slot;
    CHECK(slot < 2048);
    client_table[slot] = (struct client_allocation){pointer, size, ++client_next_id, leaf, input};
    ++client_live;
    client_bytes += size;
    if (client_live > client_peak) client_peak = client_live;
    if (client_bytes > client_peak_bytes) client_peak_bytes = client_bytes;
    return pointer;
}
void *consumer_test_malloc(size_t size) { return client_allocate(size, 0, 0); }
void *consumer_test_input(size_t size, size_t leaf) { return client_allocate(size, 1, leaf); }
void consumer_test_free(void *pointer) {
    if (pointer == NULL) return;
    size_t slot = 0;
    while (slot < 2048 && client_table[slot].pointer != pointer) ++slot;
    CHECK(slot < 2048 && client_live > 0);
    CHECK(client_release_count < 4096);
    const struct client_allocation owned = client_table[slot];
    client_release_ids[client_release_count++] = owned.id;
    if (owned.input == 1 && observing_input) {
        CHECK(input_release_count < 256);
        input_release_indices[input_release_count++] = owned.leaf;
    }
    if (owned.input == 2) { CHECK(owned.leaf < last_result_leaf); last_result_leaf = owned.leaf; }
    if (owned.input == 3) { CHECK(owned.leaf < last_staged_leaf); last_staged_leaf = owned.leaf; }
    --client_live;
    client_bytes -= owned.size;
    client_table[slot] = (struct client_allocation){0};
    free(pointer);
}
void consumer_test_client_fail_after(size_t ordinal) { client_failure_at = client_attempts + ordinal; }
void consumer_test_client_begin(int cpp, int recipe, size_t fields) {
    allocation_role = cpp ? 3 : 0;
    allocation_recipe = recipe;
    allocation_fields = fields;
    allocation_leaf = 0;
    last_result_leaf = last_staged_leaf = SIZE_MAX;
    input_release_count = 0;
    observing_input = 1;
}
void consumer_test_client_decode_begin(int recipe, size_t fields, int hostile) {
    allocation_role = 2;
    decode_forbidden = hostile;
    allocation_recipe = recipe;
    allocation_fields = fields;
    allocation_leaf = 0;
}
void consumer_test_client_check(void) {
    for (size_t i = 1; i < input_release_count; ++i) CHECK(input_release_indices[i - 1] > input_release_indices[i]);
    observing_input = 0;
}
void consumer_test_client_print(void) {
    CHECK(client_live == 0 && client_bytes == 0);
    printf(" client_peak=%zu client_peak_bytes=%zu client_live=%zu client_live_bytes=%zu client_release=",
        client_peak, client_peak_bytes, client_live, client_bytes);
    for (size_t i = 0; i < client_release_count; ++i) printf("%s%zu", i ? "," : "", client_release_ids[i]);
}
size_t consumer_test_length(int recipe, size_t leaf) {
    if (recipe == 1) return 0;
    if (recipe == 2 && leaf == 0) return 0;
    if (recipe == 3) return 65536;
    if (recipe == 4 && leaf == 0) return 65537;
    return 5 + leaf % 3;
}
uint8_t consumer_test_byte(size_t leaf, size_t offset) {
    return offset % 3 == 0 ? 0 : (uint8_t)((leaf * 31 + offset * 17) & 255u);
}
void consumer_test_write_u64(FILE *stream, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) { CHECK(fputc((int)(value & 255), stream) != EOF); value >>= 8; }
}
