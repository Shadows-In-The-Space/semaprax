#include <assert.h>
#include "spx_pg_calling_consumer.c"
extern void auth_recipe(uint32_t mode);
extern void auth_receipt(uint32_t mode, int32_t primary, int32_t secondary);
static spx_pg_owned_bytes owned(const uint8_t *bytes, size_t length) {
    spx_pg_owned_bytes result = {(uint8_t *)malloc(length), length};
    assert(result.data); memcpy(result.data, bytes, length); return result;
}
int main(void) {
    static const uint8_t first[] = {1, 7, 13}, second[] = {2, 11, 17, 23};
    for (uint32_t mode = 0; mode < 3; ++mode) {
        auth_recipe(mode);
        spx_pg_calling_consumer *consumer = NULL;
        assert(spx_pg_consumer_open(spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_len,
            spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len, &consumer) == 0);
        spx_pg_input input = {0}; spx_pg_output output = {0};
        input.@INPUT0@ = owned(first, sizeof(first)); input.@INPUT1@ = owned(second, sizeof(second));
        spx_pg_consumer_settlement_v1 report;
        const spx_pg_consumer_status status = spx_pg_consumer_transform_with_settlement(consumer, &input, &output, &report);
        assert(!input.@INPUT0@.data && !input.@INPUT1@.data);
        assert(!input.@INPUT0@.len && !input.@INPUT1@.len);
        if (mode == 1) {
            assert(status == SPX_PG_CONSUMER_EXECUTION_FAILED);
            assert(!output.@OUTPUT0@.data && !output.@OUTPUT1@.data);
            assert(!output.@OUTPUT0@.len && !output.@OUTPUT1@.len);
        } else {
            assert(status == SPX_PG_CONSUMER_OK);
            assert(output.@OUTPUT0@.len == sizeof(first) && memcmp(output.@OUTPUT0@.data, first, sizeof(first)) == 0);
            assert(output.@OUTPUT1@.len == sizeof(second) && memcmp(output.@OUTPUT1@.data, second, sizeof(second)) == 0);
        }
        spx_pg_output_free(&output);
        assert(spx_pg_consumer_test_live_handles(consumer) == 0);
        int close_status = -1;
        assert(spx_pg_consumer_close_checked(&consumer, &close_status) == 0 && close_status == 0);
        auth_receipt(mode, report.native_status, report.release_status);
    }
}
