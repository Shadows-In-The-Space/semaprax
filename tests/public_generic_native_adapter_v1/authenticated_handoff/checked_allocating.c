#include <assert.h>
#include "spx_pg_calling_consumer.c"
extern void auth_arm(unsigned);
extern int auth_receipt(size_t, size_t, size_t, size_t);
extern size_t auth_live(void), auth_calls(void);
static spx_pg_owned_bytes owned(const uint8_t *bytes, size_t length) {
    spx_pg_owned_bytes value = {(uint8_t *)malloc(length), length};
    assert(value.data); memcpy(value.data, bytes, length); return value;
}
int main(void) {
    static const uint8_t first[] = {1, 7, 13}, second[] = {2, 11, 17, 23};
    static const uint8_t changed[] = {9, 0, 0};
    spx_pg_calling_consumer *consumer = NULL;
    assert(spx_pg_consumer_open(spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_len,
        spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len, &consumer) == SPX_PG_CONSUMER_OK);
    const size_t baseline = auth_live();
    for (size_t iteration = 0; iteration < 2; ++iteration) {
        spx_pg_input input = {0}; spx_pg_output output = {0};
        input.@INPUT0@ = owned(first, sizeof(first));
        input.@INPUT1@ = owned(second, sizeof(second));
        auth_arm(@MODE@);
        spx_pg_consumer_settlement_v1 report;
        const spx_pg_consumer_status status =
            spx_pg_consumer_transform_with_settlement(consumer, &input, &output, &report);
        if (report.native_status != @RAW@ ||
            status != (@RAW@ ? SPX_PG_CONSUMER_EXECUTION_FAILED : SPX_PG_CONSUMER_OK)) return 43;
        assert(report.release_status == 0);
        assert(!input.@INPUT0@.data && !input.@INPUT0@.len && !input.@INPUT1@.data && !input.@INPUT1@.len);
        if (auth_calls() != (@ISSUED@ == 0 ? 0 : iteration + 1)) return 78;
        if (@RAW@ == 0) {
            if (output.@OUTPUT0@.len != sizeof(first) || memcmp(output.@OUTPUT0@.data, first, sizeof(first)) ||
                output.@OUTPUT1@.len != sizeof(changed) || memcmp(output.@OUTPUT1@.data, changed, sizeof(changed))) return 42;
        } else {
            assert(!output.@OUTPUT0@.data && !output.@OUTPUT0@.len &&
                !output.@OUTPUT1@.data && !output.@OUTPUT1@.len);
        }
        assert(auth_receipt(@ISSUED@, @PEAK@, @LIVE@, @HOOKS@));
        assert(auth_live() == baseline && spx_pg_consumer_test_live_handles(consumer) == 0);
        spx_pg_output_free(&output);
    }
    int closed = -1;
    assert(spx_pg_consumer_close_checked(&consumer, &closed) == 0 && closed == 0);
    assert(!consumer && auth_live() == 0);
    assert(spx_pg_consumer_close_checked(&consumer, &closed) == 0);
    return 0;
}
