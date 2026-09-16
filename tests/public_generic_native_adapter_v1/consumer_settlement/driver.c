#include "hooks.h"
#include "spx_pg_calling_consumer.h"
#include "cases.inc"
static const struct consumer_case *select_case(const char *id) {
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) if (strcmp(cases[i].id, id) == 0) return &cases[i];
    return NULL;
}
int main(int argc, char **argv) {
    CHECK(argc == 3);
    const struct consumer_case *test = select_case(argv[1]);
    CHECK(test != NULL);
    consumer_test_start(test, 0, @COUNT@);
    spx_pg_calling_consumer *consumer = NULL;
    uint8_t descriptor[131072], binding[262144];
    CHECK(spx_pg_trusted_descriptor_len <= sizeof(descriptor) && spx_pg_trusted_binding_len <= sizeof(binding));
    memcpy(descriptor, spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_len);
    memcpy(binding, spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len);
    if (test->input_mutation == 10) descriptor[spx_pg_trusted_descriptor_len - 1] ^= 1;
    if (test->input_mutation == 11) binding[spx_pg_trusted_binding_len - 1] ^= 1;
    if (test->input_mutation == 12) consumer_test_client_fail_after(1);
    int status = spx_pg_consumer_open(descriptor, spx_pg_trusted_descriptor_len, binding, spx_pg_trusted_binding_len, &consumer);
    if (status != SPX_PG_CONSUMER_OK) {
        CHECK(consumer == NULL);
        consumer_test_finish(status, 0, 0);
        return 0;
    }
    if (test->input_mutation == 22) {
        spx_pg_input input;
        memset(&input, 0, sizeof(input));
        spx_pg_owned_bytes *leaves[] = {@INPUT_REFS@};
        leaves[0]->data = (uint8_t *)consumer_test_input(65537, 0);
        leaves[0]->len = 65537;
        spx_pg_output output;
        int native = -1;
        spx_pg_consumer_test_inject_failure(6);
        CHECK(spx_pg_consumer_transform(consumer, &input, &output, &native) == SPX_PG_CONSUMER_CAPACITY_EXCEEDED);
        CHECK(native == 0 && leaves[0]->data == NULL && leaves[0]->len == 0);
        spx_pg_output_free(&output);
    }
    spx_pg_consumer_settlement_v1 report = {SPX_PG_CONSUMER_OK, 0, 0};
    const int repeat = test->input_mutation == 21 ? 8 : 1;
    for (int iteration = 0; iteration < repeat; ++iteration) {
        spx_pg_input input;
        spx_pg_output output;
        memset(&input, 0, sizeof(input));
        spx_pg_owned_bytes *in[] = {@INPUT_REFS@};
        spx_pg_owned_bytes *out[] = {@OUTPUT_REFS@};
        for (size_t i = 0; i < @COUNT@; ++i) {
            in[i]->len = consumer_test_length(test->recipe, i);
            if (in[i]->len != 0) {
                in[i]->data = (uint8_t *)consumer_test_input(in[i]->len, i);
                for (size_t j = 0; j < in[i]->len; ++j) in[i]->data[j] = consumer_test_byte(i, j);
            }
        }
        if (test->input_mutation == 1) { consumer_test_free(in[0]->data); in[0]->data = NULL; }
        if (test->input_mutation == 2) in[0]->len = 0;
#if @COUNT@ >= 2
        if (test->input_mutation == 3) {
            CHECK(@COUNT@ >= 2);
            consumer_test_free(in[1]->data);
            in[1]->data = in[0]->data; in[1]->len = in[0]->len;
        }
#endif
        if (test->input_mutation == 4) in[0]->len = SIZE_MAX;
        if (test->input_mutation == 7) {
            for (size_t i = @COUNT@; i-- > 0;) { consumer_test_free(in[i]->data); in[i]->data = NULL; in[i]->len = 0; }
        }
        consumer_test_arm();
        if (test->logical >= 0) spx_pg_consumer_test_inject_failure((uint32_t)test->logical);
        status = spx_pg_consumer_transform_with_settlement(test->input_mutation == 5 ? NULL : consumer,
            test->input_mutation == 7 ? NULL : &input, test->input_mutation == 6 ? NULL : &output, &report);
        CHECK((int)report.primary_status == status);
        for (size_t i = 0; i < @COUNT@; ++i) CHECK(in[i]->data == NULL && in[i]->len == 0);
        consumer_test_assert_empty_children();
        if (status == SPX_PG_CONSUMER_OK) {
            FILE *file = fopen(argv[2], "wb");
            CHECK(file != NULL);
            consumer_test_write_u64(file, @COUNT@);
            for (size_t i = 0; i < @COUNT@; ++i) {
                CHECK(out[i]->len == consumer_test_length(test->recipe, i));
                for (size_t j = 0; j < out[i]->len; ++j) CHECK(out[i]->data[j] == consumer_test_byte(i, out[i]->len - 1 - j));
                consumer_test_write_u64(file, out[i]->len);
                if (out[i]->len != 0) CHECK(fwrite(out[i]->data, 1, out[i]->len, file) == out[i]->len);
            }
            CHECK(fclose(file) == 0);
        } else if (test->input_mutation != 6) {
            for (size_t i = 0; i < @COUNT@; ++i) CHECK(out[i]->data == NULL && out[i]->len == 0);
        }
        if (test->input_mutation != 6) { spx_pg_output_free(&output); spx_pg_output_free(&output); }
    }
    if (test->input_mutation == 20) {
        consumer_test_close_refusal();
        int native = 0;
        CHECK(spx_pg_consumer_close_checked(&consumer, &native) == SPX_PG_CONSUMER_RELEASE_FAILED);
        CHECK(native == 7 && consumer != NULL);
    }
    CHECK(spx_pg_consumer_close_checked(&consumer, NULL) == SPX_PG_CONSUMER_OK);
    CHECK(consumer == NULL);
    CHECK(spx_pg_consumer_close_checked(&consumer, NULL) == SPX_PG_CONSUMER_OK);
    consumer_test_finish(status, report.native_status, report.release_status);
    return 0;
}
