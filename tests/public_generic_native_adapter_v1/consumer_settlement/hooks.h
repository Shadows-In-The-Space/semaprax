/* Test-only observations, compiled separately from the generated clients. */
#ifndef SPX_CONSUMER_TEST_H
#define SPX_CONSUMER_TEST_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif
struct consumer_case {
    const char *id;
    int recipe, logical, phase, phase_leaf, release_leaf, export_mutation;
    int client_failure, input_mutation, expected_status, expected_native, expected_release, endpoint;
};
void consumer_test_require(int ok, const char *expression, unsigned line);
#define CHECK(expression) consumer_test_require(!!(expression), #expression, __LINE__)
void consumer_test_start(const struct consumer_case *test, int cpp, size_t fields);
void consumer_test_arm(void);
void consumer_test_finish(int status, int native_status, int release_status);
void *consumer_test_malloc(size_t size);
void consumer_test_free(void *pointer);
void *consumer_test_input(size_t size, size_t leaf);
void consumer_test_client_fail_after(size_t ordinal);
size_t consumer_test_length(int recipe, size_t leaf);
uint8_t consumer_test_byte(size_t leaf, size_t offset);
void consumer_test_write_u64(FILE *stream, uint64_t value);
void consumer_test_close_refusal(void);
void consumer_test_assert_empty_children(void);
void consumer_test_reset_observations(void);
#ifdef __cplusplus
}
#endif
#endif
