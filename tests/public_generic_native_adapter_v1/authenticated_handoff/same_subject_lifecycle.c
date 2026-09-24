#include <assert.h>
#include <stdio.h>
#include <string.h>
size_t auth_live(void);
size_t auth_calls(void);
int main(void) {
    assert(printf("[") == 1);
    for (size_t cycle = 0; cycle < 2; ++cycle) {
        spx_pg_provider_v1 *provider = NULL;
        assert(spx_pg_provider_open_v1(descriptor, sizeof(descriptor), binding, sizeof(binding), &provider) == 0);
        spx_pg_provider_v1 *stale_provider = provider;
        spx_pg_result_v1 *result = NULL;
        assert(spx_pg_call_v1(provider, NULL, &result) == 8 && result == NULL);
        assert(auth_calls() == cycle);
        uint64_t generation = 0;
        assert(spx_pg_authenticated_generation_v1(provider, &generation) == 0 && generation != 0);
        spx_pg_value_v1 *input = NULL;
        assert(spx_pg_authenticated_input_prepare_v1(provider, generation, 0, cleanup, sizeof(cleanup),
            canonical, sizeof(canonical), &input) == 0);
        assert(spx_pg_provider_close_v1(&provider) == 7 && provider != NULL);
        /* Native null provider is 13, unlike the Core-Wasm invalid-handle 8. */
        assert(spx_pg_call_v1(NULL, input, &result) == 13 && result == NULL);
        assert(auth_calls() == cycle);
        assert(spx_pg_call_v1(provider, input, &result) == EXPECT_CALL_STATUS);
        assert(auth_calls() == cycle + 1);
        spx_pg_result_v1 *duplicate = NULL;
        assert(spx_pg_call_v1(provider, input, &duplicate) == 8 && duplicate == NULL);
        assert(spx_pg_call_v1(provider, NULL, &duplicate) == 8 && duplicate == NULL);
        uint8_t out[31], retry[31]; size_t required = 0;
        if (EXPECT_CALL_STATUS == 0) {
            assert(result != NULL);
            assert(spx_pg_provider_close_v1(&provider) == 7 && provider != NULL);
            assert(spx_pg_result_export_v1(result, NULL, 0, &required) == 12 && required == sizeof(out));
            memset(out, 0xa5, sizeof(out));
            assert(spx_pg_result_export_v1(result, out, sizeof(out) - 1, &required) == 12 && required == sizeof(out));
            for (size_t i = 0; i < sizeof(out); ++i) assert(out[i] == 0xa5);
            assert(spx_pg_result_export_v1(result, out, sizeof(out), &required) == 0 && required == sizeof(out));
            assert(spx_pg_result_export_v1(result, retry, sizeof(retry), &required) == 0 && memcmp(out, retry, sizeof(out)) == 0);
            spx_pg_result_v1 *stale = result;
            assert(spx_pg_result_release_v1(&result) == 0 && result == NULL);
            size_t stale_required = 99;
            assert(spx_pg_result_export_v1(stale, retry, sizeof(retry), &stale_required) == 8 && stale_required == 0);
            assert(spx_pg_result_release_v1(&stale) == 8 && stale == NULL);
        } else assert(result == NULL);
        assert(spx_pg_value_release_v1(&input) == 8 && input == NULL);
        assert(auth_calls() == cycle + 1 && spx_pg_test_live_handles_v1(provider) == 0);
        assert(spx_pg_provider_close_v1(&provider) == 0 && provider == NULL);
        assert(spx_pg_provider_close_v1(&stale_provider) == 8 && stale_provider == NULL);
        assert(auth_live() == 0);
        if (cycle != 0) assert(printf(",") == 1);
        assert(printf("[") == 1);
        for (size_t i = 0; i < required; ++i) {
            if (i != 0) assert(printf(",") == 1);
            assert(printf("%u", (unsigned)out[i]) > 0);
        }
        assert(printf("]") == 1);
    }
    assert(printf("]") == 1);
    return 0;
}
