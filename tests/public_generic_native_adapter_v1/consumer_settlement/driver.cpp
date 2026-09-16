#include <cstdio>
#include "hooks.h"
#define SPX_PG_CXX_ALLOC(size) consumer_test_malloc(size)
#include "include/semaprax_public_generic_v1.hpp"
#include "cases.inc"
using namespace semaprax::public_generic::v1;
static int kind_code(ErrorKind kind) {
    switch (kind) {
    case ErrorKind::DescriptorRejected: return 1;
    case ErrorKind::ProviderMismatch: return 2;
    case ErrorKind::CarrierRejected: return 3;
    case ErrorKind::CapacityExceeded: return 4;
    case ErrorKind::ExecutionFailed: return 5;
    case ErrorKind::ResultRejected: return 6;
    case ErrorKind::AllocationFailure: return 7;
    case ErrorKind::NullArgument: return 8;
    case ErrorKind::ReleaseFailed: return 9;
    }
    std::abort();
}
int main(int argc, char **argv) {
    CHECK(argc == 3);
    const struct consumer_case *test = nullptr;
    for (const auto &entry : cases) if (std::strcmp(entry.id, argv[1]) == 0) test = &entry;
    CHECK(test != nullptr);
    consumer_test_start(test, 1, @COUNT@);
    std::vector<std::uint8_t> descriptor(spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_bytes + spx_pg_trusted_descriptor_len);
    std::vector<std::uint8_t> binding(spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_bytes + spx_pg_trusted_binding_len);
    if (test->input_mutation == 10) descriptor.back() ^= 1;
    if (test->input_mutation == 11) binding.back() ^= 1;
    if (test->input_mutation == 12) consumer_test_client_fail_after(1);
    int status = 0, native = 0, release = 0;
    {
        auto opened = Provider::open(descriptor.data(), descriptor.size(), binding.data(), binding.size());
        if (!opened) { consumer_test_finish(kind_code(opened.error().kind()), opened.error().native_status(), opened.error().release_status()); return 0; }
        Provider provider = std::move(opened).value();
        Provider moved(std::move(provider));
        CHECK(!provider.valid());
        provider = std::move(moved);
        CHECK(provider.valid() && !moved.valid());
        Provider *alias = &provider;
        provider = std::move(*alias); /* intentional self-move, not an alias owner */
        CHECK(provider.valid());
        if (test->input_mutation == 22) {
            Input input;
            std::vector<std::uint8_t> *leaves[] = {@CPP_INPUT_REFS@};
            leaves[0]->resize(65537);
            spx_pg_consumer_test_inject_failure(6);
            auto rejected = provider.transform(std::move(input));
            CHECK(!rejected && rejected.error().kind() == ErrorKind::CapacityExceeded);
        }
        if (test->input_mutation == 23) {
            auto second = Provider::open();
            CHECK(second.has_value());
            Provider other = std::move(second).value();
            consumer_test_close_refusal();
            provider = std::move(other);
            CHECK(provider.valid() && other.valid());
            CHECK(other.close_checked().has_value());
        }
        const int repeat = test->input_mutation == 21 ? 8 : 1;
        for (int iteration = 0; iteration < repeat; ++iteration) {
            Input input;
            std::vector<std::uint8_t> *leaves[] = {@CPP_INPUT_REFS@};
            for (std::size_t i = 0; i < @COUNT@; ++i) {
                leaves[i]->resize(consumer_test_length(test->recipe, i));
                for (std::size_t j = 0; j < leaves[i]->size(); ++j) (*leaves[i])[j] = consumer_test_byte(i, j);
            }
            consumer_test_arm();
            if (test->logical >= 0) spx_pg_consumer_test_inject_failure(static_cast<std::uint32_t>(test->logical));
            auto result = provider.transform(std::move(input));
            consumer_test_assert_empty_children();
            if (result) {
                Output first = std::move(result).value();
                Output output(std::move(first));
                first = std::move(output);
                Output *self = &first;
                first = std::move(*self);
                const BytesView values[] = {@CPP_VIEWS@};
                FILE *file = std::fopen(argv[2], "wb");
                CHECK(file != nullptr);
                consumer_test_write_u64(file, @COUNT@);
                for (std::size_t i = 0; i < @COUNT@; ++i) {
                    CHECK(values[i].size == consumer_test_length(test->recipe, i));
                    for (std::size_t j = 0; j < values[i].size; ++j) CHECK(values[i].data[j] == consumer_test_byte(i, values[i].size - 1 - j));
                    consumer_test_write_u64(file, values[i].size);
                    if (values[i].size) CHECK(std::fwrite(values[i].data, 1, values[i].size, file) == values[i].size);
                }
                CHECK(std::fclose(file) == 0);
            } else {
                status = kind_code(result.error().kind()); native = result.error().native_status(); release = result.error().release_status();
            }
        }
        if (test->input_mutation == 20) {
            consumer_test_close_refusal();
            auto closed = provider.close_checked();
            CHECK(!closed && closed.error().kind() == ErrorKind::ReleaseFailed);
            CHECK(closed.error().native_status() == 7 && provider.valid());
        }
        CHECK(provider.close_checked().has_value());
        CHECK(!provider.valid());
        CHECK(provider.close_checked().has_value());
        CHECK(!provider.transform(Input{}));
    }
    consumer_test_finish(status, native, release);
    return 0;
}
