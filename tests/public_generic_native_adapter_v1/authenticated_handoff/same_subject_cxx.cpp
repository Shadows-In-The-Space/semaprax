#include "include/semaprax_public_generic_v1.hpp"
#include <cassert>
#include <cstdio>
using namespace semaprax::public_generic::v1;
extern "C" {
std::size_t auth_allocations(void);
std::size_t auth_live(void);
std::size_t auth_calls(void);
}
static Input sample() {
    Input value;
    value.@INPUT0@ = {1, 7, 13}; value.@INPUT1@ = {2, 11, 17, 23};
    return value;
}
static_assert(!std::is_copy_constructible_v<Provider> && !std::is_copy_assignable_v<Provider>);
static_assert(std::is_nothrow_move_constructible_v<Provider> && std::is_nothrow_move_assignable_v<Provider>);
static_assert(!std::is_copy_constructible_v<Output> && !std::is_copy_assignable_v<Output>);
static_assert(std::is_nothrow_move_constructible_v<Output> && std::is_nothrow_move_assignable_v<Output>);
int main() {
    constexpr int mode = @MODE@;
    constexpr bool guard = @GUARD@;
    std::vector<std::uint8_t> descriptor(spx_pg_trusted_descriptor_bytes,
        spx_pg_trusted_descriptor_bytes + spx_pg_trusted_descriptor_len);
    descriptor[0] ^= 1;
    auto refused = Provider::open(descriptor.data(), descriptor.size(), spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len);
    assert(!refused && refused.error().kind() == ErrorKind::DescriptorRejected);
    assert(auth_calls() == 0 && auth_allocations() == 0 && auth_live() == 0);
    {
        auto opened = Provider::open(); assert(opened);
        Provider original = std::move(opened).value();
        Provider provider = std::move(original);
        assert(!original.valid() && provider.valid());
        const auto allocation_baseline = auth_allocations();
        auto moved_from = original.transform(sample());
        assert(!moved_from && moved_from.error().kind() == ErrorKind::NullArgument);
        assert(auth_allocations() == allocation_baseline && auth_calls() == 0);
        const auto live_baseline = auth_live();
        for (std::size_t iteration = 0; iteration < 2; ++iteration) {
            const auto before = auth_allocations();
            auto result = provider.transform(sample());
            if (mode == 1) {
                assert(auth_calls() == iteration + 1);
                if (guard) {
                    assert(result);
                    Output first = std::move(result).value();
                    Output second = std::move(first);
                    assert(first.@OUTPUT0@().size == 0 && first.@OUTPUT1@().size == 0);
                    Output last; last = std::move(second);
                    assert(second.@OUTPUT0@().size == 0 && second.@OUTPUT1@().size == 0);
                    assert(to_owned(last.@OUTPUT0@()) == std::vector<std::uint8_t>({1, 7, 13}));
                    assert(to_owned(last.@OUTPUT1@()) == std::vector<std::uint8_t>({2, 11, 17, 23}));
                } else {
                    assert(!result && result.error().kind() == ErrorKind::ExecutionFailed);
                    assert(result.error().native_status() == 11 && result.error().release_status() == 0);
                }
            } else {
                assert(!result && result.error().kind() == ErrorKind::CarrierRejected);
                assert(result.error().native_status() == (mode == 2 ? 14 : 5));
                assert(result.error().release_status() == 0);
                assert(auth_calls() == 0 && auth_allocations() == before);
            }
            assert(auth_live() == live_baseline);
        }
        assert(provider.close_checked() && !provider.valid());
        assert(provider.close_checked());
        assert(original.close_checked());
        assert(auth_live() == 0);
    }
    assert(auth_live() == 0); // moved-from and explicitly closed destructors
    return std::fputs("cxx-authenticated-caller-settled", stdout) < 0 ? 1 : 0;
}
