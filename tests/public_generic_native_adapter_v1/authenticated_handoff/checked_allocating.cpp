#include "include/semaprax_public_generic_v1.hpp"
#include <cassert>
#include <cstdio>
using namespace semaprax::public_generic::v1;
extern "C" {
void auth_arm(unsigned);
int auth_receipt(std::size_t, std::size_t, std::size_t, std::size_t);
std::size_t auth_live(void), auth_calls(void);
}
static Input sample() {
    Input value; value.@INPUT0@ = {1, 7, 13}; value.@INPUT1@ = {2, 11, 17, 23}; return value;
}
int main() {
    auto opened = Provider::open(); assert(opened);
    Provider original = std::move(opened).value();
    Provider provider = std::move(original);
    assert(!original.valid() && provider.valid());
    const auto baseline = auth_live();
    for (std::size_t iteration = 0; iteration < 2; ++iteration) {
        auth_arm(@MODE@);
        auto result = provider.transform(sample());
        if (auth_calls() != (@ISSUED@ == 0 ? 0 : iteration + 1)) return 78;
        if (@RAW@ == 0) {
            if (!result) return 43;
            Output first = std::move(result).value();
            Output output = std::move(first);
            assert(first.@OUTPUT0@().size == 0 && first.@OUTPUT1@().size == 0);
            if (to_owned(output.@OUTPUT0@()) != std::vector<std::uint8_t>({1, 7, 13}) ||
                to_owned(output.@OUTPUT1@()) != std::vector<std::uint8_t>({9, 0, 0})) return 42;
        } else {
            if (result || result.error().kind() != ErrorKind::ExecutionFailed ||
                result.error().native_status() != @RAW@) return 43;
            assert(result.error().release_status() == 0);
        }
        assert(auth_receipt(@ISSUED@, @PEAK@, @LIVE@, @HOOKS@));
        assert(auth_live() == baseline);
    }
    assert(provider.close_checked() && !provider.valid());
    assert(provider.close_checked() && original.close_checked());
    assert(auth_live() == 0);
    return std::fputs("cxx-authenticated-caller-settled", stdout) < 0 ? 1 : 0;
}
