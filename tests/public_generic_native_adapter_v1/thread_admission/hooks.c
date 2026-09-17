/* Test-only observers. All thread creation and synchronization lives in this
 * harness, never in the provider. Include before the actual provider body. */
#include <pthread.h>
#include <stdatomic.h>
static void thread_probe_hook(unsigned point);
#define SPX_PG_OBSERVE_ALLOCATION(allocations, bytes) thread_probe_hook(1)
#define SPX_PG_OBSERVE_HANDLE(delta) thread_probe_hook(2)
#define SPX_PG_OBSERVE_ENDPOINT() thread_probe_hook(3)
#define SPX_PG_OBSERVE_LEAF_RELEASE(direction, index) thread_probe_hook(4)
#define SPX_PG_PHYSICAL_PHASE(phase, direction, leaf, allocations, bytes) \
    (thread_probe_hook(5), 0)
static void thread_probe_free(void *pointer) {
    thread_probe_hook(6);
    fixture_free(pointer);
}
#undef free
#define free thread_probe_free
