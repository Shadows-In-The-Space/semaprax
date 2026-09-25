use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

std::thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
    static LAST: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(crate) struct ProbeGuard;

impl ProbeGuard {
    pub(crate) fn finish(self) -> usize {
        let count = COUNT.with(Cell::get);
        ACTIVE.with(|active| active.set(false));
        LAST.with(|last| last.set(Some(count)));
        std::mem::forget(self);
        count
    }
}

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(false));
    }
}

pub(crate) fn begin() -> ProbeGuard {
    ACTIVE.with(|active| assert!(!active.replace(true), "allocation probe nested"));
    COUNT.with(|count| count.set(0));
    LAST.with(|last| last.set(None));
    ProbeGuard
}

pub(crate) fn take_last() -> Option<usize> {
    LAST.with(|last| last.take())
}

pub(crate) struct CountingAllocator;

impl CountingAllocator {
    fn record(&self) {
        ACTIVE.with(|active| {
            if active.get() {
                COUNT.with(|count| count.set(count.get().saturating_add(1)));
            }
        });
    }
}

// SAFETY: Test-only forwarding allocator preserves `System`'s contract and
// merely increments thread-local counters before allocation/reallocation.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.record();
        // SAFETY: Forwarding the caller-provided layout unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.record();
        // SAFETY: Forwarding the caller-provided layout unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: Forwarding the allocation and its original layout.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        self.record();
        // SAFETY: Forwarding the allocation, original layout and new size.
        unsafe { System.realloc(pointer, layout, size) }
    }
}
