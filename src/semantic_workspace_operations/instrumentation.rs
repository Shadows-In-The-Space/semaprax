thread_local! {
    static CANDIDATE_PREFLIGHT_ENTRY_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static BASE_PREFLIGHT_ENTRY_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn reset_candidate_preflight_entry_count() {
    CANDIDATE_PREFLIGHT_ENTRY_COUNT.with(|count| count.set(0));
}

pub(super) fn candidate_preflight_entry_count() -> usize {
    CANDIDATE_PREFLIGHT_ENTRY_COUNT.with(std::cell::Cell::get)
}

pub(super) fn reset_base_operations_preflight_entry_count() {
    BASE_PREFLIGHT_ENTRY_COUNT.with(|count| count.set(0));
}

pub(super) fn base_operations_preflight_entry_count() -> usize {
    BASE_PREFLIGHT_ENTRY_COUNT.with(std::cell::Cell::get)
}

pub(crate) fn mark_base_operations_preflight_entry() {
    BASE_PREFLIGHT_ENTRY_COUNT.with(|count| count.set(count.get() + 1));
}

pub(super) fn mark_candidate_preflight_entry() {
    CANDIDATE_PREFLIGHT_ENTRY_COUNT.with(|count| count.set(count.get() + 1));
}
