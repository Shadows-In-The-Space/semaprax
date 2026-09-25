//! CLI adapter; shared held cache ownership lives in the compiler library.
use super::{Diagnostic, FetchOptions};

pub(super) fn run(options: &FetchOptions) -> Result<String, Vec<Diagnostic>> {
    semaprax::package_cache_host::fetch_locked(
        options.lock.as_ref().expect("lock route"),
        &options.cache,
        &options.subjects,
    )
}
