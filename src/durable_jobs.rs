//! Durable background jobs on this repository's own atomic-generation
//! substrate — issue #192, closing the one gap
//! `docs/decisions/0005-durable-job-storage-medium.md` (ADR 0005) leaves
//! open after `std/jobs`, `src/job_fixture.rs`, `src/job_evidence.rs`, and
//! `src/job_runtime.rs` already shipped the pure lifecycle/lease/retry/
//! idempotency/scheduling/uncertainty decision procedures and an
//! in-process host runtime.
//!
//! # What this module is
//!
//! [`store::JobStore`] is the sealed persistence seam ADR 0005 calls the
//! "real deliverable": a trait narrow enough that a different physical
//! medium (a vendored SQLite file, say) could implement it later without
//! reaching into any caller. [`store::GenerationJobStore`] is this seam's
//! first and, for now, only implementation, and it deliberately does not
//! use a SQL driver:
//!
//! - **No unsafe FFI, no ambient network authority.** `rusqlite`'s
//!   `bundled` feature compiles vendored C behind `unsafe`, which eight
//!   crates in this workspace forbid; a PostgreSQL client needs a running
//!   server and network authority, which AGENTS.md forbids compiler and
//!   generated code from acquiring ambiently. See ADR 0005 for the full
//!   argument, including why SQLite's own default durability settings would
//!   not even buy the property this module needs.
//! - **Reuses the atomic-rename commit pattern this repository already
//!   trusts.** ADR 0002's managed workspace generations publish one
//!   complete immutable generation through `.semaprax-workspace/ACTIVE` by
//!   staging content, fsyncing it, and atomically renaming it into place.
//!   [`durable_fs`] applies that exact discipline — plus fsyncing the
//!   *containing directory*, the detail ADR 0005 names as "the single most
//!   commonly botched detail here" — to a directory of the caller's own
//!   choosing, independent of and without modifying `src/workspace.rs`
//!   itself: that module's own public API (`initialize`/`preview`/`apply`)
//!   is specific to semantic source patches and is not reused here.
//!
//! # What this module is not
//!
//! It does not reimplement `std.jobs`'s full ten-state lifecycle,
//! scheduling, or delivery-uncertainty model — see [`model::JobState`]'s
//! doc comment for the exact, smaller closed state set this seam owns, and
//! `docs/DURABLE-JOBS-V1.md` for where the rest already lives. It opens no
//! socket, spawns no thread, and reads no environment variable; every
//! filesystem path it touches is a path the caller explicitly passed to
//! [`store::GenerationJobStore::open`].
//!
//! # Local evidence
//!
//! ```sh
//! cargo test --locked -p semaprax --lib durable_jobs::
//! ```

mod codec;
mod durable_fs;
pub mod model;
pub mod retry;
pub mod store;

pub use model::{
    AttemptOutcome, EnqueueOutcome, EnqueueRequest, JobId, JobRecord, JobState, JobStoreError,
    JobTable, Lease, LeaseToken, RetryPolicy,
};
pub use store::{GenerationJobStore, JobStore};
