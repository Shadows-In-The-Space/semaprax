//! The job-service reference application carried end to end.
//!
//! Issue #192's audit found the durable-jobs machinery genuinely complete
//! (concurrent enqueue/idempotency races, lease/expiry/heartbeat/crash
//! recovery, retry/backoff/dead-letter ceilings, payload/handler revision
//! migration, database transaction integration) but found no reference
//! service that actually enqueues and executes a durable typed job reachable
//! from checked `.spx` source -- the issue's own first acceptance criterion.
//! `examples/job-service-project` is that reference service, and this module
//! is its regression gate, in the shape `tests/useful_data/task_service_project.rs`
//! already established for its sibling reference application.
//!
//! Two things this module proves that a pure `.spx` fixture walk cannot:
//!
//! - `source_handler_binding_executes_the_real_compiled_handler_to_completion`
//!   and `source_handler_binding_retries_within_ceiling_then_dead_letters`
//!   bind `job_service.app.handle_report_job` -- a real function in this
//!   project's own checked, retained source -- to the host `JobRuntime`
//!   through `SourceJobHandlerBinding` (`src/job_runtime/source_handler.rs`)
//!   and drive a real enqueued job to completion by calling it. This is the
//!   project's genuine "execute a durable typed job" path: `JobRuntime` owns
//!   every checkpoint, lease, retry, backoff, and dead-letter transition:
//!   the `.spx` handler owns only the effect-free classification of one
//!   already-admitted payload.
//! - `duplicate_idempotency_key_bound_to_this_handlers_identity_is_a_harmless_duplicate`
//!   exercises the same real handler's own deployment identity as the
//!   descriptor a durable job store dedupes on, tying the real bound source
//!   (not an arbitrary byte string) into the enqueue idempotency guarantee.
//!
//! `entry_and_conformance_return_zero_on_interpreter_native_and_wasm` carries
//! this project's own `.spx` fixture walk (the retry/backoff/dead-letter
//! *decision* logic, modeled purely in `.spx` on top of the bundled
//! `std.jobs` package, exactly as `task_service_project.rs`'s sibling test
//! does for `std.auth`/`std.jobs`) across the interpreter, native C11, and
//! Core Wasm lanes.
//!
//! Canonical formatting for every module under `examples/job-service-project`
//! is already covered by
//! `tests/examples.rs::every_example_below_the_top_level_is_canonical`, so
//! this module does not repeat that check.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use semaprax::agent_interaction_schema::CompiledInteractionSchema;
use semaprax::database_fixture::DatabaseFixture;
use semaprax::diagnostic::quote_json;
use semaprax::job_fixture::{EnqueueOutcome, JobState, JobStore};
use semaprax::job_runtime::{
    drive_checked_source_job, CheckpointStoreError, DriveOutcome, JobCheckpointStore, JobRuntime,
    JobSubmission, SourceJobHandlerBinding, StoredJobCheckpoint,
};
use semaprax::project::ProjectRevision;
use semaprax::{codegen, project};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/job-service-project")
}

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "semaprax-job-service-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path.canonicalize().unwrap()
}

fn compile_c(source: &str, output: &Path, optimization: &str) {
    let c_path = output.with_extension("c");
    std::fs::write(&c_path, source).unwrap();
    let result = Command::new("clang")
        .args(["-std=c11", optimization, "-Wall", "-Wextra", "-Werror"])
        .arg(&c_path)
        .arg("-o")
        .arg(output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "clang {optimization} failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn run_returns_zero(path: &Path) {
    let output = Command::new(path).output().unwrap();
    assert!(output.status.success(), "{} failed", path.display());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "0",
        "{} did not report success",
        path.display()
    );
}

/// `check`, `test`, and `run` all pass on the interpreter, and the
/// manifest's bundled dependency resolves to the compiler's own `std.jobs`
/// source rather than anything vendored by hand.
///
/// Negative control (performed manually against the compiled interpreter
/// binary, then reverted -- not committed): flipping
/// `job_service.tests.duplicate_enqueue_is_idempotent`'s expected `== 1usize`
/// to `== 0usize` makes `job_service.tests.main` return `1` (`semaprax test`
/// reports "project tests failed"), so `execute_test()`'s outcome assertion
/// below fails too. Restoring the source turns the gate green again.
#[test]
fn check_test_and_run_pass_on_the_interpreter() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        assert!(
            snapshot
                .workspace_manifest()
                .contains("dependencies/std.jobs/0.1.0"),
            "the workspace does not carry the bundled std.jobs source"
        );
        let options = project::ProjectExecutionOptions::default();
        assert_eq!(
            snapshot.execute_entry(&options)?.outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "the entry's own handler smoke check did not report success"
        );
        assert_eq!(
            snapshot.execute_test(&options)?.outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "the project's own named test cases (scenario, duplicate-enqueue, \
             conflicting-key, retry-then-dead-letter) did not all pass"
        );
        Ok(())
    })
    .unwrap();
}

/// The manifest's single declared `[exports].web` root is a real public
/// function reachable in the retained revision's semantic graph, the same
/// shape `tests/useful_data/task_service_project.rs` asserts for its sibling
/// reference project.
#[test]
fn the_declared_web_export_is_a_reachable_public_function() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let public = snapshot.retain_revision();
        let ids = public
            .public_api_program()
            .functions
            .iter()
            .map(|function| function.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            snapshot.manifest().web_exports().len(),
            1,
            "the reference application must still declare its one web export root"
        );
        for selected in snapshot.manifest().web_exports() {
            assert!(
                ids.iter().any(|id| id.as_str() == selected.as_str()),
                "missing selected export root {selected}"
            );
            assert!(snapshot.semantic_graph().contains(selected));
        }
        Ok(())
    })
    .unwrap();
}

/// Entry and conformance both return `0` on all three execution lanes:
/// interpreter, native C11 at `-O0` and `-O2`, and Core Wasm under Node. The
/// Wasm harness below is the same generic byte-slice ABI shim
/// `tests/useful_data/task_service_project.rs` uses -- this project's own
/// idempotency-key comparisons (`std.jobs.idempotency.enqueue_outcome`,
/// through `std.bytes.equals`) and the `export_report_payload` web export
/// need the same `spx_bytes_*` import set that project's byte-slice checks
/// do.
///
/// Negative control (performed manually, not committed): swapping
/// `job_service.core.run_scenario`'s `first_retry_state == 5usize` bound to
/// `== 4usize` makes the reference application's own retry-ceiling
/// acceptance check fail identically on all three lanes -- `execute_test`,
/// the compiled C binaries, and the Node Wasm run all stop returning `0`.
/// Restoring the source turns every lane green again, which is what proves
/// this gate actually drives native and Wasm codegen rather than only the
/// interpreter path.
#[test]
fn entry_and_conformance_return_zero_on_interpreter_native_and_wasm() {
    let scratch = scratch("lanes");
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let options = project::ProjectExecutionOptions::default();
        assert_eq!(
            snapshot.execute_entry(&options)?.outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "the entry failed on the interpreter"
        );
        assert_eq!(
            snapshot.execute_test(&options)?.outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "conformance failed on the interpreter"
        );
        for (role, program) in [
            ("entry", snapshot.entry_program()),
            ("tests", snapshot.test_program()),
        ] {
            let c = codegen::emit_hir_c(program).map_err(|error| vec![error])?;
            for optimization in ["-O0", "-O2"] {
                let binary = scratch.join(format!("{role}{}", optimization.to_lowercase()));
                compile_c(&c, &binary, optimization);
                run_returns_zero(&binary);
            }
        }
        let wasm = snapshot.test_wasm_module()?;
        let wasm_path = scratch.join("tests.wasm");
        std::fs::write(&wasm_path, wasm).unwrap();
        let script = scratch.join("tests.mjs");
        std::fs::write(
            &script,
            r#"import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
const bytes = await readFile("./tests.wasm");
const checked = (operation) => (a, b) => { const value = operation(a, b); if (value < -(1n<<63n) || value > (1n<<63n)-1n) throw new RangeError(); return value; };
const entries = new Map(); let next = 1; let linked;
const decode = carrier => { const word = BigInt.asUintN(64, carrier), length = Number(word & 0xffffffffn), root = Number((word >> 32n) & 0xffffffffn); return { word, length, root, tagged: (root & 0x80000000) !== 0, token: root & 0x7fffffff }; };
const read = decoded => { if ((decoded.root & 0xc0000000) === 0x40000000) { const pointer = (decoded.root & 0xffff) * 8, key = (decoded.root >>> 16) & 0x1fff, view = new DataView((linked.instance.exports.__spx_byte_memory ?? linked.instance.exports.memory).buffer); if (pointer + 32 > view.byteLength || view.getUint32(pointer, true) !== key || view.getUint32(pointer + 4, true) !== pointer || Number(view.getBigUint64(pointer + 24, true)) !== decoded.length) throw new Error("corrupt range descriptor"); const root = view.getBigInt64(pointer + 8, true), offset = Number(view.getBigUint64(pointer + 16, true)), all = read(decode(root)); if (offset > all.length || decoded.length > all.length - offset) throw new Error("byte range"); return all.slice(offset, offset + decoded.length); } if (decoded.tagged) { const value = entries.get(decoded.token); if (!(value instanceof Uint8Array) || value.length !== decoded.length) throw new Error("stale byte token"); return value; } const memory = new Uint8Array((linked.instance.exports.__spx_byte_memory ?? linked.instance.exports.memory).buffer); if (decoded.root > memory.length - decoded.length) throw new Error("byte range"); return memory.slice(decoded.root, decoded.root + decoded.length); };
const allocate = bytes => { const token = next++, owned = new Uint8Array(bytes); entries.set(token, owned); return BigInt.asIntN(64, ((0x80000000n | BigInt(token)) << 32n) | BigInt(owned.length)); };
const imports = {env:{spx_add:checked((a,b)=>a+b),spx_sub:checked((a,b)=>a-b),spx_mul:checked((a,b)=>a*b),spx_div:(a,b)=>a/b,spx_rem:(a,b)=>a%b,spx_neg:(a)=>-a,spx_contract_fail:()=>{throw new Error();},
spx_bytes_copy:c=>allocate(read(decode(c))),spx_bytes_get:(c,i)=>{ const b = read(decode(c)), u = BigInt.asUintN(64, i); return u >= BigInt(b.length) ? -1 : b[Number(u)]; },spx_bytes_drop:c=>{ const d = decode(c); read(d); entries.delete(d.token); },spx_bytes_as_slice:c=>{ const d = decode(c); read(d); return BigInt.asIntN(64, d.word); }}};
linked = await WebAssembly.instantiate(bytes, imports);
assert.equal(linked.instance.exports.semaprax_main(), 0n);
"#,
        )
        .unwrap();
        let node = Command::new("node")
            .arg(script.file_name().unwrap())
            .current_dir(&scratch)
            .output()
            .unwrap();
        assert!(
            node.status.success(),
            "Node conformance closure failed: {}",
            String::from_utf8_lossy(&node.stderr)
        );
        Ok(())
    })
    .unwrap();
    let _ = std::fs::remove_dir_all(scratch);
}

/// A single-job, in-memory checkpoint store, the same shape
/// `src/job_runtime/source_handler_tests.rs`'s own `MemoryCheckpointStore`
/// uses -- reimplemented here because that helper is private to its crate
/// module and this is an external integration test.
#[derive(Default)]
struct MemoryCheckpointStore {
    current: Option<StoredJobCheckpoint>,
}

impl JobCheckpointStore for MemoryCheckpointStore {
    fn load(&mut self) -> Result<Option<StoredJobCheckpoint>, CheckpointStoreError> {
        Ok(self.current.clone())
    }

    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        document: &[u8],
    ) -> Result<u64, CheckpointStoreError> {
        if self.current.as_ref().map(|current| current.generation) != expected_generation {
            return Err(CheckpointStoreError);
        }
        let generation = expected_generation.map_or(1, |current| current + 1);
        self.current = Some(StoredJobCheckpoint {
            generation,
            bytes: document.to_vec(),
        });
        Ok(generation)
    }
}

/// Bind `job_service.app.handle_report_job` -- a real function retained in
/// this project's own checked source, not a Rust stand-in -- through
/// `SourceJobHandlerBinding`.
fn handler_binding(revision: &Arc<ProjectRevision>) -> SourceJobHandlerBinding {
    let root = revision.program_root().unwrap();
    SourceJobHandlerBinding::derive(
        Arc::clone(revision),
        root.program_root_digest(),
        "src/app.spx",
        "job_service.app.handle_report_job",
        "job_service.app.payload",
        10_000,
    )
    .unwrap()
}

/// A `ReportJob { outcome_code }` payload encoded the same
/// agent-interaction-value wire shape `source_handler_tests.rs` uses.
fn submission(schema: &CompiledInteractionSchema, key: &[u8], outcome_code: i64) -> JobSubmission {
    JobSubmission {
        idempotency_key: key.to_vec(),
        payload_descriptor: b"placeholder".to_vec(),
        payload: format!(
            "{{\"schema\":\"semaprax.agent-interaction-value.v1\",\"root_type_id\":\"job_service.app.payload\",\"schema_digest\":{},\"value\":{{\"fields\":{{\"job_service.app.payload.outcome_code\":\"{outcome_code}\"}}}}}}\n",
            quote_json(schema.schema().digest()),
        )
        .into_bytes(),
        schedule: None,
        max_attempts: 3,
        is_idempotent_handler: true,
        base_backoff_ticks: 10,
        max_backoff_ticks: 10,
    }
}

/// The project's genuine "enqueue and execute a durable typed job" path: a
/// real `JobRuntime` claims a real lease, hands the admitted payload to
/// `job_service.app.handle_report_job` -- compiled from this project's own
/// checked `.spx` source, not a Rust stand-in -- through the retained-call
/// interpreter seam, and the runtime durably records `Succeeded`.
///
/// Negative control (performed manually, not committed): editing
/// `job_service.app.handle_report_job` to always return `2` (permanent
/// failure) instead of passing `payload.outcome_code` through makes this
/// test's `Succeeded` assertion fail with `PermanentFailure` instead, even
/// though the enqueued payload still carries outcome code `0`. Restoring the
/// source turns this test green again, which is what proves the runtime is
/// really calling the compiled `.spx` function rather than the payload
/// alone deciding the outcome.
#[test]
fn source_handler_binding_executes_the_real_compiled_handler_to_completion() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let revision = snapshot.retain_revision();
        let binding = handler_binding(&revision);
        let expected = binding.deployment_identity().to_owned();
        let mut checkpoints = MemoryCheckpointStore::default();
        let mut runtime = JobRuntime::enqueue(
            &mut checkpoints,
            binding.payload_schema(),
            1,
            binding.bind_submission(submission(binding.payload_schema(), b"report-succeeds", 0)),
        )
        .unwrap();

        assert_eq!(
            drive_checked_source_job(
                &mut runtime,
                &mut checkpoints,
                &binding,
                &expected,
                1,
                100,
                50,
            ),
            Ok(DriveOutcome::Completed(JobState::Succeeded))
        );
        assert_eq!(runtime.state(), JobState::Succeeded);
        Ok(())
    })
    .unwrap();
}

/// A handler-reported retryable failure is retried once within a
/// three-attempt ceiling (the durable state after the first drive is
/// `Scheduled`, not yet terminal) and, once the ceiling is reached, the same
/// real compiled handler's outcome dead-letters the job (a terminal state)
/// instead of being retried forever. The handler function driven here is
/// the exact same `job_service.app.handle_report_job` the success test
/// above binds -- only the enqueued payload's `outcome_code` differs.
///
/// Negative control (performed manually, not committed): calling
/// `drive_checked_source_job` a third time at `now_tick=1000` (past the
/// second attempt's backoff) after this test's own second drive would need
/// the job to still accept work; asserting `NoWork` immediately after the
/// first retryable drive at the same tick it was claimed (before the
/// backoff-scheduled tick elapses) and expecting `Completed` instead makes
/// this test fail closed rather than silently proving nothing -- this
/// module exercises exactly that ordering below (`NoWork` before the due
/// tick, `Completed` at or after it).
#[test]
fn source_handler_binding_retries_within_ceiling_then_dead_letters() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let revision = snapshot.retain_revision();
        let binding = handler_binding(&revision);
        let expected = binding.deployment_identity().to_owned();
        let mut checkpoints = MemoryCheckpointStore::default();
        let mut runtime = JobRuntime::enqueue(
            &mut checkpoints,
            binding.payload_schema(),
            1,
            binding.bind_submission(submission(binding.payload_schema(), b"report-retries", 1)),
        )
        .unwrap();

        // Attempt 1 of 3: retryable failure, not yet at the ceiling. The
        // durable state moves to `Scheduled` (retry pending), never a
        // terminal state.
        assert_eq!(
            drive_checked_source_job(
                &mut runtime,
                &mut checkpoints,
                &binding,
                &expected,
                1,
                100,
                50,
            ),
            Ok(DriveOutcome::Completed(JobState::Scheduled))
        );
        assert_eq!(runtime.state(), JobState::Scheduled);

        // Before the backoff-scheduled tick elapses, the runtime refuses to
        // claim it again rather than retrying early.
        assert_eq!(
            drive_checked_source_job(
                &mut runtime,
                &mut checkpoints,
                &binding,
                &expected,
                1,
                105,
                50,
            ),
            Ok(DriveOutcome::NoWork)
        );
        assert_eq!(runtime.state(), JobState::Scheduled);

        // Attempt 2 of 3, once due: still retryable, still under the
        // ceiling.
        assert_eq!(
            drive_checked_source_job(
                &mut runtime,
                &mut checkpoints,
                &binding,
                &expected,
                1,
                110,
                50,
            ),
            Ok(DriveOutcome::Completed(JobState::Scheduled))
        );

        // Attempt 3 of 3, once due: the ceiling is reached, so the same
        // retryable outcome dead-letters the job instead of scheduling a
        // fourth attempt.
        assert_eq!(
            drive_checked_source_job(
                &mut runtime,
                &mut checkpoints,
                &binding,
                &expected,
                1,
                120,
                50,
            ),
            Ok(DriveOutcome::Completed(JobState::DeadLettered))
        );
        assert_eq!(runtime.state(), JobState::DeadLettered);
        Ok(())
    })
    .unwrap();
}

/// The same real handler's own deployment identity -- not an arbitrary byte
/// string -- is the payload descriptor a durable job store dedupes
/// idempotency keys on. A retried enqueue naming the same key and the same
/// bound handler identity is a harmless duplicate, and the same key reused
/// against a different payload descriptor is a closed refusal, never a
/// silent merge.
///
/// Negative control (performed manually, not committed): comparing
/// `existing.payload_descriptor == payload_descriptor` with a truncated
/// slice (say, the first byte only) instead of the exact descriptor would
/// make the `Conflict` assertion below fail, because two different
/// `sha256:`-prefixed descriptors that happen to share a first byte would
/// be misclassified as the same job. This test pins the exact-match
/// requirement.
#[test]
fn duplicate_idempotency_key_bound_to_this_handlers_identity_is_a_harmless_duplicate() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let revision = snapshot.retain_revision();
        let binding = handler_binding(&revision);
        let descriptor = binding.deployment_identity().as_bytes().to_vec();
        let other_descriptor = b"sha256:not-this-deployment".to_vec();

        let mut ledger = DatabaseFixture::new();
        JobStore::install_ledger_schema(&mut ledger);
        let mut store = JobStore::new(1);
        let key = b"report-dedup".to_vec();

        let first = store
            .enqueue(&mut ledger, key.clone(), descriptor.clone(), None, 3, true)
            .unwrap();
        let EnqueueOutcome::Created(job_id) = first else {
            panic!("expected the first enqueue to create a job, got {first:?}");
        };

        let duplicate = store
            .enqueue(&mut ledger, key.clone(), descriptor.clone(), None, 3, true)
            .unwrap();
        assert_eq!(
            duplicate,
            EnqueueOutcome::Duplicate(job_id),
            "a retried enqueue with the same key and the same bound handler \
             identity must be a harmless duplicate, never a second job"
        );
        assert_eq!(ledger.row_count("jobs").unwrap(), 1);

        let conflict = store
            .enqueue(&mut ledger, key, other_descriptor, None, 3, true)
            .unwrap();
        assert_eq!(
            conflict,
            EnqueueOutcome::Conflict,
            "the same key reused against a different payload descriptor must \
             be a closed refusal, never a silent merge"
        );
        assert_eq!(ledger.row_count("jobs").unwrap(), 1);
        Ok(())
    })
    .unwrap();
}
