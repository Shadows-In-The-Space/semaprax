use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::agent_interaction_schema::CompiledInteractionSchema;
use crate::job_runtime::{
    DriveOutcome, JobCheckpointStore, JobRuntime, JobState, JobSubmission, StoredJobCheckpoint,
};

static NEXT_PROJECT: AtomicU64 = AtomicU64::new(0);

const SOURCE: &str = r#"
module job.handler.app;

@id("job.payload")
record Payload {
    @id("job.payload.code")
    code: i64,
}

@id("job.handler.export.payload")
record ExportPayload {
    @id("job.handler.export.payload.bytes")
    bytes: Bytes,
}

@id("job.handler.run")
fn run(payload: Payload) -> i64
{
    payload.code
}

@id("job.handler.alternate")
fn alternate(payload: Payload) -> i64
{
    payload.code
}

@id("job.handler.export")
fn export(input: borrow Slice<u8>) -> ExportPayload
{
    ExportPayload { bytes: bytes_copy(input) }
}

@id("job.handler.main")
fn main() -> i64 { 0 }
"#;

struct TempProject {
    root: PathBuf,
    revision: Arc<ProjectRevision>,
}

impl TempProject {
    fn new() -> Self {
        let unique = NEXT_PROJECT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "semaprax-source-job-handler-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        let root = root.canonicalize().unwrap();
        fs::write(
            root.join("semaprax.toml"),
            "schema = \"semaprax.project.v11\"\nname = \"source-job-handler\"\nversion = \"1.0.0\"\nprofile = \"nested-owned-record-api.v1\"\nentry = \"job.handler.app\"\nsources = [\"src/app.spx\", \"src/tests.spx\"]\nweb_exports = [\"job.handler.export\"]\ntests = [\"job.handler.tests\"]\n",
        )
        .unwrap();
        let parsed = crate::parse(SOURCE, "src/app.spx").unwrap();
        fs::write(root.join("src/app.spx"), crate::format::canonical(&parsed)).unwrap();
        let tests = crate::parse(
            "module job.handler.tests;\n\n@id(\"job.handler.tests.main\")\nfn main() -> i64 { 0 }\n",
            "src/tests.spx",
        )
        .unwrap();
        fs::write(root.join("src/tests.spx"), crate::format::canonical(&tests)).unwrap();
        let revision = crate::project::load_snapshot(&root.join("semaprax.toml"))
            .unwrap()
            .retain_revision();
        Self { root, revision }
    }

    fn binding(&self) -> SourceJobHandlerBinding {
        self.binding_for("job.handler.run")
    }

    fn binding_for(&self, handler_id: &str) -> SourceJobHandlerBinding {
        let root = self.revision.program_root().unwrap();
        SourceJobHandlerBinding::derive(
            Arc::clone(&self.revision),
            root.program_root_digest(),
            "src/app.spx",
            handler_id,
            "job.payload",
            10_000,
        )
        .unwrap()
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Default)]
struct MemoryCheckpointStore {
    current: Option<StoredJobCheckpoint>,
}

impl JobCheckpointStore for MemoryCheckpointStore {
    fn load(&mut self) -> Result<Option<StoredJobCheckpoint>, crate::job_runtime::CheckpointStoreError> {
        Ok(self.current.clone())
    }

    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        document: &[u8],
    ) -> Result<u64, crate::job_runtime::CheckpointStoreError> {
        if self.current.as_ref().map(|current| current.generation) != expected_generation {
            return Err(crate::job_runtime::CheckpointStoreError);
        }
        let generation = expected_generation.map_or(1, |current| current + 1);
        self.current = Some(StoredJobCheckpoint {
            generation,
            bytes: document.to_vec(),
        });
        Ok(generation)
    }
}

fn submission(schema: &CompiledInteractionSchema) -> JobSubmission {
    JobSubmission {
        idempotency_key: b"source-handler-job".to_vec(),
        payload_descriptor: b"job.payload.v1".to_vec(),
        payload: format!(
            "{{\"schema\":\"semaprax.agent-interaction-value.v1\",\"root_type_id\":\"job.payload\",\"schema_digest\":{},\"value\":{{\"fields\":{{\"job.payload.code\":\"0\"}}}}}}\n",
            crate::diagnostic::quote_json(schema.schema().digest()),
        )
        .into_bytes(),
        schedule: None,
        max_attempts: 1,
        is_idempotent_handler: true,
        base_backoff_ticks: 1,
        max_backoff_ticks: 1,
    }
}

#[test]
fn retained_source_handler_drives_the_existing_job_runtime_to_success() {
    let project = TempProject::new();
    let binding = project.binding();
    let expected = binding.deployment_identity().to_owned();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut runtime = JobRuntime::enqueue(
        &mut checkpoints,
        binding.payload_schema(),
        7,
        binding.bind_submission(submission(binding.payload_schema())),
    )
    .unwrap();

    assert_eq!(
        drive_checked_source_job(
            &mut runtime,
            &mut checkpoints,
            &binding,
            &expected,
            9,
            20,
            5,
        ),
        Ok(DriveOutcome::Completed(JobState::Succeeded))
    );
    assert_eq!(runtime.state(), JobState::Succeeded);
}

#[test]
fn stale_program_root_refuses_before_a_source_handler_is_constructed() {
    let project = TempProject::new();
    assert!(matches!(
        SourceJobHandlerBinding::derive(
            Arc::clone(&project.revision),
            "sha256:stale-program-root",
            "src/app.spx",
            "job.handler.run",
            "job.payload",
            10_000,
        ),
        Err(SourceJobHandlerRefusal::StaleProgramRoot)
    ));
}

#[test]
fn stale_handler_deployment_identity_refuses_before_claiming_the_job() {
    let project = TempProject::new();
    let binding = project.binding();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut runtime = JobRuntime::enqueue(
        &mut checkpoints,
        binding.payload_schema(),
        7,
        binding.bind_submission(submission(binding.payload_schema())),
    )
    .unwrap();

    assert_eq!(
        drive_checked_source_job(
            &mut runtime,
            &mut checkpoints,
            &binding,
            "sha256:wrong-source-handler-deployment",
            9,
            20,
            5,
        ),
        Err(SourceJobDriveError::Binding(
            SourceJobHandlerRefusal::BindingDigestMismatch
        ))
    );
    assert_eq!(runtime.state(), JobState::Pending);
}

#[test]
fn recovered_job_refuses_a_same_schema_different_source_handler_before_claiming() {
    let project = TempProject::new();
    let original = project.binding();
    let mut checkpoints = MemoryCheckpointStore::default();
    let runtime = JobRuntime::enqueue(
        &mut checkpoints,
        original.payload_schema(),
        7,
        original.bind_submission(submission(original.payload_schema())),
    )
    .unwrap();
    assert_eq!(runtime.state(), JobState::Pending);

    let mut recovered = JobRuntime::recover(&mut checkpoints, original.payload_schema(), 7).unwrap();
    let changed = project.binding_for("job.handler.alternate");
    let changed_identity = changed.deployment_identity().to_owned();

    assert_eq!(
        drive_checked_source_job(
            &mut recovered,
            &mut checkpoints,
            &changed,
            &changed_identity,
            9,
            20,
            5,
        ),
        Err(SourceJobDriveError::Binding(
            SourceJobHandlerRefusal::RuntimeHandlerDescriptorMismatch
        ))
    );
    assert_eq!(recovered.state(), JobState::Pending);
}
