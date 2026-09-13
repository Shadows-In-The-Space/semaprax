//! Machine-readable workflow observations for quiet-host benchmark campaigns.
//!
//! This target is intentionally opt-in. Build it with
//! `--features unstable-workflow-profiling`; timings are observations and are
//! never part of a canonical compiler artifact.

#[path = "support/project_equivalence.rs"]
mod project_equivalence;
#[path = "support/project_fixture.rs"]
mod project_fixture;

use semaprax::project::{
    self, PreparedProjectExecutionOptions, PreparedProjectInterpreterOptions,
    ProjectExecutionCancellation, ProjectFrontendCache, ProjectFrontendSource, ProjectManifest,
};
use semaprax::workflow_profile::{capture, Observation, Stage};
use serde_json::{json, Value};
use std::env;
use std::path::{Path, PathBuf};
use std::time::Instant;

const DEFAULT_SAMPLES: usize = 3;
const LOOP_ITERATIONS: u64 = 10_000;

fn observations(observation: &Observation) -> Value {
    let stages = Stage::ALL
        .iter()
        .enumerate()
        .map(|(index, stage)| {
            let value = observation.stages[index];
            json!({
                "stage": stage.name(),
                "calls": value.calls,
                "inclusive_ns": value.inclusive_ns,
                "self_ns": value.self_ns,
            })
        })
        .collect::<Vec<_>>();
    assert!(observation.complete, "workflow observation was incomplete");
    json!({
        "total_ns": observation.total_ns,
        "complete": observation.complete,
        "stages": stages,
    })
}

fn source_rows(sources: &[(String, String)]) -> Vec<ProjectFrontendSource> {
    sources
        .iter()
        .map(|(path, source)| ProjectFrontendSource::new(path, source).unwrap())
        .collect()
}

fn work(build: &project::ProjectFrontendBuild) -> Value {
    serde_json::from_str(build.to_json()).expect("frontend work report must be JSON")
}

fn revision_fields(revision: &std::sync::Arc<project::ProjectRevision>) -> Value {
    let image = project::ProjectSemanticImage::derive(
        std::sync::Arc::clone(revision),
        revision.project_revision(),
    )
    .expect("revision must derive an image");
    json!({
        // The Project revision is the authenticated digest of the canonical
        // manifest and exact source closure; retain it as the fixture id.
        "fixture_digest": revision.project_revision(),
        "project_revision": revision.project_revision(),
        "workspace_revision": revision.workspace_revision(),
        "graph_digest": revision.semantic_graph_digest(),
        "image_digest": image.image_digest(),
    })
}

fn timed_cache(
    manifest: &ProjectManifest,
    sources: &[ProjectFrontendSource],
) -> (Value, Value, Value, u128) {
    let plain_start = Instant::now();
    let plain = ProjectFrontendCache::new()
        .build(manifest, sources)
        .unwrap();
    let plain_ns = plain_start.elapsed().as_nanos();
    let (build, observation) = capture(|| {
        ProjectFrontendCache::new()
            .build(manifest, sources)
            .unwrap()
    })
    .expect("cache capture must not be nested");
    assert_eq!(plain.to_json(), build.to_json());
    project_equivalence::assert_revision_equivalent(build.revision(), plain.into_revision());
    (
        work(&build),
        revision_fields(build.revision()),
        observations(&observation),
        plain_ns,
    )
}

fn timed_warm_cache(
    manifest: &ProjectManifest,
    prime: &[ProjectFrontendSource],
    sources: &[ProjectFrontendSource],
) -> (Value, Value, Value, u128) {
    let mut cache = ProjectFrontendCache::new();
    cache.build(manifest, prime).unwrap();
    let plain_start = Instant::now();
    let plain = cache.build(manifest, sources).unwrap();
    let plain_ns = plain_start.elapsed().as_nanos();
    cache = ProjectFrontendCache::new();
    cache.build(manifest, prime).unwrap();
    let (build, observation) = capture(|| cache.build(manifest, sources).unwrap())
        .expect("cache capture must not be nested");
    assert_eq!(plain.to_json(), build.to_json());
    project_equivalence::assert_revision_equivalent(build.revision(), plain.into_revision());
    (
        work(&build),
        revision_fields(build.revision()),
        observations(&observation),
        plain_ns,
    )
}

fn cache_row(
    scale: usize,
    name: &str,
    manifest: &ProjectManifest,
    original: &[ProjectFrontendSource],
    variant: &[ProjectFrontendSource],
    samples: usize,
) -> Value {
    let cold = ProjectFrontendCache::new()
        .build(manifest, variant)
        .unwrap()
        .into_revision();
    let mut cache = ProjectFrontendCache::new();
    cache.build(manifest, original).unwrap();
    let warm = cache.build(manifest, variant).unwrap().into_revision();
    project_equivalence::assert_revision_equivalent(&warm, cold);

    let mut cold_samples = Vec::with_capacity(samples);
    let mut warm_samples = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (cold_work, cold_product, cold_observation, cold_plain_ns) =
            timed_cache(manifest, variant);
        let (warm_work, warm_product, warm_observation, warm_plain_ns) =
            timed_warm_cache(manifest, original, variant);
        assert_eq!(cold_product, warm_product);
        cold_samples.push(json!({
            "work": cold_work,
            "product": cold_product,
            "observation": cold_observation,
            "plain_ns": cold_plain_ns,
        }));
        warm_samples.push(json!({
            "work": warm_work,
            "product": warm_product,
            "observation": warm_observation,
            "plain_ns": warm_plain_ns,
        }));
    }
    json!({
        "id": format!("cache-{scale}x-{name}"),
        "kind": "frontend_cache",
        "scale": scale,
        "variant": name,
        "product": revision_fields(&warm),
        "arms": {"cold": cold_samples, "warm": warm_samples},
    })
}

fn execution_fields(execution: &project::PreparedProjectExecution) -> Value {
    json!({
        "outcome": format!("{:?}", execution.outcome()),
        "steps_used": execution.steps_used(),
        "trace_bytes": execution.trace().envelope().len(),
        "trace_digest": execution.trace().digest(),
        "recorded_events": execution.trace().recorded_events(),
        "dropped_events": execution.trace().dropped_events(),
    })
}

fn untraced_execution_fields(execution: &project::UntracedPreparedProjectExecution) -> Value {
    json!({
        "outcome": format!("{:?}", execution.outcome()),
        "steps_used": execution.steps_used(),
        "max_steps": execution.max_steps(),
        "trace_bytes": 0,
    })
}

fn collect_execution_rows<T, W, C, E>(
    samples: usize,
    mut warm: W,
    mut cold: C,
    encode: E,
) -> (Vec<Value>, Vec<Value>)
where
    T: Eq + std::fmt::Debug,
    W: FnMut() -> T,
    C: FnMut() -> T,
    E: Fn(&T) -> Value,
{
    let mut warm_samples = Vec::with_capacity(samples);
    let mut cold_samples = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (warm_execution, warm_observation) = capture(&mut warm).unwrap();
        let plain_start = Instant::now();
        let plain_execution = warm();
        let plain_ns = plain_start.elapsed().as_nanos();
        assert_eq!(warm_execution, plain_execution);
        warm_samples.push(json!({
            "execution": encode(&warm_execution),
            "observation": observations(&warm_observation),
            "plain_ns": plain_ns,
        }));

        let (cold_execution, cold_observation) = capture(&mut cold).unwrap();
        let cold_plain_start = Instant::now();
        let cold_plain_execution = cold();
        let cold_plain_ns = cold_plain_start.elapsed().as_nanos();
        assert_eq!(cold_execution, warm_execution);
        assert_eq!(cold_execution, cold_plain_execution);
        cold_samples.push(json!({
            "execution": encode(&cold_execution),
            "observation": observations(&cold_observation),
            "plain_ns": cold_plain_ns,
        }));
    }
    (warm_samples, cold_samples)
}

fn prepared_rows(id: &str, manifest: &Path, samples: usize) -> Vec<Value> {
    let revision =
        project::with_authenticated_project(manifest, |snapshot| Ok(snapshot.retain_revision()))
            .unwrap();
    let ceilings = PreparedProjectInterpreterOptions::default();
    let options = PreparedProjectExecutionOptions::default();
    let cancellation = ProjectExecutionCancellation::new();
    let prepared = revision.prepare_interpreter(ceilings).unwrap();
    let traced = prepared.execute_entry(&options, &cancellation).unwrap();
    let untraced = prepared
        .execute_entry_untraced(options.max_steps, &cancellation)
        .unwrap();
    let cold_traced = project::with_authenticated_project(manifest, |snapshot| {
        let worker = snapshot.prepare_interpreter(ceilings)?;
        worker.execute_entry(&options, &cancellation)
    })
    .unwrap();
    let cold_untraced = project::with_authenticated_project(manifest, |snapshot| {
        let worker = snapshot.prepare_interpreter(ceilings)?;
        worker.execute_entry_untraced(options.max_steps, &cancellation)
    })
    .unwrap();
    assert_eq!(traced, cold_traced);
    assert_eq!(untraced, cold_untraced);

    let mut rows = Vec::new();
    {
        let (prepared_samples, cold_samples) = collect_execution_rows(
            samples,
            || prepared.execute_entry(&options, &cancellation).unwrap(),
            || {
                project::with_authenticated_project(manifest, |snapshot| {
                    let worker = snapshot.prepare_interpreter(ceilings)?;
                    worker.execute_entry(&options, &cancellation)
                })
                .unwrap()
            },
            execution_fields,
        );
        rows.push(json!({
            "id": format!("prepared-{id}-traced"),
            "kind": "prepared_interpreter",
            "fixture": revision_fields(&revision),
            "product": execution_fields(&traced),
            "arms": {"prepared": prepared_samples, "cold": cold_samples},
        }));
    }
    {
        let (prepared_samples, cold_samples) = collect_execution_rows(
            samples,
            || {
                prepared
                    .execute_entry_untraced(options.max_steps, &cancellation)
                    .unwrap()
            },
            || {
                project::with_authenticated_project(manifest, |snapshot| {
                    let worker = snapshot.prepare_interpreter(ceilings)?;
                    worker.execute_entry_untraced(options.max_steps, &cancellation)
                })
                .unwrap()
            },
            untraced_execution_fields,
        );
        rows.push(json!({
            "id": format!("prepared-{id}-untraced"),
            "kind": "prepared_interpreter",
            "fixture": revision_fields(&revision),
            "product": untraced_execution_fields(&untraced),
            "arms": {"prepared": prepared_samples, "cold": cold_samples},
        }));
    }
    rows
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path =
            env::temp_dir().join(format!("semaprax-workflow-observer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn main() {
    let mut samples = DEFAULT_SAMPLES;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--samples" {
            samples = args
                .next()
                .expect("--samples requires a value")
                .parse()
                .unwrap();
        } else {
            panic!("unknown argument: {arg}");
        }
    }
    assert!((1..=20).contains(&samples), "--samples must be in 1..=20");

    let mut rows = Vec::new();
    for scale in project_fixture::SCALES {
        let fixture = project_fixture::generate(scale);
        let manifest = ProjectManifest::parse(&fixture.manifest).unwrap();
        let original = source_rows(&fixture.sources);
        let leaf = source_rows(&fixture.with_edited_leaf());
        let provider = source_rows(&fixture.with_edited_core());
        rows.push(cache_row(
            scale,
            "unchanged",
            &manifest,
            &original,
            &original,
            samples,
        ));
        rows.push(cache_row(
            scale, "leaf", &manifest, &original, &leaf, samples,
        ));
        rows.push(cache_row(
            scale, "provider", &manifest, &original, &provider, samples,
        ));
    }

    let scratch = Scratch::new();
    let scalar_manifest =
        project_fixture::scalar_loop_project(LOOP_ITERATIONS).write_to(&scratch.0);
    rows.extend(prepared_rows("scalar-loop", &scalar_manifest, samples));
    for (id, directory) in [
        ("calculator", "examples/calculator-project"),
        ("apex", "examples/apex-supply-chain"),
    ] {
        rows.extend(prepared_rows(
            id,
            &Path::new(directory).join("semaprax.toml"),
            samples,
        ));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "benchmark.workflow-observation.v1",
            "samples": samples,
            "stages": Stage::ALL.iter().map(|stage| stage.name()).collect::<Vec<_>>(),
            "rows": rows,
        }))
        .unwrap()
    );
}
