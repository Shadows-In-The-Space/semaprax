//! Instrumentation must leave every canonical product and work counter intact.

#[path = "../../benches/support/project_equivalence.rs"]
mod project_equivalence;
#[path = "../../benches/support/project_fixture.rs"]
mod project_fixture;

use semaprax::project::{ProjectFrontendCache, ProjectFrontendSource, ProjectManifest};
use semaprax::workflow_profile::{capture, Stage};

#[test]
fn observing_cold_and_unchanged_builds_preserves_products_and_exposes_repeated_work() {
    let fixture = project_fixture::generate(1);
    let manifest = ProjectManifest::parse(&fixture.manifest).unwrap();
    let sources = fixture
        .sources
        .iter()
        .map(|(path, text)| ProjectFrontendSource::new(path, text).unwrap())
        .collect::<Vec<_>>();
    let ordinary = ProjectFrontendCache::new()
        .build(&manifest, &sources)
        .unwrap();
    let mut cache = ProjectFrontendCache::new();
    let (cold, cold_profile) = capture(|| cache.build(&manifest, &sources)).unwrap();
    let cold = cold.unwrap();
    assert!(cold_profile.complete);
    assert_eq!(cold.to_json(), ordinary.to_json());
    project_equivalence::assert_revision_equivalent(cold.revision(), ordinary.into_revision());

    let (warm, warm_profile) = capture(|| cache.build(&manifest, &sources)).unwrap();
    let warm = warm.unwrap();
    assert!(warm_profile.complete);
    project_equivalence::assert_revision_equivalent(warm.revision(), cold.into_revision());
    assert_eq!(
        cold_profile.stages[Stage::Parse as usize].calls,
        sources.len() as u64
    );
    assert_eq!(warm_profile.stages[Stage::Parse as usize].calls, 0);
    for phase in [
        Stage::Resolve,
        Stage::HirValidate,
        Stage::GraphRender,
        Stage::AnalysisIndex,
        Stage::TargetAdmission,
    ] {
        assert!(
            warm_profile.stages[phase as usize].calls > 0,
            "{} must still execute",
            phase.name()
        );
    }
    for report in [&cold_profile, &warm_profile] {
        let self_ns = report
            .stages
            .iter()
            .map(|stage| stage.self_ns)
            .sum::<u128>();
        assert!(self_ns <= report.total_ns);
    }
}
