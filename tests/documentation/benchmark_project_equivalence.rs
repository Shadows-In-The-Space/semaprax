//! Benchmark smoke coverage for exact cold/cache semantic-product equality.

#[path = "../../benches/support/project_equivalence.rs"]
mod project_equivalence;
#[path = "../../benches/support/project_fixture.rs"]
mod project_fixture;

use semaprax::project::{ProjectFrontendCache, ProjectFrontendSource, ProjectManifest};

fn frontend_sources(sources: &[(String, String)]) -> Vec<ProjectFrontendSource> {
    sources
        .iter()
        .map(|(path, source)| ProjectFrontendSource::new(path, source).unwrap())
        .collect()
}

#[test]
fn every_fixture_scale_preserves_exact_products_on_cache_hits() {
    for scale in project_fixture::SCALES {
        let fixture = project_fixture::generate(scale);
        let manifest = ProjectManifest::parse(&fixture.manifest).unwrap();
        let original = frontend_sources(&fixture.sources);
        let leaf = frontend_sources(&fixture.with_edited_leaf());
        let provider = frontend_sources(&fixture.with_edited_core());

        for sources in [&original, &leaf, &provider] {
            let cold = ProjectFrontendCache::new()
                .build(&manifest, sources)
                .unwrap()
                .into_revision();
            let mut cache = ProjectFrontendCache::new();
            cache.build(&manifest, &original).unwrap();
            let warm = cache.build(&manifest, sources).unwrap().into_revision();
            project_equivalence::assert_revision_equivalent(&warm, cold);
        }
    }
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn exact_helper_rejects_comparing_different_source_revisions() {
    let original_fixture = project_fixture::generate(1);
    let edited_fixture = original_fixture.with_edited_leaf();
    let manifest = ProjectManifest::parse(&original_fixture.manifest).unwrap();
    let original = frontend_sources(&original_fixture.sources);
    let edited = frontend_sources(&edited_fixture);
    let left = ProjectFrontendCache::new()
        .build(&manifest, &original)
        .unwrap()
        .into_revision();
    let right = ProjectFrontendCache::new()
        .build(&manifest, &edited)
        .unwrap()
        .into_revision();
    project_equivalence::assert_revision_equivalent(&left, right);
}
