//! Exact semantic-product comparisons shared by benchmarks and their smoke tests.

use semaprax::project::{ProjectRevision, ProjectSemanticImage};
use std::sync::Arc;

/// Assert that two independently built revisions expose the same complete
/// authenticated Project and derived image products.
pub fn assert_revision_equivalent(cached: &Arc<ProjectRevision>, cold: Arc<ProjectRevision>) {
    assert_eq!(cached.project_revision(), cold.project_revision());
    assert_eq!(cached.workspace_revision(), cold.workspace_revision());
    assert_eq!(cached.workspace_manifest(), cold.workspace_manifest());
    assert_eq!(cached.sources(), cold.sources());
    assert_eq!(cached.semantic_graph(), cold.semantic_graph());

    let left = ProjectSemanticImage::derive(Arc::clone(cached), cached.project_revision())
        .expect("cached revision must derive an image");
    let right = ProjectSemanticImage::derive(Arc::clone(&cold), cold.project_revision())
        .expect("cold revision must derive an image");
    assert_eq!(left.image_digest(), right.image_digest());
    assert_eq!(left.to_json(), right.to_json());
}
