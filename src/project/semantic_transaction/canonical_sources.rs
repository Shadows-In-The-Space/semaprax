//! Which sources a Universal Semantic Transaction v1 operation must find
//! comment-free canonical, and why that is no longer the whole workspace.
//!
//! Split out of `semantic_transaction.rs` to keep that module under the
//! repository's 1500-line cap.

use std::collections::BTreeMap;
use std::path::Path;

use crate::diagnostic::Diagnostic;

use super::{invalid, ProjectRevision};

/// Comment-free canonical source is required of exactly the sources a v1
/// operation **rewrites**, not of the complete workspace (issue #274).
///
/// The old whole-workspace scope was load-bearing while
/// `ProjectCandidate::apply`'s `materialize` step re-derived *every* source
/// through the comment-dropping canonical formatter: it was the only thing
/// standing between an already-canonical base and a candidate that silently
/// lost comments from a source the operation never intended to touch. That
/// made the precondition unsatisfiable for any project depending on a
/// commented compiler-bundled package (`std.auth` alone carries 253 `//`
/// lines), because bundled dependency source is immutable and reaches
/// `revision.sources()` through `standard_dependencies::extend_sources`.
///
/// `materialize` now preserves an untouched source's exact base bytes, so
/// the guarantee is re-established structurally rather than by a blanket
/// precondition: a source whose candidate bytes equal its base bytes lost
/// nothing, and needs no requirement at all. Every source the candidate
/// actually rewrote -- or dropped -- must still have been comment-free
/// canonical on both sides, so the rewrite is still provably the operation's
/// own intent and never an incidental reformat. This check fails closed on
/// anything it cannot pair.
pub(super) fn require_comment_free_canonical_rewrites(
    base: &ProjectRevision,
    candidate: &ProjectRevision,
) -> Result<(), Vec<Diagnostic>> {
    let base_sources = base
        .sources()
        .iter()
        .map(|source| (source.path(), source.source()))
        .collect::<BTreeMap<_, _>>();
    for source in candidate.sources() {
        match base_sources.get(source.path()).copied() {
            // Byte-identical to the base: `materialize` preserved it
            // verbatim, so no comment and no formatting choice was lost and
            // this source carries no requirement.
            Some(base_source) if base_source == source.source() => continue,
            Some(base_source) => {
                require_comment_free_canonical_source(source.path(), base_source)?;
            }
            None => {}
        }
        require_comment_free_canonical_source(source.path(), source.source())?;
    }
    // A base source the candidate no longer carries had its bytes discarded
    // rather than preserved, so it is a rewrite too.
    for (path, base_source) in &base_sources {
        if !candidate
            .sources()
            .iter()
            .any(|candidate_source| candidate_source.path() == *path)
        {
            require_comment_free_canonical_source(path, base_source)?;
        }
    }
    Ok(())
}

fn require_comment_free_canonical_source(path: &str, source: &str) -> Result<(), Vec<Diagnostic>> {
    let (program, comments) =
        crate::parse_with_comments(source, Path::new(path)).map_err(|error| vec![error])?;
    if !comments.items.is_empty() || crate::format::canonical(&program) != source {
        return Err(invalid(
            "semantic transaction v1 requires comment-free canonical source in every source it \
             rewrites; sources the operation leaves untouched -- compiler-bundled dependency \
             source included -- keep their exact bytes and carry no such requirement",
        ));
    }
    Ok(())
}

/// Advisory, discovery-side form of the same rule: the one source a v1
/// operation on `target` would rewrite must be comment-free canonical. Kept
/// separate from [`require_comment_free_canonical_rewrites`] because
/// discovery has no candidate to diff against.
pub(super) fn comment_free_canonical_rewrite_domain(
    revision: &ProjectRevision,
    owner: Option<&str>,
) -> bool {
    let Some(owner) = owner else {
        return false;
    };
    revision
        .sources()
        .iter()
        .find(|source| source.path() == owner)
        .is_some_and(|source| {
            require_comment_free_canonical_source(source.path(), source.source()).is_ok()
        })
}
