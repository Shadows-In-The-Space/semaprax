use super::{Frame, ResolvedExpr};
use crate::hir::capacity_probe::{note_iterative_phase_capacity, resolved_expr_owned_capacity};
use crate::hir::resolve_expr_frame::frame_owned_capacity;

pub(super) fn note(frames: &Vec<Frame<'_>>, results: &Vec<ResolvedExpr>, frame: &Frame<'_>) {
    let mut seen_scopes = std::collections::HashSet::new();
    let frame_owned = frames.iter().fold(0_usize, |total, candidate| {
        total.saturating_add(frame_owned_capacity(candidate, &mut seen_scopes))
    });
    let current_owned = frame_owned_capacity(frame, &mut seen_scopes);
    note_iterative_phase_capacity(
        0,
        frames.capacity() * std::mem::size_of::<Frame<'_>>()
            + results.capacity() * std::mem::size_of::<ResolvedExpr>()
            + results
                .iter()
                .map(resolved_expr_owned_capacity)
                .sum::<usize>()
            + frame_owned
            + current_owned,
    );
}
