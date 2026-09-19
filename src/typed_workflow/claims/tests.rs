use super::*;

fn concurrent(ids: &[u32]) -> BTreeSet<StepId> {
    ids.iter().copied().map(StepId).collect()
}

#[test]
fn a_graph_that_declares_nothing_has_no_conflict() {
    let claims = ClaimSet::none();
    assert!(claims.is_empty());
    assert_eq!(
        first_conflict_among(&claims, StepId(0), &concurrent(&[1, 2, 3])),
        None
    );
}

#[test]
fn disjoint_claims_are_not_a_conflict() {
    let mut claims = ClaimSet::none();
    claims.declare(StepId(1), ResourceClaim::resource("a"));
    claims.declare(StepId(2), ResourceClaim::resource("b"));
    assert_eq!(
        first_conflict_among(&claims, StepId(0), &concurrent(&[1, 2])),
        None
    );
}

#[test]
fn the_same_name_under_different_kinds_is_not_a_conflict() {
    // A semantic candidate named "x" and a resource named "x" are not the
    // same thing. Comparing names alone would refuse a legitimate graph.
    let mut claims = ClaimSet::none();
    claims.declare(StepId(1), ResourceClaim::resource("x"));
    claims.declare(StepId(2), ResourceClaim::semantic_candidate("x"));
    assert_eq!(
        first_conflict_among(&claims, StepId(0), &concurrent(&[1, 2])),
        None
    );
}

#[test]
fn two_concurrent_branches_claiming_one_resource_conflict() {
    let mut claims = ClaimSet::none();
    claims.declare(StepId(1), ResourceClaim::resource("workspace/main"));
    claims.declare(StepId(2), ResourceClaim::resource("workspace/main"));
    assert_eq!(
        first_conflict_among(&claims, StepId(0), &concurrent(&[1, 2])),
        Some(Conflict {
            parallel: StepId(0),
            left: StepId(1),
            right: StepId(2),
            claim: ResourceClaim::resource("workspace/main"),
        })
    );
}

#[test]
fn two_concurrent_branches_claiming_one_semantic_candidate_conflict() {
    // The issue's own named failure case, spelled out as its own test so a
    // future change that only handles `Resource` fails here.
    let mut claims = ClaimSet::none();
    claims.declare(StepId(3), ResourceClaim::semantic_candidate("cand-7"));
    claims.declare(StepId(4), ResourceClaim::semantic_candidate("cand-7"));
    let conflict = first_conflict_among(&claims, StepId(1), &concurrent(&[3, 4]))
        .expect("overlapping semantic candidate is a conflict");
    assert_eq!(conflict.claim.kind, ClaimKind::SemanticCandidate);
    assert_eq!(conflict.claim.name, "cand-7");
}

#[test]
fn a_step_never_conflicts_with_itself() {
    // Declaring the same claim twice for one step, and a step appearing in
    // its own concurrent set, must both be non-conflicts: a step does not
    // race itself.
    let mut claims = ClaimSet::none();
    claims.declare(StepId(5), ResourceClaim::resource("r"));
    claims.declare(StepId(5), ResourceClaim::resource("r"));
    assert_eq!(claims.of(StepId(5)).map(BTreeSet::len), Some(1));
    assert_eq!(
        first_conflict_among(&claims, StepId(0), &concurrent(&[5])),
        None
    );
}

#[test]
fn the_reported_pair_and_claim_are_the_lowest_ones_not_an_arbitrary_overlap() {
    // Three branches, several overlaps, two shared claims between the same
    // pair: the report must be the ascending-first pair and that pair's
    // ascending-first shared claim, so a caller reading a diagnostic gets
    // the same answer on every run.
    let mut claims = ClaimSet::none();
    for step in [2u32, 4, 6] {
        claims.declare(StepId(step), ResourceClaim::resource("zeta"));
        claims.declare(StepId(step), ResourceClaim::resource("alpha"));
    }
    let conflict = first_conflict_among(&claims, StepId(1), &concurrent(&[6, 4, 2]))
        .expect("all three branches overlap");
    assert_eq!(conflict.left, StepId(2));
    assert_eq!(conflict.right, StepId(4));
    assert_eq!(conflict.claim, ResourceClaim::resource("alpha"));
}

#[test]
fn conflict_detection_is_a_pure_function_of_the_declaration_not_of_insertion_order() {
    let mut forwards = ClaimSet::none();
    forwards.declare(StepId(1), ResourceClaim::resource("a"));
    forwards.declare(StepId(1), ResourceClaim::resource("b"));
    forwards.declare(StepId(2), ResourceClaim::resource("b"));
    forwards.declare(StepId(2), ResourceClaim::resource("a"));

    let mut backwards = ClaimSet::none();
    backwards.declare(StepId(2), ResourceClaim::resource("a"));
    backwards.declare(StepId(2), ResourceClaim::resource("b"));
    backwards.declare(StepId(1), ResourceClaim::resource("b"));
    backwards.declare(StepId(1), ResourceClaim::resource("a"));

    assert_eq!(forwards, backwards);
    assert_eq!(
        first_conflict_among(&forwards, StepId(0), &concurrent(&[1, 2])),
        first_conflict_among(&backwards, StepId(0), &concurrent(&[2, 1]))
    );
}

#[test]
fn a_step_over_the_claim_bound_is_reported_and_the_lowest_such_step_wins() {
    let mut claims = ClaimSet::none();
    for index in 0..=MAX_CLAIMS_PER_STEP {
        claims.declare(StepId(9), ResourceClaim::resource(format!("r{index}")));
        claims.declare(StepId(4), ResourceClaim::resource(format!("r{index}")));
    }
    assert_eq!(claims.first_over_claim_bound(), Some(StepId(4)));
}

#[test]
fn exactly_the_claim_bound_is_admitted() {
    let mut claims = ClaimSet::none();
    for index in 0..MAX_CLAIMS_PER_STEP {
        claims.declare(StepId(1), ResourceClaim::resource(format!("r{index}")));
    }
    assert_eq!(claims.first_over_claim_bound(), None);
}

#[test]
fn the_conflict_diagnostic_names_both_branches_the_claim_and_a_stable_code() {
    let diagnostic = conflict_diagnostic(&Conflict {
        parallel: StepId(1),
        left: StepId(2),
        right: StepId(3),
        claim: ResourceClaim::semantic_candidate("cand-7"),
    });
    assert_eq!(diagnostic.code, CONFLICT_DIAGNOSTIC_CODE);
    assert_eq!(diagnostic.code, "SPX-Z925");
    let message = diagnostic.message.clone();
    assert!(message.contains(" 2 "), "{message}");
    assert!(message.contains(" 3 "), "{message}");
    assert!(message.contains("semantic-candidate"), "{message}");
    assert!(message.contains("cand-7"), "{message}");
}

#[test]
fn declaring_steps_enumerates_in_ascending_order() {
    let mut claims = ClaimSet::none();
    claims.declare(StepId(9), ResourceClaim::resource("a"));
    claims.declare(StepId(2), ResourceClaim::resource("a"));
    claims.declare(StepId(5), ResourceClaim::resource("a"));
    let steps: Vec<StepId> = claims.declaring_steps().collect();
    assert_eq!(steps, vec![StepId(2), StepId(5), StepId(9)]);
}
