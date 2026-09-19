//! Admission decisions for the schema-only `Declared` step kinds
//! (`AgentCall`, `ToolCall`, `Job`, `TestBuild`, `PublicationRequest` — see
//! [`super::graph::DeclaredStepKind`]).
//!
//! [`super::graph::StepKind::Declared`] carries no target payload at all: a
//! workflow author can say "this step is an `AgentCall`" but the graph
//! schema itself names no agent, tool, job, build profile, or publication
//! target. [`decide`] is the only function that turns a caller-declared
//! [`DispatchRequest`] into an admitted target, and it can only ever return
//! a member of the [`DispatchPolicy`] it was given — mirroring
//! [`super::model_routing::route`]'s relationship to
//! [`super::model_routing::DeploymentPolicy`] exactly, applied here to the
//! five declared dispatch kinds instead of `ModelCall`.
//!
//! Per the repository invariant that "a settlement or concurrency model is
//! proof data, not permission to perform a physical finalizer, spawn
//! runtime work, or publish an artifact," this module (and
//! `engine::DispatchExecutor`, the only caller of [`decide`]) never invokes
//! an agent, runs a tool, spawns a job, runs a build, or publishes
//! anything. [`decide`] is a pure function from an admission request and a
//! declared allow-list to an admitted target name, or a refusal — nothing
//! here holds a handle, closure, process, or capability able to act on that
//! decision. A caller with its own, separately granted authority is free to
//! act on an admitted target; this module only ever decides whether the
//! request was in scope.

use std::collections::BTreeSet;

/// A workflow author's declared allow-list of dispatch targets for one
/// `Declared` step. Closed and explicit: there is no wildcard member and no
/// path from "not listed" to "admitted anyway."
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchPolicy {
    allowed_targets: BTreeSet<String>,
}

impl DispatchPolicy {
    #[must_use]
    pub fn new(allowed_targets: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed_targets: allowed_targets.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn allows(&self, target: &str) -> bool {
        self.allowed_targets.contains(target)
    }
}

/// A caller's declared request naming the dispatch target (an agent name, a
/// tool name, a job kind, a build profile, or a publication target) for one
/// `Declared` step. Presenting a request never itself performs the
/// dispatch; it is only the "what would this step do" half of the decision
/// [`decide`] makes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchRequest {
    pub target: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchError {
    /// The requested target is not a member of the declared policy. Never
    /// widened to "admit the closest allowed target instead": an
    /// out-of-policy request is refused, not silently substituted.
    NotInPolicy,
}

/// Decides whether `request.target` is admissible under `policy`. Returns
/// the requested target unchanged only if it is a policy member; otherwise
/// refuses. A pure function of `(policy, request)` — same inputs, same
/// output, every time — and nothing more: it never invokes, spawns, or
/// publishes the target it admits.
pub fn decide(policy: &DispatchPolicy, request: &DispatchRequest) -> Result<String, DispatchError> {
    if policy.allows(&request.target) {
        Ok(request.target.clone())
    } else {
        Err(DispatchError::NotInPolicy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> DispatchPolicy {
        DispatchPolicy::new(["release-agent".to_string(), "triage-agent".to_string()])
    }

    #[test]
    fn requesting_an_allowed_target_is_admitted() {
        assert_eq!(
            decide(
                &policy(),
                &DispatchRequest {
                    target: "release-agent".to_string()
                }
            ),
            Ok("release-agent".to_string())
        );
    }

    #[test]
    fn requesting_a_target_outside_the_policy_is_refused() {
        assert_eq!(
            decide(
                &policy(),
                &DispatchRequest {
                    target: "unlisted-agent".to_string()
                }
            ),
            Err(DispatchError::NotInPolicy)
        );
    }

    #[test]
    fn deciding_is_deterministic_across_repeated_calls() {
        let p = policy();
        let request = DispatchRequest {
            target: "triage-agent".to_string(),
        };
        let first = decide(&p, &request);
        let second = decide(&p, &request);
        assert_eq!(first, second);
    }

    #[test]
    fn empty_policy_admits_nothing() {
        let empty = DispatchPolicy::new(std::iter::empty());
        assert_eq!(
            decide(
                &empty,
                &DispatchRequest {
                    target: "release-agent".to_string()
                }
            ),
            Err(DispatchError::NotInPolicy)
        );
    }
}
