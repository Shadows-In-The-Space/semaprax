//! Model routing bound to a closed deployment policy.
//!
//! A [`StepKind::ModelCall`](super::graph::StepKind::ModelCall) step names
//! the model it wants; [`route`] is the only function that turns that
//! request into a model to actually call, and it can only ever return a
//! member of the [`DeploymentPolicy`] it was given. There is no path in
//! this module from "requested model string" to "chosen model" that skips
//! the policy — routing is a lookup against a fixed, explicit set, never a
//! dynamic provider choice, matching the issue's "model routing must stay
//! inside the declared deployment policy" requirement.
//!
//! This module makes the routing *decision* deterministic and
//! policy-bound; it does not perform a model call, issue a model receipt,
//! or integrate with `crate::live_invocation` — that integration is
//! residual scope (see the module's audit notes).

use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentPolicy {
    allowed_models: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingError {
    /// The requested model is not a member of the policy. Note this is
    /// never widened to "pick the closest allowed model instead": an
    /// out-of-policy request is refused, not silently substituted.
    NotInPolicy,
}

impl DeploymentPolicy {
    #[must_use]
    pub fn new(allowed_models: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed_models: allowed_models.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn allows(&self, model: &str) -> bool {
        self.allowed_models.contains(model)
    }
}

/// Route `requested_model` through `policy`. Returns the requested model
/// unchanged only if it is a policy member; otherwise refuses. The result
/// is a pure function of `(policy, requested_model)` — same inputs, same
/// output, every time.
pub fn route(policy: &DeploymentPolicy, requested_model: &str) -> Result<String, RoutingError> {
    if policy.allows(requested_model) {
        Ok(requested_model.to_string())
    } else {
        Err(RoutingError::NotInPolicy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> DeploymentPolicy {
        DeploymentPolicy::new(["small-checked-1".to_string(), "large-checked-1".to_string()])
    }

    #[test]
    fn requesting_an_allowed_model_routes_to_it() {
        assert_eq!(
            route(&policy(), "small-checked-1"),
            Ok("small-checked-1".to_string())
        );
    }

    #[test]
    fn requesting_a_model_outside_the_policy_is_refused() {
        assert_eq!(
            route(&policy(), "unlisted-provider-model"),
            Err(RoutingError::NotInPolicy)
        );
    }

    #[test]
    fn routing_is_deterministic_across_repeated_calls() {
        let p = policy();
        let first = route(&p, "large-checked-1");
        let second = route(&p, "large-checked-1");
        assert_eq!(first, second);
    }

    #[test]
    fn empty_policy_admits_nothing() {
        let empty = DeploymentPolicy::new(std::iter::empty());
        assert_eq!(
            route(&empty, "small-checked-1"),
            Err(RoutingError::NotInPolicy)
        );
    }
}
