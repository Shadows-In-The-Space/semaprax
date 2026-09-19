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

use serde_json::{Map, Value};

use crate::diagnostic::Diagnostic;

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

// ---------------------------------------------------------------------------
// JSON wire decode for issue #208's CLI/API surface.
//
// `crate::cli::typed_workflow` (the `workflow dispatch` front) reads bytes
// from disk and calls these two functions; it never parses a policy or
// request document itself. Both formats are deliberately minimal --
// `DispatchPolicy` and `DispatchRequest` each carry exactly one field -- so,
// unlike `super::graph_wire`, one small closed-key decode per type is kept
// here rather than split into a separate module.
// ---------------------------------------------------------------------------

fn malformed(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io(
        "SPX-Z922",
        format!("declared dispatch document: {}", message.into()),
    )
}

/// Largest wire document either decoder below accepts, checked before any
/// JSON parsing runs.
const MAX_WIRE_BYTES: usize = 65_536;

/// Bound on `DispatchPolicy`'s `allowed_targets` array length. Generous for
/// any real allow-list while still refusing an unbounded one.
const MAX_ALLOWED_TARGETS: usize = 256;

fn parse_value(bytes: &[u8], what: &str) -> Result<Value, Diagnostic> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(malformed(format!(
            "{what} document is {} bytes, over the {MAX_WIRE_BYTES}-byte bound",
            bytes.len()
        )));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| malformed(format!("{what} document is not valid UTF-8")))?;
    serde_json::from_str(text)
        .map_err(|error| malformed(format!("{what} document is not valid JSON: {error}")))
}

fn as_object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, Diagnostic> {
    value
        .as_object()
        .ok_or_else(|| malformed(format!("{what} document must be a JSON object")))
}

fn closed(map: &Map<String, Value>, keys: &[&str], what: &str) -> Result<(), Diagnostic> {
    if map.len() != keys.len() || !keys.iter().all(|key| map.contains_key(*key)) {
        let mut present: Vec<&str> = map.keys().map(String::as_str).collect();
        present.sort_unstable();
        return Err(malformed(format!(
            "{what} document must have exactly the fields {keys:?}, got {present:?}"
        )));
    }
    Ok(())
}

/// Decodes a [`DispatchPolicy`] from `{"allowed_targets": [<string>...]}`.
/// Every entry must be a string; the array is bounded by
/// [`MAX_ALLOWED_TARGETS`]. This function performs no admission decision of
/// its own -- it only builds the closed allow-list [`decide`] later checks a
/// [`DispatchRequest`] against.
pub fn parse_policy(bytes: &[u8]) -> Result<DispatchPolicy, Diagnostic> {
    let value = parse_value(bytes, "dispatch policy")?;
    let map = as_object(&value, "dispatch policy")?;
    closed(map, &["allowed_targets"], "dispatch policy")?;
    let targets = map
        .get("allowed_targets")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("dispatch policy `allowed_targets` must be an array"))?;
    if targets.len() > MAX_ALLOWED_TARGETS {
        return Err(malformed(format!(
            "dispatch policy `allowed_targets` has more than {MAX_ALLOWED_TARGETS} entries"
        )));
    }
    let mut allowed = Vec::with_capacity(targets.len());
    for (index, target) in targets.iter().enumerate() {
        let target = target.as_str().ok_or_else(|| {
            malformed(format!(
                "dispatch policy `allowed_targets[{index}]` must be a string"
            ))
        })?;
        allowed.push(target.to_owned());
    }
    Ok(DispatchPolicy::new(allowed))
}

/// Decodes a [`DispatchRequest`] from `{"target": <string>}`.
pub fn parse_request(bytes: &[u8]) -> Result<DispatchRequest, Diagnostic> {
    let value = parse_value(bytes, "dispatch request")?;
    let map = as_object(&value, "dispatch request")?;
    closed(map, &["target"], "dispatch request")?;
    let target = map
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("dispatch request `target` must be a string"))?;
    Ok(DispatchRequest {
        target: target.to_owned(),
    })
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    #[test]
    fn a_well_formed_policy_and_request_decode() {
        let policy =
            parse_policy(br#"{"allowed_targets": ["release-agent", "triage-agent"]}"#).unwrap();
        assert!(policy.allows("release-agent"));
        assert!(!policy.allows("unlisted-agent"));
        let request = parse_request(br#"{"target": "release-agent"}"#).unwrap();
        assert_eq!(request.target, "release-agent");
        assert_eq!(decide(&policy, &request), Ok("release-agent".to_owned()));
    }

    #[test]
    fn decoding_is_deterministic() {
        let bytes: &[u8] = br#"{"allowed_targets": ["a", "b"]}"#;
        assert_eq!(parse_policy(bytes).unwrap(), parse_policy(bytes).unwrap());
    }

    fn assert_malformed_policy(bytes: &[u8]) {
        let error = parse_policy(bytes).expect_err("expected a malformed-document refusal");
        assert_eq!(error.code, "SPX-Z922");
    }

    fn assert_malformed_request(bytes: &[u8]) {
        let error = parse_request(bytes).expect_err("expected a malformed-document refusal");
        assert_eq!(error.code, "SPX-Z922");
    }

    #[test]
    fn non_utf8_policy_bytes_are_refused() {
        assert_malformed_policy(&[0xff, 0xfe]);
    }

    #[test]
    fn invalid_json_policy_is_refused() {
        assert_malformed_policy(b"{ not json");
    }

    #[test]
    fn a_non_object_policy_is_refused() {
        assert_malformed_policy(b"[1, 2]");
    }

    #[test]
    fn an_unknown_field_on_a_policy_is_refused() {
        assert_malformed_policy(br#"{"allowed_targets": [], "extra": true}"#);
    }

    #[test]
    fn a_non_string_target_in_a_policy_is_refused() {
        assert_malformed_policy(br#"{"allowed_targets": ["ok", 5]}"#);
    }

    #[test]
    fn an_oversized_allowed_targets_array_is_refused() {
        let targets = (0..=MAX_ALLOWED_TARGETS)
            .map(|index| format!("\"target-{index}\""))
            .collect::<Vec<_>>()
            .join(",");
        let document = format!("{{\"allowed_targets\": [{targets}]}}");
        assert_malformed_policy(document.as_bytes());
    }

    #[test]
    fn an_unknown_field_on_a_request_is_refused() {
        assert_malformed_request(br#"{"target": "x", "extra": 1}"#);
    }

    #[test]
    fn a_non_string_request_target_is_refused() {
        assert_malformed_request(br#"{"target": 5}"#);
    }

    /// A request naming a path-traversal-shaped string is decoded as an
    /// entirely opaque target string, exactly like any other target name --
    /// this module never treats a target as, or resolves it against, a
    /// filesystem path.
    #[test]
    fn a_path_traversal_shaped_target_is_treated_as_an_opaque_string() {
        let request = parse_request(br#"{"target": "../../etc/passwd"}"#).unwrap();
        assert_eq!(request.target, "../../etc/passwd");
        let policy = DispatchPolicy::new(["../../etc/passwd".to_owned()]);
        assert_eq!(
            decide(&policy, &request),
            Ok("../../etc/passwd".to_owned())
        );
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
