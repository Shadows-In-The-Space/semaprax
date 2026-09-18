//! Effect declarations and capability requirements (issue #204's "In scope"
//! bullet of that exact name): a bounded, ordered capability registry
//! checked at the exact effect-authority boundary
//! ([`EffectHandler::dispatch`]), generalizing the checked tool/effect-id
//! registry `agent_lifecycle::iterative::effects::compile_typed_effects`
//! already binds to one closed Agent shape ("every operation must name an
//! exact source-owned tool ID present in the deployment's allowed subset")
//! to an arbitrary [`super::core::ResumableEffectProgram`]'s own `Request`
//! type.
//!
//! # Why a decorator, not a driver change
//!
//! [`CapabilityGatedHandler`] wraps an already-injected [`EffectHandler`]
//! and refuses a request whose declared capability id is outside the
//! caller's currently authorized [`CapabilityPolicy`] *before* the wrapped
//! handler -- the only real physical-effect boundary in this codebase -- is
//! ever called. A denial is reported through the driver's existing
//! `HandlerFailed` path (the same one a genuine host failure already takes,
//! proven by
//! `super::tests::replaying_a_recorded_failed_dispatch_never_recontacts_the_host`),
//! so it is recorded in the journal, never silently discarded, and a
//! replay of a denied journal reports the same denial again without ever
//! calling the wrapped handler a second time. This keeps a capability
//! declaration proof data about what is authorized, never itself an
//! authority: the wrapped handler must still be genuinely injected by the
//! caller, and genuinely authorize the id, for a request to do anything at
//! all.

use super::core::EffectHandler;

/// The bounded, ordered set of capability ids a caller currently authorizes
/// for one resumable computation. At most 64 entries, mirroring the
/// existing Agent typed-effects registry's own bound
/// (`docs/AGENT-TYPED-EFFECTS-V3.md`: "The registry contains at most 64
/// operations").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityPolicy {
    allowed: Vec<String>,
}

/// Why a [`CapabilityPolicy`] could not be constructed. Distinct, stable
/// reasons, the same way [`super::core::JournalError`]'s variants are kept
/// distinct rather than merged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityPolicyError {
    /// More entries than the bounded registry allows.
    TooManyCapabilities { count: usize },
    /// The same capability id named twice.
    DuplicateCapability { id: String },
    /// A capability id that names nothing.
    EmptyCapabilityId,
}

impl CapabilityPolicy {
    /// The bounded registry's exact ceiling, mirroring the existing Agent
    /// typed-effects operation registry.
    pub const MAX_CAPABILITIES: usize = 64;

    /// Construct a policy from an explicit, caller-supplied allowlist.
    /// Rejects more than [`Self::MAX_CAPABILITIES`] entries, a duplicate id,
    /// or an empty id, rather than silently accepting and later
    /// misreporting which ids are actually distinct and authorized.
    pub fn new(allowed: Vec<String>) -> Result<Self, CapabilityPolicyError> {
        if allowed.len() > Self::MAX_CAPABILITIES {
            return Err(CapabilityPolicyError::TooManyCapabilities {
                count: allowed.len(),
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for id in &allowed {
            if id.is_empty() {
                return Err(CapabilityPolicyError::EmptyCapabilityId);
            }
            if !seen.insert(id.clone()) {
                return Err(CapabilityPolicyError::DuplicateCapability { id: id.clone() });
            }
        }
        Ok(Self { allowed })
    }

    /// An empty policy: authorizes nothing. Never a default that silently
    /// allows every capability.
    pub fn none() -> Self {
        Self {
            allowed: Vec::new(),
        }
    }

    /// Whether `id` is currently authorized.
    pub fn allows(&self, id: &str) -> bool {
        self.allowed.iter().any(|allowed| allowed == id)
    }
}

/// Why a request was refused before any physical dispatch was attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityDenial {
    /// The request's declared capability id is not in the current policy's
    /// allowed set.
    NotAuthorized { capability: String },
}

/// Wraps an injected [`EffectHandler`], refusing any request whose declared
/// capability is not currently authorized before the wrapped handler is
/// ever called. `capability_of` is the pure, deterministic mapping from one
/// program's `Request` to the capability id it declares; it is supplied
/// once per program the same way [`super::core::ResumableEffectProgram`]'s
/// own `request`/`transition` methods are.
pub struct CapabilityGatedHandler<'a, Req, Obs> {
    inner: &'a mut dyn EffectHandler<Req, Obs>,
    policy: CapabilityPolicy,
    capability_of: Box<dyn Fn(&Req) -> String + 'a>,
    denials: Vec<CapabilityDenial>,
}

impl<'a, Req, Obs> CapabilityGatedHandler<'a, Req, Obs> {
    pub fn new(
        inner: &'a mut dyn EffectHandler<Req, Obs>,
        policy: CapabilityPolicy,
        capability_of: impl Fn(&Req) -> String + 'a,
    ) -> Self {
        Self {
            inner,
            policy,
            capability_of: Box::new(capability_of),
            denials: Vec::new(),
        }
    }

    /// Every denial this handler issued, in the exact order it issued them,
    /// for a caller (or test) to inspect after a driver call returns.
    pub fn denials(&self) -> &[CapabilityDenial] {
        &self.denials
    }
}

impl<'a, Req, Obs> EffectHandler<Req, Obs> for CapabilityGatedHandler<'a, Req, Obs> {
    fn dispatch(&mut self, request: &Req) -> Result<Obs, String> {
        let capability = (self.capability_of)(request);
        if !self.policy.allows(&capability) {
            self.denials.push(CapabilityDenial::NotAuthorized {
                capability: capability.clone(),
            });
            return Err(format!("capability not authorized: {capability}"));
        }
        self.inner.dispatch(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resumable_effects::core::*;

    /// A minimal one-turn program whose single request always declares the
    /// capability id `"multiply"`, small enough to stay local to this
    /// module rather than reusing `super::super::tests`'s larger
    /// `CounterProgram` fixture.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct OneShotProgram;

    impl ResumableEffectProgram for OneShotProgram {
        type State = u32;
        type Result = i64;
        type Request = i64;
        type Observation = i64;
        type CleanupOp = ();

        fn request(&self, state: &u32) -> Option<i64> {
            if *state == 0 {
                Some(7)
            } else {
                None
            }
        }

        fn transition(&self, state: &u32, observation: Option<&i64>) -> Step<u32, i64> {
            match observation {
                Some(obs) => Step::Complete(*obs),
                None => Step::Complete(*state as i64),
            }
        }

        fn cleanup_plan(&self, _state: &u32) -> Vec<()> {
            Vec::new()
        }
    }

    fn scope() -> EffectScope {
        EffectScope {
            program_root: "root:v1".to_string(),
            invocation_id: "cap-1".to_string(),
            policy_epoch: 1,
        }
    }

    fn always_multiply(request: &i64) -> String {
        let _ = request;
        "multiply".to_string()
    }

    struct RecordingHandler {
        calls: Vec<i64>,
    }
    impl EffectHandler<i64, i64> for RecordingHandler {
        fn dispatch(&mut self, request: &i64) -> Result<i64, String> {
            self.calls.push(*request);
            Ok(request * 10)
        }
    }

    struct PanicIfCalled;
    impl EffectHandler<i64, i64> for PanicIfCalled {
        fn dispatch(&mut self, request: &i64) -> Result<i64, String> {
            panic!("a capability-denied request must never reach the wrapped handler ({request})");
        }
    }

    struct NoCleanup;
    impl CleanupHandler<()> for NoCleanup {
        fn run(&mut self, _op: &()) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn policy_rejects_too_many_capabilities() {
        let ids: Vec<String> = (0..65).map(|i| format!("cap-{i}")).collect();
        let err = CapabilityPolicy::new(ids).unwrap_err();
        assert_eq!(
            err,
            CapabilityPolicyError::TooManyCapabilities { count: 65 }
        );
    }

    #[test]
    fn policy_rejects_a_duplicate_capability_id() {
        let err = CapabilityPolicy::new(vec!["multiply".to_string(), "multiply".to_string()])
            .unwrap_err();
        assert_eq!(
            err,
            CapabilityPolicyError::DuplicateCapability {
                id: "multiply".to_string()
            }
        );
    }

    #[test]
    fn policy_rejects_an_empty_capability_id() {
        let err = CapabilityPolicy::new(vec![String::new()]).unwrap_err();
        assert_eq!(err, CapabilityPolicyError::EmptyCapabilityId);
    }

    #[test]
    fn an_authorized_capability_reaches_the_wrapped_handler_and_dispatches_normally() {
        let program = OneShotProgram;
        let policy = CapabilityPolicy::new(vec!["multiply".to_string()]).unwrap();
        let mut inner = RecordingHandler { calls: Vec::new() };
        let mut gated = CapabilityGatedHandler::new(&mut inner, policy, always_multiply);
        let mut cleanup = NoCleanup;

        let (outcome, _journal) = run(
            &program,
            scope(),
            0u32,
            10,
            &mut gated,
            &mut cleanup,
            &|| false,
        )
        .expect("an authorized capability must dispatch and complete normally");

        assert_eq!(outcome.terminal, Step::Complete(70));
        assert!(gated.denials().is_empty());
    }

    #[test]
    fn an_unauthorized_capability_never_reaches_the_wrapped_handler() {
        let program = OneShotProgram;
        // Deliberately does not authorize "multiply".
        let policy = CapabilityPolicy::new(vec!["other".to_string()]).unwrap();
        let mut inner = PanicIfCalled;
        let mut gated = CapabilityGatedHandler::new(&mut inner, policy, always_multiply);
        let mut cleanup = NoCleanup;

        let (err, journal) = run(
            &program,
            scope(),
            0u32,
            10,
            &mut gated,
            &mut cleanup,
            &|| false,
        )
        .expect_err("an unauthorized capability must be refused, never dispatched");

        match err {
            DriverError::HandlerFailed { turn, reason } => {
                assert_eq!(turn, 0);
                assert!(reason.contains("multiply"), "reason was {reason:?}");
            }
            other => panic!("expected HandlerFailed, got {other:?}"),
        }
        assert_eq!(
            gated.denials(),
            &[CapabilityDenial::NotAuthorized {
                capability: "multiply".to_string()
            }]
        );
        // The failed intent is durable evidence for a later authorized
        // resume, exactly like any other recorded handler failure.
        assert!(journal.validate(&scope()).is_ok());
    }

    #[test]
    fn replaying_a_denied_capability_never_recontacts_the_wrapped_handler() {
        let program = OneShotProgram;
        let policy = CapabilityPolicy::new(vec!["other".to_string()]).unwrap();
        let mut inner = PanicIfCalled;
        let mut gated = CapabilityGatedHandler::new(&mut inner, policy, always_multiply);
        let mut cleanup = NoCleanup;
        let (err1, journal) = run(
            &program,
            scope(),
            0u32,
            10,
            &mut gated,
            &mut cleanup,
            &|| false,
        )
        .unwrap_err();

        // Resume the exact same denied journal: it must report the same
        // denial again, deterministically, without a second physical
        // dispatch attempt against the (still panic-on-call) inner handler.
        let mut inner2 = PanicIfCalled;
        let policy2 = CapabilityPolicy::new(vec!["other".to_string()]).unwrap();
        let mut gated2 = CapabilityGatedHandler::new(&mut inner2, policy2, always_multiply);
        let mut cleanup2 = NoCleanup;
        let (err2, _journal2) = resume(
            &program,
            scope(),
            journal,
            0u32,
            10,
            &mut gated2,
            &mut cleanup2,
            &|| false,
        )
        .unwrap_err();
        assert_eq!(err1, err2);
        assert!(
            gated2.denials().is_empty(),
            "replay must not re-check a fresh capability decision by re-dispatching"
        );
    }
}
