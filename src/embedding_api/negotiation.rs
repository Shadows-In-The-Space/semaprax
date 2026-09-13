//! Bounded, authority-free host feature negotiation.

use super::{
    cancelled_context_outcome, context_v2_source, ContextOutcome, ContextV2Options,
    EmbeddingApiVersion, EmbeddingCancellation, EMBEDDING_API_VERSION,
};
use crate::diagnostic::Diagnostic;

pub const UNSUPPORTED_FEATURE_DIAGNOSTIC_CODE: &str = "SPX-EMB004";

/// Exact operation/profile identifiers. Availability grants no execution or
/// publication authority; effectful calls still require their capability.
pub const SUPPORTED_FEATURES: &[&str] = &[
    "source-analysis-v1",
    "context-v1",
    "context-v2",
    "project-session-v1",
    "project-candidate-v2",
    "deterministic-i64-entry-v1",
    "context-cancellation-v1",
    "project-pre-cancellation-v1",
];

/// Successful compatibility selection. Fields are read-only and refer only to
/// this build's supported facade, never a compiler-owned program or provider.
#[derive(Debug)]
pub struct EmbeddingFeatures {
    version: EmbeddingApiVersion,
}

impl EmbeddingFeatures {
    pub fn version(&self) -> EmbeddingApiVersion {
        self.version
    }

    pub fn supports(&self, feature: &str) -> bool {
        SUPPORTED_FEATURES.contains(&feature)
    }
}

/// Require an API major, minimum minor, and exact supported feature names.
/// Unknown names fail closed. At most 32 names of at most 128 bytes are read;
/// this function allocates no retained copy of caller input.
pub fn negotiate_features(
    major: u16,
    minimum_minor: u16,
    required: &[&str],
) -> Result<EmbeddingFeatures, Diagnostic> {
    EMBEDDING_API_VERSION.require_compatible(major)?;
    if minimum_minor > EMBEDDING_API_VERSION.minor {
        return Err(Diagnostic::io(
            super::VERSION_MISMATCH_DIAGNOSTIC_CODE,
            "requested embedding API minor is newer than this host supports",
        ));
    }
    if required.len() > 32
        || required
            .iter()
            .any(|name| name.len() > 128 || !SUPPORTED_FEATURES.contains(name))
    {
        return Err(Diagnostic::io(
            UNSUPPORTED_FEATURE_DIAGNOSTIC_CODE,
            "embedding request requires an unsupported feature or exceeds negotiation bounds",
        ));
    }
    Ok(EmbeddingFeatures {
        version: EMBEDDING_API_VERSION,
    })
}

/// Sample cancellation before analysis and before returning a successful v2
/// context report. Graph traversal itself has no interruption hook.
pub fn context_v2_source_with_cancellation(
    unit_name: &str,
    source: &str,
    symbol: &str,
    options: &ContextV2Options,
    cancellation: &EmbeddingCancellation,
) -> ContextOutcome {
    if cancellation.is_cancelled() {
        return cancelled_context_outcome(unit_name, symbol);
    }
    let outcome = context_v2_source(unit_name, source, symbol, options);
    if outcome.ok && cancellation.is_cancelled() {
        cancelled_context_outcome(unit_name, symbol)
    } else {
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_negotiation_refuses_unknown_profiles_and_newer_versions() {
        let selected = negotiate_features(1, 7, SUPPORTED_FEATURES).unwrap();
        assert_eq!(selected.version(), EMBEDDING_API_VERSION);
        assert!(selected.supports("project-candidate-v2"));
        assert!(!selected.supports("ambient-network-v1"));
        for required in [&["project-candidate-v3"][..], &["context-v2"; 33][..]] {
            assert_eq!(
                negotiate_features(1, 0, required).unwrap_err().code,
                UNSUPPORTED_FEATURE_DIAGNOSTIC_CODE
            );
        }
        assert_eq!(
            negotiate_features(1, u16::MAX, &[]).unwrap_err().code,
            super::super::VERSION_MISMATCH_DIAGNOSTIC_CODE
        );
        assert_eq!(
            negotiate_features(2, 0, &[]).unwrap_err().code,
            super::super::VERSION_MISMATCH_DIAGNOSTIC_CODE
        );
    }

    #[test]
    fn pre_cancelled_v2_context_refuses_before_malformed_source() {
        let cancellation = EmbeddingCancellation::new();
        cancellation.cancel();
        let result = context_v2_source_with_cancellation(
            "not-a-file.spx",
            "invalid",
            "root",
            &ContextV2Options::default(),
            &cancellation,
        );
        assert!(!result.ok);
        assert!(result.context_json.is_none());
        assert_eq!(
            result.diagnostics[0].code,
            super::super::CANCELLATION_DIAGNOSTIC_CODE
        );
    }
}
