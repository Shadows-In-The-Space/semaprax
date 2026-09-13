//! Opt-in, current-thread workflow observations for benchmark hosts.
//!
//! Enabled only by `unstable-workflow-profiling`. These measurements never enter
//! canonical compiler artifacts and carry no validation or execution authority.
//! Worker-thread work is included in a caller's wait span, not separately traced.

/// Closed instrumentation sites, not a claim of exhaustive CPU attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Stage {
    Parse,
    Canonicalize,
    Resolve,
    HirValidate,
    WorkspacePreflight,
    ProjectLink,
    GraphRender,
    AnalysisIndex,
    TargetAdmission,
    ImageDerivation,
    InterpreterPreparation,
    PreparedExecution,
}

impl Stage {
    pub const ALL: [Self; 12] = [
        Self::Parse,
        Self::Canonicalize,
        Self::Resolve,
        Self::HirValidate,
        Self::WorkspacePreflight,
        Self::ProjectLink,
        Self::GraphRender,
        Self::AnalysisIndex,
        Self::TargetAdmission,
        Self::ImageDerivation,
        Self::InterpreterPreparation,
        Self::PreparedExecution,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Canonicalize => "canonicalize",
            Self::Resolve => "resolve",
            Self::HirValidate => "hir_validate",
            Self::WorkspacePreflight => "workspace_preflight",
            Self::ProjectLink => "project_link",
            Self::GraphRender => "graph_render",
            Self::AnalysisIndex => "analysis_index",
            Self::TargetAdmission => "target_admission",
            Self::ImageDerivation => "image_derivation",
            Self::InterpreterPreparation => "interpreter_preparation",
            Self::PreparedExecution => "prepared_execution",
        }
    }
}

#[cfg(feature = "unstable-workflow-profiling")]
mod enabled;
#[cfg(feature = "unstable-workflow-profiling")]
pub(crate) use enabled::span;
#[cfg(feature = "unstable-workflow-profiling")]
pub use enabled::{capture, CaptureBusy, Observation, StageObservation};
