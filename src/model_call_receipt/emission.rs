//! Receipt emission directly from completed/in-progress live run evidence.
//! Host metadata stays explicit: a run cannot invent measurements it did not
//! record. These convenience routes share the same constructors and replay.
use super::{
    generic_enrichment::{enrich_generic_call, EnrichmentError, GenericAttemptMetadata},
    receipt::{ModelCallReceipt, RootBindingContext},
    source_enrichment::{
        enrich_source_calls, SourceAttemptMetadata, SourceEnrichmentError,
        SourceReceiptBindingInputs,
    },
};
use crate::{
    agent_interaction_schema::CompiledInteractionSchema,
    live_invocation::{
        identity::LiveInvocationSeed, kernel::LiveKernelRun, model_invoke::ModelInvocationRequest,
        source_journal::RecoveredSourceCheckpoint,
    },
};

impl LiveKernelRun {
    /// Emits the selected attempt's rich receipt from this run's actual
    /// journal. The request and host binding must have been retained separately.
    pub fn rich_model_call_receipt(
        &self,
        seed: &LiveInvocationSeed,
        request: &ModelInvocationRequest,
        schema: &CompiledInteractionSchema,
        roots: &RootBindingContext<'_>,
        host: &GenericAttemptMetadata<'_>,
    ) -> Result<ModelCallReceipt, EnrichmentError> {
        enrich_generic_call(&self.journal, seed, request, schema, roots, host)
    }
}

impl RecoveredSourceCheckpoint {
    /// Emits causally ordered rich receipts from the authenticated checkpoint.
    /// Unknown mandatory host facts cannot be replaced with invented defaults.
    pub fn rich_model_call_receipts(
        &self,
        inputs: &SourceReceiptBindingInputs<'_>,
        attempts: &[SourceAttemptMetadata<'_>],
    ) -> Result<Vec<ModelCallReceipt>, SourceEnrichmentError> {
        enrich_source_calls(self, inputs, attempts)
    }
}
