//! The ordinary kernel decoder backed by one checked interaction schema.

use crate::agent_interaction_schema::CompiledInteractionSchema;

use super::model_invoke::{ProposalDecoder, ProposalOutcome};

/// Binds the generic kernel's whole-response decode seam to the same compiled
/// schema the streaming provider bridge uses. Decoding returns only the
/// schema's canonical document; raw provider bytes never become a proposal.
pub struct CompiledProposalDecoder<'a> {
    schema: &'a CompiledInteractionSchema,
}

impl<'a> CompiledProposalDecoder<'a> {
    #[must_use]
    pub fn new(schema: &'a CompiledInteractionSchema) -> Self {
        Self { schema }
    }
}

impl ProposalDecoder for CompiledProposalDecoder<'_> {
    fn schema_digest(&self) -> &str {
        self.schema.schema().digest()
    }

    fn decode(&mut self, _: u32, response: &[u8]) -> ProposalOutcome {
        match self.schema.decode(response) {
            Ok(value) => ProposalOutcome::Admitted(value.canonical_json().as_bytes().to_vec()),
            Err(diagnostics) => ProposalOutcome::Refused(
                diagnostics
                    .first()
                    .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
                    .unwrap_or_else(|| "compiled proposal decode failed".to_owned()),
            ),
        }
    }
}
