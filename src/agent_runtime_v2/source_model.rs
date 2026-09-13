//! Bound streaming model-operation facts for Direct Runtime v2.
//!
//! This is the additive bridge between a retained source Agent deployment and
//! an injected provider adapter. It names checked identities and bounded
//! observations only; it never stores a credential, endpoint, prompt, or
//! response body and grants no transport authority by itself.

use sha2::{Digest, Sha256};

use crate::agent_deployment::DeploymentModelSelection;
use crate::diagnostic::quote_json;
use crate::provider_adapter_sdk::AdapterCapabilities;

const DOMAIN: &[u8] = b"semaprax.agent-runtime-v2.source-model-binding.v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"semaprax.agent-runtime-v2.source-model-evidence.v1\0";
const REQUEST_DOMAIN: &[u8] = b"semaprax.agent-runtime-v2.source-model-request.v1\0";
const RESPONSE_DOMAIN: &[u8] = b"semaprax.agent-runtime-v2.source-model-response.v1\0";
const MAX_ID_BYTES: usize = 256;
const MAX_ATTEMPTS: usize = 4096;

/// Host-selected identity of one adapter implementation behind a deployment
/// model selection. These labels are commitments, never provider credentials
/// or network endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceModelAdapterIdentity {
    pub provider_id: String,
    pub model_id: String,
    pub adapter_identity: String,
    pub adapter_version: String,
    pub provider_profile: String,
}

impl SourceModelAdapterIdentity {
    fn valid(&self) -> bool {
        [
            &self.provider_id,
            &self.model_id,
            &self.adapter_identity,
            &self.adapter_version,
            &self.provider_profile,
        ]
        .iter()
        .all(|value| {
            !value.is_empty() && value.len() <= MAX_ID_BYTES && !value.chars().any(char::is_control)
        })
    }
}

/// Runtime-derived, provider-neutral model operation binding v1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceModelBinding {
    deployment_root: String,
    instance_root: String,
    source_revision: String,
    proposal_schema_digest: String,
    adapter: SourceModelAdapterIdentity,
    max_request_bytes: usize,
    max_response_bytes: usize,
    digest: String,
}

/// Retained deployment and compiler facts from which one concrete bound
/// adapter selection can be derived. Kept private to the checked runtime
/// producer so callers cannot synthesize it from arbitrary JSON.
pub(crate) struct SourceModelContract {
    deployment_digest: String,
    bound_deployment_digest: String,
    source_revision: String,
    proposal_schema_digest: String,
    granted_capabilities: Vec<String>,
    required_model_capabilities: Vec<String>,
    selections: Vec<DeploymentModelSelection>,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl SourceModelContract {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        deployment_digest: &str,
        bound_deployment_digest: &str,
        source_revision: &str,
        proposal_schema_digest: &str,
        granted_capabilities: &[String],
        required_model_capabilities: &[String],
        selections: Vec<DeploymentModelSelection>,
        max_request_bytes: usize,
        max_response_bytes: usize,
    ) -> Result<Self, &'static str> {
        if deployment_digest.is_empty()
            || bound_deployment_digest.is_empty()
            || source_revision.is_empty()
            || proposal_schema_digest.is_empty()
            || selections.is_empty()
            || max_request_bytes == 0
            || max_response_bytes == 0
        {
            return Err("source.model_contract");
        }
        Ok(Self {
            deployment_digest: deployment_digest.to_owned(),
            bound_deployment_digest: bound_deployment_digest.to_owned(),
            source_revision: source_revision.to_owned(),
            proposal_schema_digest: proposal_schema_digest.to_owned(),
            granted_capabilities: granted_capabilities.to_vec(),
            required_model_capabilities: required_model_capabilities.to_vec(),
            selections,
            max_request_bytes,
            max_response_bytes,
        })
    }

    pub(crate) fn bind(
        &self,
        deployment_root: &str,
        instance_root: &str,
        adapter: SourceModelAdapterIdentity,
    ) -> Result<SourceModelBinding, &'static str> {
        SourceModelBinding::new(
            deployment_root,
            instance_root,
            &self.deployment_digest,
            &self.bound_deployment_digest,
            &self.source_revision,
            &self.proposal_schema_digest,
            &self.granted_capabilities,
            &self.required_model_capabilities,
            &self.selections,
            adapter,
            self.max_request_bytes,
            self.max_response_bytes,
        )
    }
}

impl SourceModelBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        deployment_root: &str,
        instance_root: &str,
        deployment_digest: &str,
        bound_deployment_digest: &str,
        source_revision: &str,
        proposal_schema_digest: &str,
        granted_capabilities: &[String],
        required_model_capabilities: &[String],
        selections: &[DeploymentModelSelection],
        adapter: SourceModelAdapterIdentity,
        max_request_bytes: usize,
        max_response_bytes: usize,
    ) -> Result<Self, &'static str> {
        if !adapter.valid()
            || deployment_root.is_empty()
            || instance_root.is_empty()
            || deployment_digest.is_empty()
            || bound_deployment_digest.is_empty()
            || source_revision.is_empty()
            || proposal_schema_digest.is_empty()
            || max_request_bytes == 0
            || max_response_bytes == 0
            || max_request_bytes > 1_048_576
            || max_response_bytes > 1_048_576
        {
            return Err("source.model_binding");
        }
        let Some(selection) = selections.iter().find(|selection| {
            selection.provider_id() == adapter.provider_id
                && selection.model_id() == adapter.model_id
        }) else {
            return Err("source.model_binding");
        };
        if !required_model_capabilities.iter().all(|required| {
            selection
                .capabilities()
                .iter()
                .any(|capability| capability == required)
        }) {
            return Err("source.model_capability");
        }
        let granted_capabilities = granted_capabilities.to_vec();
        let required_model_capabilities = required_model_capabilities.to_vec();
        let canonical = format!(
            "{{\"schema\":\"semaprax.agent-runtime-v2.source-model-binding.v1\",\"deployment_root\":{},\"instance_root\":{},\"deployment\":{},\"binding\":{},\"source_revision\":{},\"proposal_schema\":{},\"grants\":[{}],\"required_model_capabilities\":[{}],\"provider\":{},\"model\":{},\"adapter\":{},\"adapter_version\":{},\"profile\":{},\"max_request_bytes\":{},\"max_response_bytes\":{}}}",
            quote_json(deployment_root), quote_json(instance_root), quote_json(deployment_digest), quote_json(bound_deployment_digest),
            quote_json(source_revision), quote_json(proposal_schema_digest),
            granted_capabilities.iter().map(|value| quote_json(value)).collect::<Vec<_>>().join(","),
            required_model_capabilities.iter().map(|value| quote_json(value)).collect::<Vec<_>>().join(","),
            quote_json(&adapter.provider_id), quote_json(&adapter.model_id), quote_json(&adapter.adapter_identity),
            quote_json(&adapter.adapter_version), quote_json(&adapter.provider_profile), max_request_bytes,
            max_response_bytes,
        );
        let digest = digest(DOMAIN, canonical.as_bytes());
        Ok(Self {
            deployment_root: deployment_root.to_owned(),
            instance_root: instance_root.to_owned(),
            source_revision: source_revision.to_owned(),
            proposal_schema_digest: proposal_schema_digest.to_owned(),
            adapter,
            max_request_bytes,
            max_response_bytes,
            digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    #[must_use]
    pub fn proposal_schema_digest(&self) -> &str {
        &self.proposal_schema_digest
    }

    #[must_use]
    pub fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    #[must_use]
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    #[must_use]
    pub fn adapter_identity(&self) -> &SourceModelAdapterIdentity {
        &self.adapter
    }

    /// Derives the non-ambient binding token an adapter must present to the
    /// Direct Runtime route. The token is a commitment, never transport
    /// authority; actual host authority remains `AdapterInvocationCapability`.
    #[must_use]
    pub fn invocation_capability(&self) -> SourceModelInvocationCapability {
        SourceModelInvocationCapability {
            binding_digest: self.digest.clone(),
        }
    }

    pub(crate) fn adapter_matches(&self, caps: &AdapterCapabilities) -> bool {
        caps.adapter_identity == self.adapter.adapter_identity
            && caps.adapter_version == self.adapter.adapter_version
            && caps.provider_profile == self.adapter.provider_profile
    }

    pub(crate) fn capability_matches(&self, capability: &SourceModelInvocationCapability) -> bool {
        capability.binding_digest == self.digest
    }

    pub(crate) fn runtime_matches(
        &self,
        deployment_root: &str,
        instance_root: &str,
        source_revision: &str,
        proposal_schema_digest: &str,
    ) -> bool {
        self.deployment_root == deployment_root
            && self.instance_root == instance_root
            && self.source_revision == source_revision
            && self.proposal_schema_digest == proposal_schema_digest
    }
}

/// Opaque commitment that ties a source adapter instance to one binding.
#[derive(Clone, Debug)]
pub struct SourceModelInvocationCapability {
    binding_digest: String,
}

/// One bounded, redacted model attempt observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceModelAttemptEvidence {
    request_digest: String,
    request_bytes: usize,
    response_digest: Option<String>,
    response_bytes: usize,
    terminal: String,
    tokens_in: Option<u64>,
    tokens_out: Option<u64>,
    cost_micros: Option<i64>,
}

impl SourceModelAttemptEvidence {
    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }
    #[must_use]
    pub fn request_bytes(&self) -> usize {
        self.request_bytes
    }
    #[must_use]
    pub fn response_digest(&self) -> Option<&str> {
        self.response_digest.as_deref()
    }
    #[must_use]
    pub fn response_bytes(&self) -> usize {
        self.response_bytes
    }
    #[must_use]
    pub fn terminal(&self) -> &str {
        &self.terminal
    }
    #[must_use]
    pub fn tokens_in(&self) -> Option<u64> {
        self.tokens_in
    }
    #[must_use]
    pub fn tokens_out(&self) -> Option<u64> {
        self.tokens_out
    }
    #[must_use]
    pub fn cost_micros(&self) -> Option<i64> {
        self.cost_micros
    }
}

/// Canonical redacted observations for a bound live model source.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceModelEvidence {
    attempts: Vec<SourceModelAttemptEvidence>,
}

impl SourceModelEvidence {
    #[must_use]
    pub fn attempts(&self) -> &[SourceModelAttemptEvidence] {
        &self.attempts
    }

    #[must_use]
    pub fn digest(&self) -> String {
        digest(EVIDENCE_DOMAIN, self.canonical_json().as_bytes())
    }

    fn canonical_json(&self) -> String {
        let attempts = self.attempts.iter().map(|attempt| format!(
            "{{\"request\":{},\"request_bytes\":{},\"response\":{},\"response_bytes\":{},\"terminal\":{},\"tokens_in\":{},\"tokens_out\":{},\"cost_micros\":{}}}",
            quote_json(&attempt.request_digest), attempt.request_bytes,
            attempt.response_digest.as_deref().map(quote_json).unwrap_or_else(|| "null".to_owned()),
            attempt.response_bytes, quote_json(&attempt.terminal),
            attempt.tokens_in.map_or_else(|| "null".to_owned(), |value| value.to_string()),
            attempt.tokens_out.map_or_else(|| "null".to_owned(), |value| value.to_string()),
            attempt.cost_micros.map_or_else(|| "null".to_owned(), |value| value.to_string()),
        )).collect::<Vec<_>>().join(",");
        format!("{{\"schema\":\"semaprax.agent-runtime-v2.source-model-evidence.v1\",\"attempts\":[{attempts}]}}\n")
    }

    pub(crate) fn can_record(&self) -> bool {
        self.attempts.len() < MAX_ATTEMPTS
    }

    pub(crate) fn record(
        &mut self,
        request: &[u8],
        response: Option<&[u8]>,
        terminal: &str,
        tokens_in: Option<u64>,
        tokens_out: Option<u64>,
        cost_micros: Option<i64>,
    ) {
        assert!(
            self.can_record(),
            "source model evidence capacity preflight"
        );
        self.attempts.push(SourceModelAttemptEvidence {
            request_digest: digest(REQUEST_DOMAIN, request),
            request_bytes: request.len(),
            response_digest: response.map(|bytes| digest(RESPONSE_DOMAIN, bytes)),
            response_bytes: response.map_or(0, <[u8]>::len),
            terminal: terminal.to_owned(),
            tokens_in,
            tokens_out,
            cost_micros,
        });
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}
