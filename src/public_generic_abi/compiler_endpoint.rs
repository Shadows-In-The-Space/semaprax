//! Compiler-owned admission facts for the future Public Generic Core Wasm
//! Provider v1 target.
//!
//! This is deliberately a Phase-A product only: it derives and independently
//! verifies the exact checked endpoint that a later Wasm emitter may lower.
//! It neither emits Wasm nor grants execution, allocation, filesystem,
//! process, network, publication, or provider authority.

use crate::diagnostic::Diagnostic;
use crate::hir::ResolvedProgram;
use crate::public_generic_abi::classifier::{self, AdmittedSubject};
use crate::public_generic_abi::descriptor::producer;
use crate::public_generic_abi::descriptor::verify::{
    verify_public_generic_descriptor, VerificationOptions, VerifiedPublicGenericDescriptor,
    GENERATOR_DISAGREEMENT,
};
use crate::public_generic_abi::{digest, frame};

/// The exact Project target/profile selected by this admission product.
pub const PUBLIC_GENERIC_WASM_PROVIDER_PROFILE: &str = "public-generic-wasm-provider.v1";

/// A domain-separated digest over every declaration identity in the checked
/// program. This is intentionally an independent reconstruction of the
/// descriptor producer's program-root input; the verifier independently
/// reconstructs it once more before accepting descriptor bytes.
const PROGRAM_ROOT_DOMAIN: &[u8] = b"semaprax.public-generic-descriptor.v1.program-root\0";

/// The trusted, compiler-derived endpoint facts a later provider emitter must
/// consume as one unit. The retained descriptor was independently verified
/// against the exact checked program and canonical source revision supplied at
/// admission time; callers cannot construct this type from parsed bytes.
pub struct AdmittedPublicGenericEndpointV1 {
    subject: AdmittedSubject,
    descriptor: VerifiedPublicGenericDescriptor,
}

impl AdmittedPublicGenericEndpointV1 {
    /// The persistent identity of the one concrete checked endpoint.
    pub fn export_id(&self) -> &str {
        self.subject.export_id()
    }

    /// Presentation-only source name of the selected endpoint.
    pub fn export_name(&self) -> &str {
        self.subject.export_name()
    }

    /// The classifier's target-neutral ownership and settlement facts.
    pub fn subject(&self) -> &AdmittedSubject {
        &self.subject
    }

    /// The independently verified descriptor binding this exact endpoint to
    /// its checked program and source revision.
    pub fn descriptor(&self) -> &VerifiedPublicGenericDescriptor {
        &self.descriptor
    }

    /// Canonical descriptor bytes embedded by a future provider artifact.
    pub fn descriptor_bytes(&self) -> &[u8] {
        self.descriptor.accepted_bytes()
    }
}

/// Derive the future provider target's endpoint from real checked HIR and
/// immediately replay the producer's bytes through the independent verifier.
///
/// `source_revision` must be the canonical source projection associated with
/// `program`; this function has no path or source-reading authority and never
/// accepts an unbound descriptor as a substitute for checked facts.
pub fn derive_admitted_public_generic_endpoint_v1(
    program: &ResolvedProgram,
    source_revision: &str,
    export_id: &str,
) -> Result<AdmittedPublicGenericEndpointV1, Diagnostic> {
    let generated =
        producer::generate_public_generic_descriptor(program, source_revision, export_id)?;
    replay_admitted_public_generic_endpoint_v1(
        program,
        source_revision,
        export_id,
        generated.wire_bytes(),
    )
}

/// Independently verify one candidate descriptor as the one concrete,
/// classifier-admitted endpoint of a checked program. This is the only
/// constructor for [`AdmittedPublicGenericEndpointV1`] exposed outside this
/// module.
pub fn replay_admitted_public_generic_endpoint_v1(
    program: &ResolvedProgram,
    source_revision: &str,
    expected_export_id: &str,
    candidate_descriptor_bytes: &[u8],
) -> Result<AdmittedPublicGenericEndpointV1, Diagnostic> {
    let subject = classifier::classify(program, expected_export_id)
        .map_err(|refusal| refusal.diagnostic())?;
    let expected_program_root_digest = independently_recomputed_program_root_digest(program);
    let descriptor = verify_public_generic_descriptor(
        program,
        source_revision,
        expected_export_id,
        &expected_program_root_digest,
        candidate_descriptor_bytes,
        &VerificationOptions::default(),
    )?;
    classifier_and_descriptor_agree(&subject, &descriptor)?;
    Ok(AdmittedPublicGenericEndpointV1 {
        subject,
        descriptor,
    })
}

fn classifier_and_descriptor_agree(
    subject: &AdmittedSubject,
    descriptor: &VerifiedPublicGenericDescriptor,
) -> Result<(), Diagnostic> {
    if subject.export_id() != descriptor.export_id()
        || subject.input() != descriptor.input_facts()
        || subject.result() != descriptor.result_facts()
        || subject.settlement() != descriptor.settlement()
    {
        return Err(Diagnostic::io(
            GENERATOR_DISAGREEMENT,
            "public-generic Wasm provider admission's classifier facts disagree with its independently verified descriptor",
        ));
    }
    Ok(())
}

fn independently_recomputed_program_root_digest(program: &ResolvedProgram) -> String {
    let mut identities = Vec::new();
    identities.extend(
        program
            .types
            .iter()
            .map(|declaration| declaration.id.as_str()),
    );
    identities.extend(
        program
            .function_templates
            .iter()
            .map(|declaration| declaration.id.as_str()),
    );
    identities.extend(
        program
            .functions
            .iter()
            .map(|function| function.id.as_str()),
    );
    identities.extend(
        program
            .function_instances
            .iter()
            .map(|instance| instance.id.as_str()),
    );
    identities.sort_unstable();
    identities.dedup();

    let mut preimage = Vec::new();
    frame(&mut preimage, &(identities.len() as u64).to_le_bytes());
    for identity in identities {
        frame(&mut preimage, identity.as_bytes());
    }
    digest(PROGRAM_ROOT_DOMAIN, &preimage)
}
