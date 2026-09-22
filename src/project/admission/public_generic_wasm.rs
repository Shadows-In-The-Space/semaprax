//! Authority-free Project admission for the future public-generic Core Wasm
//! provider target. It retains only a compiler-derived, independently verified
//! endpoint; no Wasm bytes, runtime, package, or publication route exists yet.

use crate::diagnostic::Diagnostic;
use crate::hir::ResolvedProgram;
use crate::public_generic_abi::compiler_endpoint::{
    derive_admitted_public_generic_endpoint_v1, AdmittedPublicGenericEndpointV1,
};

use super::super::{ProjectManifest, PublicApiSubject};

pub(super) fn prepare(
    program: &ResolvedProgram,
    manifest: &ProjectManifest,
    subject: PublicApiSubject<'_>,
) -> Result<AdmittedPublicGenericEndpointV1, Diagnostic> {
    let [export_id] = manifest.web_exports() else {
        return Err(Diagnostic::io(
            "SPX-J105",
            "public-generic-wasm-provider.v1 requires exactly one selected concrete web export",
        ));
    };
    // `project_revision` is the authenticated canonical Project source
    // projection for this linked program. The endpoint constructor binds it
    // into the descriptor and verifies the descriptor against this exact HIR.
    derive_admitted_public_generic_endpoint_v1(program, subject.project_revision, export_id)
}
