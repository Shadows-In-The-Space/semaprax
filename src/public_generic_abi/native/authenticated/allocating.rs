//! Private reservation-backed Bytes body profile, not a public ABI/support claim.
use super::*;

pub const ALLOCATING_PROFILE: &str = "semaprax.authenticated-native-allocating.v1";

pub struct AuthenticatedNativeAllocatingArtifact {
    inner: AuthenticatedNativeIdentityArtifact,
}

impl AuthenticatedNativeAllocatingArtifact {
    pub fn source(&self) -> &str {
        self.inner.source()
    }
    pub fn descriptor_bytes(&self) -> &[u8] {
        self.inner.descriptor_bytes()
    }
    pub fn binding(&self) -> &NativeProviderBindingV1 {
        self.inner.binding()
    }
}

pub fn render_authenticated_allocating_provider(
    program: &ResolvedProgram,
    source_revision: &str,
    descriptor: &VerifiedPublicGenericDescriptor,
) -> Result<AuthenticatedNativeAllocatingArtifact, Diagnostic> {
    let (source, bridge) = crate::codegen::emit_public_generic_allocating_bridge(
        program,
        source_revision,
        descriptor,
    )?;
    Ok(AuthenticatedNativeAllocatingArtifact {
        inner: render_admitted(
            descriptor,
            &source,
            &bridge,
            ALLOCATING_PROFILE,
            b"semaprax.authenticated-native-allocating.v1.runtime\0",
            b"semaprax.authenticated-native-allocating.v1.artifact\0",
            "spx_pg_endpoint_checked_allocating_v1(",
        )?,
    })
}
