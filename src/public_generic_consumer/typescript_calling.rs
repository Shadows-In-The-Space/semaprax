//! Generates a real, standalone TypeScript/Wasm *calling* consumer package
//! (issue #157), answering the TypeScript half of PG-5/PG-6's *calling* gate
//! that [`super::rust_calling`] already answered for Rust (issue #156).
//!
//! This is not the metadata-only TypeScript consumer [`super::typescript`]
//! emits: that consumer never allocates, transfers, or calls anything, and
//! exists only so a human can see the substituted field tree. A package
//! generated here does the opposite: it embeds one trusted descriptor and
//! [`WasmProviderBindingV1`], independently verifies both before any Wasm
//! allocation, encodes one concrete owned input record into [Logical
//! Carrier v1](../../docs/PUBLIC-GENERIC-CARRIER-V1.md) bytes, transfers it
//! into real `WebAssembly.Memory`, calls the one endpoint export [Core Wasm
//! physical
//! adapter](../../docs/PUBLIC-GENERIC-CARRIER-V1.md#core-wasm-physical-adapter-issue-155)
//! already names (`FIXTURE_ENDPOINT_EXPORT_NAME` in
//! `public_generic_abi::wasm::provider`), and decodes and independently
//! validates the result.
//!
//! **Scope, stated once, mirroring [`super::rust_calling`]'s own module
//! documentation exactly.** [Public Generic Boundary Profile
//! v1](../../docs/PUBLIC-GENERIC-BOUNDARY-PROFILE-V1.md) admits exactly one
//! owned aggregate input parameter and one owned aggregate result in v1, so
//! this generator emits exactly two concrete TypeScript interfaces, `Input`
//! and `Output`. The bound endpoint only implements "the existing
//! owned-Bytes shapes... a flat sequence of independent owned `Bytes`
//! leaves" until issue #119 unblocks a real checked generic export, so
//! every field this generator emits is an owned `Uint8Array` leaf; a Copy
//! scalar or nested-record leaf is future work tracked by that same
//! prerequisite, not a limitation invented here.
//!
//! The generated `wasm-provider.ts` now authenticates and instantiates the
//! compiler-owned zero-import provider artifact. For the compiled binding it
//! delegates scratch, open/prepare/call/export, handles, and release/close
//! transitions to that module; that selected route uses no host allocator or
//! provider state machine. The generated file deliberately retains the
//! explicit reference-provider route for its older fixture and settlement
//! corpora, with no fallback between the two bindings.
//! `carrier.ts` emits the canonical descriptor-bound Logical Carrier v1 frame,
//! so the generated package executes the complete lifecycle against the
//! compiled provider artifact.
//!
//! Determinism and authority: like [`super::rust_calling::generate_rust_calling_consumer`],
//! this is a pure function from already-trusted bytes to source text. It
//! reads no file, starts no process, and uses no network.

use crate::public_generic_abi::wasm::binding::WasmProviderBindingV1;

use super::identifier;
use super::rust_calling::{OwnedByteField, RecordShape, ShapeError};

/// One generated file's relative path and deterministic contents, in
/// emission order. Mirrors [`super::rust_calling::CallingConsumer`] exactly,
/// as an independent type: the two generators never share mutable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallingConsumer {
    files: Vec<(String, String)>,
}

impl CallingConsumer {
    pub fn files(&self) -> &[(String, String)] {
        &self.files
    }
}

/// The package name every generated calling consumer uses in `package.json`
/// and `package-lock.json`, so the two never drift from each other or from
/// this generator's own doc comments.
pub const PACKAGE_NAME: &str = "generated-typescript-wasm-consumer";

fn field_name(field: &OwnedByteField) -> String {
    format!("field_{}", identifier(&field.identity))
}

/// Reimplemented locally rather than calling
/// [`RecordShape`]'s own (private-to-`rust_calling`) duplicate check: this
/// module must not modify `rust_calling.rs` to widen that method's
/// visibility, and the check itself is three lines of already-public field
/// access.
fn duplicate_identity(shape: &RecordShape) -> Option<&str> {
    for (index, field) in shape.fields.iter().enumerate() {
        if shape.fields[..index]
            .iter()
            .any(|earlier| earlier.identity == field.identity)
        {
            return Some(&field.identity);
        }
    }
    None
}

/// Generate one TypeScript/Wasm calling consumer package for
/// `descriptor_bytes` and `binding`, admitting exactly `input`/`output` as
/// the one owned input parameter and one owned result [Public Generic
/// Boundary Profile v1](../../docs/PUBLIC-GENERIC-BOUNDARY-PROFILE-V1.md)
/// admits in v1.
///
/// Deterministic: the same arguments always produce byte-identical files.
pub fn generate_typescript_calling_consumer(
    descriptor_bytes: &[u8],
    binding: &WasmProviderBindingV1,
    input: &RecordShape,
    output: &RecordShape,
) -> Result<CallingConsumer, ShapeError> {
    if let Some(identity) = duplicate_identity(input) {
        return Err(ShapeError::DuplicateFieldIdentity {
            record: "Input",
            identity: identity.to_owned(),
        });
    }
    if let Some(identity) = duplicate_identity(output) {
        return Err(ShapeError::DuplicateFieldIdentity {
            record: "Output",
            identity: identity.to_owned(),
        });
    }
    if input.fields.len() != output.fields.len() {
        return Err(ShapeError::LeafCountMismatch {
            input: input.fields.len(),
            output: output.fields.len(),
        });
    }

    if input.fields.is_empty() || input.fields.len() > 256 {
        return Err(ShapeError::LeafCountOutOfBounds {
            count: input.fields.len(),
        });
    }

    let binding_bytes = binding.encode();
    let files = vec![
        ("package.json".to_owned(), render::package_json()),
        ("package-lock.json".to_owned(), render::package_lock_json()),
        ("tsconfig.json".to_owned(), render::tsconfig_json()),
        ("src/errors.ts".to_owned(), render::errors_ts()),
        (
            "src/descriptor.ts".to_owned(),
            render::descriptor_ts(descriptor_bytes, &binding_bytes, binding),
        ),
        ("src/types.ts".to_owned(), render::types_ts(input, output)),
        (
            "src/carrier.ts".to_owned(),
            render::carrier_ts(descriptor_bytes, input, output),
        ),
        (
            "src/wasm-provider.ts".to_owned(),
            render::wasm_provider_ts(),
        ),
        ("src/index.ts".to_owned(), render::index_ts()),
        (
            "test/round-trip.mjs".to_owned(),
            render::round_trip_mjs(input, output),
        ),
    ];
    Ok(CallingConsumer { files })
}

mod render;

#[cfg(test)]
mod tests;
