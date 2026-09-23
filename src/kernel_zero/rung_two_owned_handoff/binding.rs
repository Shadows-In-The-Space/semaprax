//! Private exact-byte wrapper evidence. This is not a Project, ABI, release,
//! ownership theorem, or authority to execute a target.
use sha2::{Digest, Sha256};

use super::{ENTRY, MAX_BYTES, SOURCE};
use crate::hir::DeclarationId;
use crate::kernel_zero::{
    reify::BoundTranslation,
    rung_two_bootstrap::{canonical_term_bytes, renderer_core_definitions},
};

pub(super) const EXPORT: &str = "kernel-zero.owned-handoff.export";
const PROFILE: &str = "semaprax.kernel-zero-owned-handoff.private.v1";
const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
pub(super) struct Binding {
    pub(super) source: Vec<u8>,
    pub(super) entry: String,
    pub(super) maximum: u64,
    pub(super) core_sources: Vec<Vec<u8>>,
    pub(super) core_entries: Vec<String>,
    pub(super) core_terms: Vec<Vec<u8>>,
    pub(super) descriptor: Vec<u8>,
    pub(super) c_source: Vec<u8>,
    pub(super) wasm: Vec<u8>,
    pub(super) c_symbol: String,
}

impl Binding {
    pub(super) fn derive(program: &crate::hir::ResolvedProgram) -> Result<Self, ()> {
        let cores = renderer_core_definitions();
        let core_terms = cores
            .iter()
            .map(|(source, entry)| {
                let core_entry = DeclarationId::new(*entry);
                let binding = BoundTranslation::derive(source, &core_entry).map_err(|_| ())?;
                canonical_term_bytes(binding.replay(source, &core_entry).map_err(|_| ())?)
            })
            .collect::<Result<Vec<_>, ()>>()?;
        // These are a PRIVATE standalone-source subject, not claims of an
        // authenticated managed Project generation or release provenance.
        let revision = hex_digest(b"owned-handoff.source", SOURCE.as_bytes());
        let workspace = hex_digest(b"owned-handoff.entry", ENTRY.as_bytes());
        let graph = hex_digest(b"owned-handoff.profile", PROFILE.as_bytes());
        let subject = crate::project::PublicApiSubject {
            project_schema: "semaprax.project.v8",
            project_revision: &revision,
            workspace_revision: &workspace,
            project_graph_digest: &graph,
        };
        let selected = [EXPORT.to_owned()];
        let descriptor = crate::project::derive_public_api_descriptor(program, &selected, subject)
            .map_err(|_| ())?;
        let c = crate::codegen::emit_project_v8_native_owned_data_provider(
            program,
            &selected,
            subject,
            &descriptor.canonical_bytes(),
            &descriptor.digest(),
        )
        .map_err(|_| ())?;
        let wasm = crate::wasm::emit_resolved_module_with_owned_data_exports(program, &descriptor)
            .map_err(|_| ())?;
        wasmparser::Validator::new()
            .validate_all(&wasm)
            .map_err(|_| ())?;
        let c_symbol = crate::codegen::native_owned_data_provider_symbol(
            descriptor.exports()[0].rust_method_name(),
        );
        let result = Self {
            source: SOURCE.as_bytes().to_vec(),
            entry: ENTRY.to_owned(),
            maximum: MAX_BYTES as u64,
            core_sources: cores
                .iter()
                .map(|(source, _)| source.as_bytes().to_vec())
                .collect(),
            core_entries: cores.iter().map(|(_, entry)| (*entry).to_owned()).collect(),
            core_terms,
            descriptor: descriptor.canonical_bytes(),
            c_source: c.source().as_bytes().to_vec(),
            wasm,
            c_symbol,
        };
        result.bytes()?;
        Ok(result)
    }

    pub(super) fn bytes(&self) -> Result<Vec<u8>, ()> {
        let mut bytes = PROFILE.as_bytes().to_vec();
        fn append(output: &mut Vec<u8>, input: &[u8]) -> Result<(), ()> {
            let total = output
                .len()
                .checked_add(8)
                .and_then(|n| n.checked_add(input.len()))
                .ok_or(())?;
            if total > MAX_ARTIFACT_BYTES {
                return Err(());
            }
            output.extend_from_slice(&(input.len() as u64).to_le_bytes());
            output.extend_from_slice(input);
            Ok(())
        }
        append(&mut bytes, &self.source)?;
        append(&mut bytes, self.entry.as_bytes())?;
        append(&mut bytes, &self.maximum.to_le_bytes())?;
        if self.core_sources.len() != 5
            || self.core_entries.len() != 5
            || self.core_terms.len() != 5
        {
            return Err(());
        }
        for ((source, entry), term) in self
            .core_sources
            .iter()
            .zip(&self.core_entries)
            .zip(&self.core_terms)
        {
            append(&mut bytes, source)?;
            append(&mut bytes, entry.as_bytes())?;
            append(&mut bytes, term)?;
        }
        append(&mut bytes, &self.descriptor)?;
        append(&mut bytes, self.c_symbol.as_bytes())?;
        append(&mut bytes, &self.c_source)?;
        append(&mut bytes, &self.wasm)?;
        append(&mut bytes, include_bytes!("../../../Cargo.lock"))?;
        Ok(bytes)
    }

    /// A closed expected-byte verifier, not a permissive artifact parser.
    /// Length and digest are checked without copying or allocating members;
    /// exact comparison to the compiler-derived held snapshot is the authority.
    pub(super) fn authenticate(bytes: &[u8], digest: [u8; 32], expected: &[u8]) -> Result<(), ()> {
        if bytes.len() > MAX_ARTIFACT_BYTES
            || bytes.len() != expected.len()
            || digest != checksum(bytes)
            || bytes != expected
        {
            return Err(());
        }
        Ok(())
    }
}

pub(super) fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PROFILE.as_bytes());
    hash.update([0]);
    hash.update(bytes);
    hash.finalize().into()
}

fn hex_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(bytes);
    let mut result = String::from("sha256:");
    for byte in hash.finalize() {
        use std::fmt::Write as _;
        write!(result, "{byte:02x}").expect("String formatting");
    }
    result
}
