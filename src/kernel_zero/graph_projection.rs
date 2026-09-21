//! Private finite-corpus correspondence between real graph bytes and Kernel-0.
//!
//! This consumes the existing graph v10 projection; it introduces no wire
//! format, compiler admission rule, authority, or proof of the renderer. The
//! independent decoder checks every selected signature and complete body against
//! exact-source reification, including structural value identities and authored
//! child order. Expression identities are checked for uniqueness, not promoted
//! to persistent identities. Display names and source/module location are not
//! logical declaration identity.
//!
//! Cleanup plans, prelude/type-fact tables, display metadata and declarations
//! outside the selected call closure remain opaque byte-bound payload. Their
//! semantics are not proved by this correspondence check.

use sha2::{Digest, Sha256};

use crate::hir::DeclarationId;

use super::reify::{BoundTranslation, Refusal};
use super::term::KernelType;

#[path = "graph_projection/decode.rs"]
mod decode;

const MAX_SOURCE_BYTES: usize = 65_536;
const MAX_GRAPH_BYTES: usize = 8 * 1024 * 1024;
const MAX_FUNCTIONS: usize = 64;
const MAX_NODES: usize = 8_192;
const MAX_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProjectionError {
    Capacity,
    Translation(Refusal),
    Graph,
    Json,
    DuplicateKey,
    Schema,
    Shape,
    Identity,
    UnstableIdentity,
    Inventory,
    Type,
    Expression,
    Calls,
    Binding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FunctionFact {
    id: String,
    parameters: Vec<KernelType>,
    result: KernelType,
    // Syntactic preorder, including duplicates, lazy branches and arguments.
    // This is deliberately not a claim about runtime call execution order.
    call_occurrences: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProjectionFacts {
    // Canonical stable-ID ordering, independent of graph declaration order.
    functions: Vec<FunctionFact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundProjection {
    translation: BoundTranslation,
    graph_bytes: String,
    graph_digest: [u8; 32],
    facts: ProjectionFacts,
}

impl BoundProjection {
    fn derive(source: &str, entry: &DeclarationId) -> Result<Self, ProjectionError> {
        if source.len() > MAX_SOURCE_BYTES {
            return Err(ProjectionError::Capacity);
        }
        let translation =
            BoundTranslation::derive(source, entry).map_err(ProjectionError::Translation)?;
        let terms = translation
            .replay(source, entry)
            .map_err(ProjectionError::Translation)?;
        let parsed = crate::parse(source, "kernel-zero-graph-source.spx")
            .map_err(|_| ProjectionError::Graph)?;
        let graph_bytes = crate::graph::to_json(&parsed).map_err(|_| ProjectionError::Graph)?;
        let facts = decode::check(&graph_bytes, terms, entry)?;
        let graph_digest = graph_digest(graph_bytes.as_bytes());
        Ok(Self {
            translation,
            graph_bytes,
            graph_digest,
            facts,
        })
    }

    fn replay(
        &self,
        source: &str,
        entry: &DeclarationId,
        graph_bytes: &str,
    ) -> Result<&ProjectionFacts, ProjectionError> {
        if source.len() > MAX_SOURCE_BYTES || graph_bytes.len() > MAX_GRAPH_BYTES {
            return Err(ProjectionError::Capacity);
        }
        // Exact bytes are part of the evidence even when a JSON re-encoding has
        // the same decoded meaning. Re-minting hashes never replaces derivation.
        if self.graph_bytes != graph_bytes
            || self.graph_digest != graph_digest(graph_bytes.as_bytes())
        {
            return Err(ProjectionError::Binding);
        }
        if self != &Self::derive(source, entry)? {
            return Err(ProjectionError::Binding);
        }
        Ok(&self.facts)
    }
}

fn graph_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"semaprax.kernel-zero.graph-evidence.v1\0");
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

#[cfg(test)]
#[path = "graph_projection/source_tests.rs"]
mod source_tests;
#[cfg(test)]
#[path = "graph_projection/tests.rs"]
mod tests;
