//! Canonical producer for the private Rung-2 bootstrap artifact.

use sha2::{Digest, Sha256};

use crate::hir::DeclarationId;
use crate::kernel_zero::reify::BoundTranslation;
use crate::kernel_zero::term::{KernelProgram, KernelType, Term};
use crate::{codegen, hir, wasm};

pub(super) const SCHEMA: &str = "semaprax.kernel-zero-rung-two-bootstrap.v2";
pub(super) const MAGIC: &[u8; 8] = b"SPXR2BT\0";
pub(super) const TARGET_PROFILE: &str = "c11-source+raw-core-wasm+private-scalar-export-core-wasm";
pub(super) const MAX_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
pub(super) const MAX_COMPONENT_BYTES: usize = 1024 * 1024;
pub(super) const MAX_TEXT_BYTES: usize = 256;
const MAX_TERM_BYTES: usize = 512 * 1024;
const MAX_NODES: usize = 8192;
const MAX_DEPTH: usize = 128;
const CARGO_LOCK: &[u8] = include_bytes!("../../../Cargo.lock");

pub(super) const COMPONENT_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapRefusal {
    Profile,
    Bounds,
    Encoding,
    Digest,
    Drift,
    Target,
    TermEncoding,
    TermBounds,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Artifact {
    bytes: Vec<u8>,
    digest: [u8; 32],
    components: Vec<Component>,
}

impl Artifact {
    pub(crate) fn derive() -> Result<Self, BootstrapRefusal> {
        let components = component_defs()
            .iter()
            .map(compile_component)
            .collect::<Result<Vec<_>, _>>()?;
        let bytes = encode(&components)?;
        let digest = digest(&bytes);
        Ok(Self {
            bytes,
            digest,
            components,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[cfg(test)]
    pub(super) fn components(&self) -> &[Component] {
        &self.components
    }
}

#[derive(Clone, Copy)]
pub(super) struct ComponentDef {
    pub(super) name: &'static str,
    pub(super) source_name: &'static str,
    pub(super) source: &'static str,
    pub(super) entry: &'static str,
    pub(super) length_entry: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Component {
    pub(super) name: String,
    pub(super) source_name: String,
    pub(super) source: Vec<u8>,
    pub(super) entry: String,
    pub(super) term: Vec<u8>,
    pub(super) c_source: Vec<u8>,
    pub(super) wasm: Vec<u8>,
    pub(super) execution_wasm: Vec<u8>,
}

pub(super) fn component_defs() -> [ComponentDef; COMPONENT_COUNT] {
    [
        ComponentDef {
            name: "char",
            source_name: "canonical_char_renderer.spx",
            source: include_str!("../canonical_char_renderer.spx"),
            entry: "format.render-byte",
            length_entry: "format.render-length",
        },
        ComponentDef {
            name: "bool",
            source_name: "canonical_bool_renderer.spx",
            source: include_str!("../canonical_bool_renderer.spx"),
            entry: "format.render-byte",
            length_entry: "format.render-length",
        },
        ComponentDef {
            name: "int",
            source_name: "canonical_int_renderer.spx",
            source: include_str!("../canonical_int_renderer.spx"),
            entry: "format.render-byte",
            length_entry: "format.render-length",
        },
        ComponentDef {
            name: "operator",
            source_name: "canonical_operator_renderer.spx",
            source: include_str!("../canonical_operator_renderer.spx"),
            entry: "format.operator-render-byte",
            length_entry: "format.operator-render-length",
        },
        ComponentDef {
            name: "string-scalar",
            source_name: "canonical_string_renderer.spx",
            source: include_str!("../canonical_string_renderer.spx"),
            entry: "format.render-byte",
            length_entry: "format.render-length",
        },
    ]
}

/// Derive the retained private scalar-export Core-Wasm target companion.
/// It has only the closed length/byte wrappers and is not a public package,
/// component ABI, or formatter authority route.
pub(super) fn compile_execution_wasm(def: &ComponentDef) -> Result<Vec<u8>, BootstrapRefusal> {
    let parsed =
        crate::parse(def.source, def.source_name).map_err(|_| BootstrapRefusal::Profile)?;
    let resolved = hir::resolve(&parsed).map_err(|_| BootstrapRefusal::Profile)?;
    let bytes = wasm::emit_resolved_module_with_scalar_exports(
        &resolved,
        &[def.length_entry.to_owned(), def.entry.to_owned()],
    )
    .map_err(|_| BootstrapRefusal::Target)?;
    if bytes.len() > MAX_COMPONENT_BYTES {
        return Err(BootstrapRefusal::Bounds);
    }
    Ok(bytes)
}

pub(super) fn compile_component(def: &ComponentDef) -> Result<Component, BootstrapRefusal> {
    if def.source.len() > 64 * 1024
        || def.name.len() > MAX_TEXT_BYTES
        || def.source_name.len() > MAX_TEXT_BYTES
        || def.entry.len() > MAX_TEXT_BYTES
        || def.length_entry.len() > MAX_TEXT_BYTES
    {
        return Err(BootstrapRefusal::Bounds);
    }
    let parsed =
        crate::parse(def.source, def.source_name).map_err(|_| BootstrapRefusal::Profile)?;
    let resolved = hir::resolve(&parsed).map_err(|_| BootstrapRefusal::Profile)?;
    let entry = DeclarationId::new(def.entry);
    let binding =
        BoundTranslation::derive(def.source, &entry).map_err(|_| BootstrapRefusal::Profile)?;
    let program = binding
        .replay(def.source, &entry)
        .map_err(|_| BootstrapRefusal::Drift)?;
    let term = encode_program(program)?;
    let c_source = codegen::emit_hir_c(&resolved)
        .map_err(|_| BootstrapRefusal::Target)?
        .into_bytes();
    let wasm = wasm::emit_module(&parsed).map_err(|_| BootstrapRefusal::Target)?;
    let execution_wasm = compile_execution_wasm(def)?;
    for payload in [&term, &c_source, &wasm, &execution_wasm] {
        if payload.len() > MAX_COMPONENT_BYTES {
            return Err(BootstrapRefusal::Bounds);
        }
    }
    Ok(Component {
        name: def.name.to_owned(),
        source_name: def.source_name.to_owned(),
        source: def.source.as_bytes().to_vec(),
        entry: def.entry.to_owned(),
        term,
        c_source,
        wasm,
        execution_wasm,
    })
}

pub(super) fn encode(components: &[Component]) -> Result<Vec<u8>, BootstrapRefusal> {
    if components.len() != COMPONENT_COUNT {
        return Err(BootstrapRefusal::Encoding);
    }
    let mut body = Vec::new();
    body.extend_from_slice(MAGIC);
    push_text(&mut body, SCHEMA)?;
    push_text(&mut body, TARGET_PROFILE)?;
    body.extend_from_slice(&digest(CARGO_LOCK));
    body.push(COMPONENT_COUNT as u8);
    for component in components {
        push_text(&mut body, &component.name)?;
        push_text(&mut body, &component.source_name)?;
        push_blob(&mut body, &component.source)?;
        body.extend_from_slice(&digest(&component.source));
        push_text(&mut body, &component.entry)?;
        push_blob(&mut body, &component.term)?;
        body.extend_from_slice(&digest(&component.term));
        push_blob(&mut body, &component.c_source)?;
        body.extend_from_slice(&digest(&component.c_source));
        push_blob(&mut body, &component.wasm)?;
        body.extend_from_slice(&digest(&component.wasm));
        push_blob(&mut body, &component.execution_wasm)?;
        body.extend_from_slice(&digest(&component.execution_wasm));
    }
    if body.len() > MAX_ARTIFACT_BYTES.saturating_sub(32) {
        return Err(BootstrapRefusal::Bounds);
    }
    let body_digest = digest(&body);
    body.extend_from_slice(&body_digest);
    Ok(body)
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn push_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), BootstrapRefusal> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || !value.is_ascii() {
        return Err(BootstrapRefusal::Encoding);
    }
    let length = u16::try_from(value.len()).map_err(|_| BootstrapRefusal::Bounds)?;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_blob(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), BootstrapRefusal> {
    if value.len() > MAX_COMPONENT_BYTES {
        return Err(BootstrapRefusal::Bounds);
    }
    let length = u32::try_from(value.len()).map_err(|_| BootstrapRefusal::Bounds)?;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

pub(super) fn encode_program(program: &KernelProgram) -> Result<Vec<u8>, BootstrapRefusal> {
    if program.functions.is_empty() || program.functions.len() > 64 {
        return Err(BootstrapRefusal::Profile);
    }
    let mut bytes = b"SPX-KERNEL-TERM-V1\0".to_vec();
    bytes.push(u8::try_from(program.functions.len()).map_err(|_| BootstrapRefusal::Bounds)?);
    let mut nodes = 0usize;
    for function in &program.functions {
        push_text(&mut bytes, function.id.as_str())?;
        bytes.push(u8::try_from(function.params.len()).map_err(|_| BootstrapRefusal::Bounds)?);
        for (id, ty) in &function.params {
            push_text(&mut bytes, id.as_str())?;
            bytes.push(type_tag(*ty));
        }
        bytes.push(type_tag(function.return_type));
        encode_term(&mut bytes, &function.body, 0, &mut nodes)?;
    }
    if bytes.len() > MAX_TERM_BYTES {
        return Err(BootstrapRefusal::Bounds);
    }
    Ok(bytes)
}

fn encode_term(
    bytes: &mut Vec<u8>,
    term: &Term,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), BootstrapRefusal> {
    if depth > MAX_DEPTH || *nodes >= MAX_NODES {
        return Err(BootstrapRefusal::Bounds);
    }
    *nodes += 1;
    match term {
        Term::Int(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Term::Bool(value) => {
            bytes.push(2);
            bytes.push(u8::from(*value));
        }
        Term::Var(id) => {
            bytes.push(3);
            push_text(bytes, id.as_str())?;
        }
        Term::Unary(op, operand) => {
            bytes.push(4);
            bytes.push(match op {
                crate::ast::UnaryOp::Neg => 1,
                crate::ast::UnaryOp::Not => 2,
            });
            encode_term(bytes, operand, depth + 1, nodes)?;
        }
        Term::Binary(op, left, right) => {
            bytes.push(5);
            bytes.push(binary_tag(*op));
            encode_term(bytes, left, depth + 1, nodes)?;
            encode_term(bytes, right, depth + 1, nodes)?;
        }
        Term::If {
            condition,
            then_branch,
            else_branch,
        } => {
            bytes.push(6);
            encode_term(bytes, condition, depth + 1, nodes)?;
            encode_term(bytes, then_branch, depth + 1, nodes)?;
            encode_term(bytes, else_branch, depth + 1, nodes)?;
        }
        Term::Let { bound, value, body } => {
            bytes.push(7);
            push_text(bytes, bound.as_str())?;
            encode_term(bytes, value, depth + 1, nodes)?;
            encode_term(bytes, body, depth + 1, nodes)?;
        }
        Term::Call { callee, args } => {
            bytes.push(8);
            push_text(bytes, callee.as_str())?;
            bytes.push(u8::try_from(args.len()).map_err(|_| BootstrapRefusal::Bounds)?);
            for argument in args {
                encode_term(bytes, argument, depth + 1, nodes)?;
            }
        }
    }
    Ok(())
}

const fn type_tag(ty: KernelType) -> u8 {
    match ty {
        KernelType::I64 => 1,
        KernelType::Bool => 2,
    }
}

const fn binary_tag(op: crate::ast::BinaryOp) -> u8 {
    match op {
        crate::ast::BinaryOp::Add => 1,
        crate::ast::BinaryOp::Sub => 2,
        crate::ast::BinaryOp::Mul => 3,
        crate::ast::BinaryOp::Div => 4,
        crate::ast::BinaryOp::Rem => 5,
        crate::ast::BinaryOp::Eq => 6,
        crate::ast::BinaryOp::Ne => 7,
        crate::ast::BinaryOp::Lt => 8,
        crate::ast::BinaryOp::Le => 9,
        crate::ast::BinaryOp::Gt => 10,
        crate::ast::BinaryOp::Ge => 11,
        crate::ast::BinaryOp::And => 12,
        crate::ast::BinaryOp::Or => 13,
    }
}
