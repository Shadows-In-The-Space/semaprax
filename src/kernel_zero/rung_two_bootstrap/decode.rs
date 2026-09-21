//! Independent bounded decoder and exact compiler replay for bootstrap bytes.

use sha2::{Digest, Sha256};

use crate::hir::DeclarationId;
use crate::kernel_zero::reify::BoundTranslation;
use crate::kernel_zero::term::{KernelProgram, KernelType, Term};

use super::artifact::{
    compile_component, component_defs, digest, Artifact, BootstrapRefusal, Component,
    COMPONENT_COUNT, MAGIC, MAX_ARTIFACT_BYTES, MAX_COMPONENT_BYTES, MAX_TEXT_BYTES, SCHEMA,
    TARGET_PROFILE,
};

const CARGO_LOCK: &[u8] = include_bytes!("../../../Cargo.lock");
const TERM_MAGIC: &[u8] = b"SPX-KERNEL-TERM-V1\0";
const MAX_TERM_BYTES: usize = 512 * 1024;
const MAX_TERM_FUNCTIONS: usize = 64;
const MAX_TERM_NODES: usize = 8192;
const MAX_TERM_DEPTH: usize = 128;

/// Decode a closed artifact and re-run the ordinary source → HIR → Kernel-0,
/// C11-source, and raw-Core-Wasm routes before accepting any retained byte.
///
/// The decoder does not make an artifact executable and does not give it
/// formatter authority.  It only authenticates a candidate as reproducible
/// evidence for the five exact embedded component sources.
pub(crate) fn decode_and_replay(bytes: &[u8]) -> Result<[u8; 32], BootstrapRefusal> {
    if bytes.len() > MAX_ARTIFACT_BYTES || bytes.len() < MAGIC.len() + 32 {
        return Err(BootstrapRefusal::Bounds);
    }
    let (body, supplied_digest) = bytes.split_at(bytes.len() - 32);
    if Sha256::digest(body).as_slice() != supplied_digest {
        return Err(BootstrapRefusal::Digest);
    }
    let mut reader = Reader::new(body);
    if reader.take_exact(MAGIC.len())? != MAGIC {
        return Err(BootstrapRefusal::Encoding);
    }
    if reader.text()? != SCHEMA || reader.text()? != TARGET_PROFILE {
        return Err(BootstrapRefusal::Encoding);
    }
    if reader.take_exact(32)? != digest(CARGO_LOCK) {
        return Err(BootstrapRefusal::Drift);
    }
    if usize::from(reader.byte()?) != COMPONENT_COUNT {
        return Err(BootstrapRefusal::Encoding);
    }
    for expected in component_defs() {
        let decoded = decode_component(&mut reader)?;
        if decoded.name != expected.name
            || decoded.source_name != expected.source_name
            || decoded.source != expected.source.as_bytes()
            || decoded.entry != expected.entry
        {
            return Err(BootstrapRefusal::Drift);
        }
        let decoded_term = decode_term(&decoded.term)?;
        if reencode_term(&decoded_term)? != decoded.term {
            return Err(BootstrapRefusal::TermEncoding);
        }
        // This calls the compiler's ordinary parser, resolver, exact-source
        // BoundTranslation replay, C source emitter, and raw Wasm emitter.
        // None of the decoded term or target bytes are trusted merely because
        // their in-artifact digest happened to match.
        let regenerated = compile_component(&expected)?;
        let regenerated_term = regenerate_term(&expected)?;
        if decoded.term != regenerated_term
            || decoded.c_source != regenerated.c_source
            || decoded.wasm != regenerated.wasm
        {
            return Err(BootstrapRefusal::Drift);
        }
    }
    if !reader.finished() {
        return Err(BootstrapRefusal::Encoding);
    }
    Ok(digest(bytes))
}

fn decode_component(reader: &mut Reader<'_>) -> Result<Component, BootstrapRefusal> {
    let name = reader.text()?;
    let source_name = reader.text()?;
    let source = reader.blob()?;
    reader.digest_for(&source)?;
    let entry = reader.text()?;
    let term = reader.blob()?;
    reader.digest_for(&term)?;
    let c_source = reader.blob()?;
    reader.digest_for(&c_source)?;
    let wasm = reader.blob()?;
    reader.digest_for(&wasm)?;
    Ok(Component {
        name,
        source_name,
        source,
        entry,
        term,
        c_source,
        wasm,
    })
}

fn regenerate_term(expected: &super::artifact::ComponentDef) -> Result<Vec<u8>, BootstrapRefusal> {
    let entry = DeclarationId::new(expected.entry);
    let binding =
        BoundTranslation::derive(expected.source, &entry).map_err(|_| BootstrapRefusal::Profile)?;
    let program = binding
        .replay(expected.source, &entry)
        .map_err(|_| BootstrapRefusal::Drift)?;
    encode_kernel_program(program)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DecodedProgram {
    functions: Vec<DecodedFunction>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DecodedFunction {
    id: String,
    params: Vec<(String, u8)>,
    return_type: u8,
    body: DecodedTerm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DecodedTerm {
    Int(i64),
    Bool(bool),
    Var(String),
    Unary(u8, Box<Self>),
    Binary(u8, Box<Self>, Box<Self>),
    If(Box<Self>, Box<Self>, Box<Self>),
    Let(String, Box<Self>, Box<Self>),
    Call(String, Vec<Self>),
}

fn decode_term(bytes: &[u8]) -> Result<DecodedProgram, BootstrapRefusal> {
    if bytes.len() > MAX_TERM_BYTES {
        return Err(BootstrapRefusal::TermBounds);
    }
    let mut reader = Reader::new(bytes);
    if reader.take_exact(TERM_MAGIC.len())? != TERM_MAGIC {
        return Err(BootstrapRefusal::TermEncoding);
    }
    let function_count = usize::from(reader.byte()?);
    if function_count == 0 || function_count > MAX_TERM_FUNCTIONS {
        return Err(BootstrapRefusal::TermBounds);
    }
    let mut functions = Vec::with_capacity(function_count);
    let mut ids = std::collections::BTreeSet::new();
    let mut nodes = 0usize;
    for _ in 0..function_count {
        let id = reader.text()?;
        if !ids.insert(id.clone()) {
            return Err(BootstrapRefusal::TermEncoding);
        }
        let parameter_count = usize::from(reader.byte()?);
        let mut params = Vec::with_capacity(parameter_count);
        let mut parameter_ids = std::collections::BTreeSet::new();
        for _ in 0..parameter_count {
            let parameter = reader.text()?;
            if !parameter_ids.insert(parameter.clone()) {
                return Err(BootstrapRefusal::TermEncoding);
            }
            params.push((parameter, read_type_tag(&mut reader)?));
        }
        let return_type = read_type_tag(&mut reader)?;
        let body = decode_term_node(&mut reader, 0, &mut nodes)?;
        functions.push(DecodedFunction {
            id,
            params,
            return_type,
            body,
        });
    }
    if !reader.finished() {
        return Err(BootstrapRefusal::TermEncoding);
    }
    Ok(DecodedProgram { functions })
}

fn decode_term_node(
    reader: &mut Reader<'_>,
    depth: usize,
    nodes: &mut usize,
) -> Result<DecodedTerm, BootstrapRefusal> {
    if depth > MAX_TERM_DEPTH || *nodes >= MAX_TERM_NODES {
        return Err(BootstrapRefusal::TermBounds);
    }
    *nodes += 1;
    match reader.byte()? {
        1 => Ok(DecodedTerm::Int(reader.i64()?)),
        2 => match reader.byte()? {
            0 => Ok(DecodedTerm::Bool(false)),
            1 => Ok(DecodedTerm::Bool(true)),
            _ => Err(BootstrapRefusal::TermEncoding),
        },
        3 => Ok(DecodedTerm::Var(reader.text()?)),
        4 => {
            let op = reader.byte()?;
            if !(1..=2).contains(&op) {
                return Err(BootstrapRefusal::TermEncoding);
            }
            Ok(DecodedTerm::Unary(
                op,
                Box::new(decode_term_node(reader, depth + 1, nodes)?),
            ))
        }
        5 => {
            let op = reader.byte()?;
            if !(1..=13).contains(&op) {
                return Err(BootstrapRefusal::TermEncoding);
            }
            Ok(DecodedTerm::Binary(
                op,
                Box::new(decode_term_node(reader, depth + 1, nodes)?),
                Box::new(decode_term_node(reader, depth + 1, nodes)?),
            ))
        }
        6 => Ok(DecodedTerm::If(
            Box::new(decode_term_node(reader, depth + 1, nodes)?),
            Box::new(decode_term_node(reader, depth + 1, nodes)?),
            Box::new(decode_term_node(reader, depth + 1, nodes)?),
        )),
        7 => Ok(DecodedTerm::Let(
            reader.text()?,
            Box::new(decode_term_node(reader, depth + 1, nodes)?),
            Box::new(decode_term_node(reader, depth + 1, nodes)?),
        )),
        8 => {
            let callee = reader.text()?;
            let count = usize::from(reader.byte()?);
            let mut args = Vec::with_capacity(count);
            for _ in 0..count {
                args.push(decode_term_node(reader, depth + 1, nodes)?);
            }
            Ok(DecodedTerm::Call(callee, args))
        }
        _ => Err(BootstrapRefusal::TermEncoding),
    }
}

fn read_type_tag(reader: &mut Reader<'_>) -> Result<u8, BootstrapRefusal> {
    let tag = reader.byte()?;
    match tag {
        1 | 2 => Ok(tag),
        _ => Err(BootstrapRefusal::TermEncoding),
    }
}

fn reencode_term(program: &DecodedProgram) -> Result<Vec<u8>, BootstrapRefusal> {
    let mut bytes = TERM_MAGIC.to_vec();
    bytes.push(u8::try_from(program.functions.len()).map_err(|_| BootstrapRefusal::TermBounds)?);
    let mut nodes = 0usize;
    for function in &program.functions {
        push_term_text(&mut bytes, &function.id)?;
        bytes.push(u8::try_from(function.params.len()).map_err(|_| BootstrapRefusal::TermBounds)?);
        for (id, ty) in &function.params {
            push_term_text(&mut bytes, id)?;
            bytes.push(*ty);
        }
        bytes.push(function.return_type);
        reencode_term_node(&mut bytes, &function.body, 0, &mut nodes)?;
    }
    if bytes.len() > MAX_TERM_BYTES {
        return Err(BootstrapRefusal::TermBounds);
    }
    Ok(bytes)
}

fn reencode_term_node(
    bytes: &mut Vec<u8>,
    term: &DecodedTerm,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), BootstrapRefusal> {
    if depth > MAX_TERM_DEPTH || *nodes >= MAX_TERM_NODES {
        return Err(BootstrapRefusal::TermBounds);
    }
    *nodes += 1;
    match term {
        DecodedTerm::Int(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        DecodedTerm::Bool(value) => {
            bytes.push(2);
            bytes.push(u8::from(*value));
        }
        DecodedTerm::Var(id) => {
            bytes.push(3);
            push_term_text(bytes, id)?;
        }
        DecodedTerm::Unary(op, operand) => {
            bytes.extend([4, *op]);
            reencode_term_node(bytes, operand, depth + 1, nodes)?;
        }
        DecodedTerm::Binary(op, left, right) => {
            bytes.extend([5, *op]);
            reencode_term_node(bytes, left, depth + 1, nodes)?;
            reencode_term_node(bytes, right, depth + 1, nodes)?;
        }
        DecodedTerm::If(condition, then_branch, else_branch) => {
            bytes.push(6);
            reencode_term_node(bytes, condition, depth + 1, nodes)?;
            reencode_term_node(bytes, then_branch, depth + 1, nodes)?;
            reencode_term_node(bytes, else_branch, depth + 1, nodes)?;
        }
        DecodedTerm::Let(bound, value, body) => {
            bytes.push(7);
            push_term_text(bytes, bound)?;
            reencode_term_node(bytes, value, depth + 1, nodes)?;
            reencode_term_node(bytes, body, depth + 1, nodes)?;
        }
        DecodedTerm::Call(callee, arguments) => {
            bytes.push(8);
            push_term_text(bytes, callee)?;
            bytes.push(u8::try_from(arguments.len()).map_err(|_| BootstrapRefusal::TermBounds)?);
            for argument in arguments {
                reencode_term_node(bytes, argument, depth + 1, nodes)?;
            }
        }
    }
    Ok(())
}

fn encode_kernel_program(program: &KernelProgram) -> Result<Vec<u8>, BootstrapRefusal> {
    if program.functions.is_empty() || program.functions.len() > MAX_TERM_FUNCTIONS {
        return Err(BootstrapRefusal::Profile);
    }
    let mut bytes = TERM_MAGIC.to_vec();
    bytes.push(u8::try_from(program.functions.len()).map_err(|_| BootstrapRefusal::TermBounds)?);
    let mut nodes = 0usize;
    for function in &program.functions {
        push_term_text(&mut bytes, function.id.as_str())?;
        bytes.push(u8::try_from(function.params.len()).map_err(|_| BootstrapRefusal::TermBounds)?);
        for (id, ty) in &function.params {
            push_term_text(&mut bytes, id.as_str())?;
            bytes.push(kernel_type_tag(*ty));
        }
        bytes.push(kernel_type_tag(function.return_type));
        encode_kernel_term(&mut bytes, &function.body, 0, &mut nodes)?;
    }
    if bytes.len() > MAX_TERM_BYTES {
        return Err(BootstrapRefusal::TermBounds);
    }
    Ok(bytes)
}

fn encode_kernel_term(
    bytes: &mut Vec<u8>,
    term: &Term,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), BootstrapRefusal> {
    if depth > MAX_TERM_DEPTH || *nodes >= MAX_TERM_NODES {
        return Err(BootstrapRefusal::TermBounds);
    }
    *nodes += 1;
    match term {
        Term::Int(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Term::Bool(value) => bytes.extend([2, u8::from(*value)]),
        Term::Var(id) => {
            bytes.push(3);
            push_term_text(bytes, id.as_str())?;
        }
        Term::Unary(op, operand) => {
            bytes.extend([
                4,
                match op {
                    crate::ast::UnaryOp::Neg => 1,
                    crate::ast::UnaryOp::Not => 2,
                },
            ]);
            encode_kernel_term(bytes, operand, depth + 1, nodes)?;
        }
        Term::Binary(op, left, right) => {
            bytes.extend([5, kernel_binary_tag(*op)]);
            encode_kernel_term(bytes, left, depth + 1, nodes)?;
            encode_kernel_term(bytes, right, depth + 1, nodes)?;
        }
        Term::If {
            condition,
            then_branch,
            else_branch,
        } => {
            bytes.push(6);
            encode_kernel_term(bytes, condition, depth + 1, nodes)?;
            encode_kernel_term(bytes, then_branch, depth + 1, nodes)?;
            encode_kernel_term(bytes, else_branch, depth + 1, nodes)?;
        }
        Term::Let { bound, value, body } => {
            bytes.push(7);
            push_term_text(bytes, bound.as_str())?;
            encode_kernel_term(bytes, value, depth + 1, nodes)?;
            encode_kernel_term(bytes, body, depth + 1, nodes)?;
        }
        Term::Call { callee, args } => {
            bytes.push(8);
            push_term_text(bytes, callee.as_str())?;
            bytes.push(u8::try_from(args.len()).map_err(|_| BootstrapRefusal::TermBounds)?);
            for argument in args {
                encode_kernel_term(bytes, argument, depth + 1, nodes)?;
            }
        }
    }
    Ok(())
}

fn push_term_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), BootstrapRefusal> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || !value.is_ascii() {
        return Err(BootstrapRefusal::TermEncoding);
    }
    let length = u16::try_from(value.len()).map_err(|_| BootstrapRefusal::TermBounds)?;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

const fn kernel_type_tag(ty: KernelType) -> u8 {
    match ty {
        KernelType::I64 => 1,
        KernelType::Bool => 2,
    }
}

const fn kernel_binary_tag(op: crate::ast::BinaryOp) -> u8 {
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

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn finished(&self) -> bool {
        self.remaining.is_empty()
    }

    fn byte(&mut self) -> Result<u8, BootstrapRefusal> {
        self.take_exact(1)
            .map(|bytes| bytes[0])
            .map_err(|_| BootstrapRefusal::Encoding)
    }

    fn text(&mut self) -> Result<String, BootstrapRefusal> {
        let length = self.u16()?;
        if length == 0 || usize::from(length) > MAX_TEXT_BYTES {
            return Err(BootstrapRefusal::Bounds);
        }
        let bytes = self.take_exact(usize::from(length))?;
        if !bytes.is_ascii() {
            return Err(BootstrapRefusal::Encoding);
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| BootstrapRefusal::Encoding)
    }

    fn blob(&mut self) -> Result<Vec<u8>, BootstrapRefusal> {
        let length = self.u32()?;
        let length = usize::try_from(length).map_err(|_| BootstrapRefusal::Bounds)?;
        if length > MAX_COMPONENT_BYTES {
            return Err(BootstrapRefusal::Bounds);
        }
        Ok(self.take_exact(length)?.to_vec())
    }

    fn digest_for(&mut self, value: &[u8]) -> Result<(), BootstrapRefusal> {
        let supplied = self.take_exact(32)?;
        if Sha256::digest(value).as_slice() != supplied {
            return Err(BootstrapRefusal::Digest);
        }
        Ok(())
    }

    fn u16(&mut self) -> Result<u16, BootstrapRefusal> {
        let bytes = self.take_exact(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, BootstrapRefusal> {
        let bytes = self.take_exact(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i64(&mut self) -> Result<i64, BootstrapRefusal> {
        let bytes = self.take_exact(8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn take_exact(&mut self, length: usize) -> Result<&'a [u8], BootstrapRefusal> {
        if self.remaining.len() < length {
            return Err(BootstrapRefusal::Encoding);
        }
        let (taken, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(taken)
    }
}

#[cfg(test)]
pub(super) fn reencode_for_test(components: &[Component]) -> Result<Vec<u8>, BootstrapRefusal> {
    super::artifact::encode(components)
}

#[cfg(test)]
pub(super) fn maximum_artifact_bytes() -> usize {
    MAX_ARTIFACT_BYTES
}

#[cfg(test)]
pub(super) fn maximum_term_bytes() -> usize {
    MAX_TERM_BYTES
}
