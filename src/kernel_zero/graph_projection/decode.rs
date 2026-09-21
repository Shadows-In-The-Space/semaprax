//! Independent, bounded graph-v10 reader. It calls no graph-rendering helper.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::ast::{BinaryOp, UnaryOp};
use crate::hir::{DeclarationId, FunctionExecutionId, ValueId};

use super::super::term::{KernelFn, KernelProgram, KernelType, Term};
use super::{
    FunctionFact, ProjectionError as E, ProjectionFacts, MAX_DEPTH, MAX_FUNCTIONS, MAX_GRAPH_BYTES,
    MAX_NODES,
};

pub(super) fn check(
    bytes: &str,
    expected: &KernelProgram,
    entry: &DeclarationId,
) -> Result<ProjectionFacts, E> {
    if bytes.len() > MAX_GRAPH_BYTES || expected.functions.len() > MAX_FUNCTIONS {
        return Err(E::Capacity);
    }
    // serde_json::Value alone silently collapses duplicate object keys. Scan
    // the exact input first, decoding key escapes, with explicit work bounds.
    Scanner {
        bytes: bytes.as_bytes(),
        offset: 0,
        nodes: 0,
    }
    .document()?;
    let graph: Value = serde_json::from_str(bytes).map_err(|_| E::Json)?;
    if string(&graph, "schema")? != "semaprax.graph.v10" {
        return Err(E::Schema);
    }
    if graph.get("view") != Some(&serde_json::json!({"kind":"module"})) {
        return Err(E::Shape);
    }
    let nodes = array(&graph, "nodes")?;
    if nodes.len() > 256 {
        return Err(E::Capacity);
    }
    let mut index = BTreeMap::new();
    for node in nodes {
        let id = string(node, "id")?;
        if id.is_empty() || index.insert(id, node).is_some() {
            return Err(E::Identity);
        }
    }
    let mut functions = BTreeMap::new();
    for function in &expected.functions {
        if function.id.as_str().is_empty()
            || functions.insert(function.id.as_str(), function).is_some()
        {
            return Err(E::Inventory);
        }
    }
    if !functions.contains_key(entry.as_str()) {
        return Err(E::Inventory);
    }
    let mut reader = Reader {
        functions: &functions,
        expression_ids: BTreeSet::new(),
        nodes: 0,
    };
    let mut facts = Vec::new();
    for (id, expected) in &functions {
        let function = index.get(id).ok_or(E::Inventory)?;
        exact(
            function,
            &[
                "id",
                "kind",
                "name",
                "identity_origin",
                "persistent",
                "params",
                "result_id",
                "result",
                "return_type_id",
                "effects",
                "requires_graph",
                "ensures_graph",
                "calls",
                "body",
                "cleanup",
            ],
        )?;
        if string(function, "kind")? != "function" {
            return Err(E::Inventory);
        }
        if string(function, "identity_origin")? != "explicit"
            || function.get("persistent") != Some(&Value::Bool(true))
        {
            return Err(E::UnstableIdentity);
        }
        for field in ["effects", "requires_graph", "ensures_graph"] {
            if !array(function, field)?.is_empty() {
                return Err(E::Shape);
            }
        }
        let params = array(function, "params")?;
        if params.len() != expected.params.len() {
            return Err(E::Inventory);
        }
        let mut locals = BTreeMap::new();
        for (parameter, (id, ty)) in params.iter().zip(&expected.params) {
            reader.charge()?;
            exact(parameter, &["id", "name", "type_id", "ownership_mode"])?;
            if string(parameter, "id")? != id.as_str()
                || locals.insert(id.as_str().to_owned(), *ty).is_some()
                || !reader.expression_ids.insert(id.as_str().to_owned())
            {
                return Err(E::Identity);
            }
            scalar_metadata(parameter, *ty)?;
        }
        let result = field(function, "result")?;
        exact(result, &["id", "type_id", "ownership_mode"])?;
        let result_id = string(function, "result_id")?;
        let expected_result_id =
            ValueId::result(&FunctionExecutionId::Monomorphic(expected.id.clone()));
        if result_id != expected_result_id.as_str()
            || string(result, "id")? != result_id
            || locals.contains_key(result_id)
            || !reader.expression_ids.insert(result_id.to_owned())
        {
            return Err(E::Identity);
        }
        scalar_metadata(result, expected.return_type)?;
        if scalar(string(function, "return_type_id")?)? != expected.return_type {
            return Err(E::Type);
        }
        let mut calls = Vec::new();
        let body_ty = reader.expression(
            field(function, "body")?,
            &expected.body,
            &mut locals,
            &mut calls,
            0,
        )?;
        if body_ty != expected.return_type {
            return Err(E::Type);
        }
        let unique = calls
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let actual = array(function, "calls")?
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or(E::Calls))
            .collect::<Result<Vec<_>, _>>()?;
        if unique != actual {
            return Err(E::Calls);
        }
        facts.push(FunctionFact {
            id: (*id).to_owned(),
            parameters: expected.params.iter().map(|(_, ty)| *ty).collect(),
            result: body_ty,
            call_occurrences: calls,
        });
    }
    // Exact selected closure: no unvisited extra expected function, no missing
    // target, and no call cycle can hide in an unexecuted branch or argument.
    let by_id = facts
        .iter()
        .map(|f| (f.id.as_str(), f))
        .collect::<BTreeMap<_, _>>();
    fn visit<'a>(
        id: &'a str,
        by_id: &BTreeMap<&'a str, &'a FunctionFact>,
        active: &mut BTreeSet<&'a str>,
        done: &mut BTreeSet<&'a str>,
    ) -> Result<(), E> {
        if done.contains(id) {
            return Ok(());
        }
        if !active.insert(id) {
            return Err(E::Calls);
        }
        for callee in &by_id.get(id).ok_or(E::Calls)?.call_occurrences {
            visit(callee, by_id, active, done)?;
        }
        active.remove(id);
        done.insert(id);
        Ok(())
    }
    let mut done = BTreeSet::new();
    visit(entry.as_str(), &by_id, &mut BTreeSet::new(), &mut done)?;
    if done.len() != facts.len() {
        return Err(E::Inventory);
    }
    Ok(ProjectionFacts { functions: facts })
}

fn field<'a>(object: &'a Value, key: &str) -> Result<&'a Value, E> {
    object.get(key).ok_or(E::Shape)
}
fn string<'a>(object: &'a Value, key: &str) -> Result<&'a str, E> {
    field(object, key)?.as_str().ok_or(E::Shape)
}
fn array<'a>(object: &'a Value, key: &str) -> Result<&'a Vec<Value>, E> {
    field(object, key)?.as_array().ok_or(E::Shape)
}
fn exact(object: &Value, keys: &[&str]) -> Result<(), E> {
    let object = object.as_object().ok_or(E::Shape)?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(E::Shape);
    }
    Ok(())
}
fn scalar(value: &str) -> Result<KernelType, E> {
    match value {
        "i64" => Ok(KernelType::I64),
        "bool" => Ok(KernelType::Bool),
        _ => Err(E::Type),
    }
}
fn scalar_metadata(value: &Value, expected: KernelType) -> Result<(), E> {
    if scalar(string(value, "type_id")?)? != expected || string(value, "ownership_mode")? != "value"
    {
        return Err(E::Type);
    }
    Ok(())
}

struct Reader<'a> {
    functions: &'a BTreeMap<&'a str, &'a KernelFn>,
    expression_ids: BTreeSet<String>,
    nodes: usize,
}

impl Reader<'_> {
    fn charge(&mut self) -> Result<(), E> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(E::Capacity);
        }
        Ok(())
    }

    fn expression(
        &mut self,
        value: &Value,
        expected: &Term,
        locals: &mut BTreeMap<String, KernelType>,
        calls: &mut Vec<String>,
        depth: usize,
    ) -> Result<KernelType, E> {
        if depth >= MAX_DEPTH {
            return Err(E::Capacity);
        }
        self.charge()?;
        let id = string(value, "id")?;
        if id.is_empty() || !self.expression_ids.insert(id.to_owned()) {
            return Err(E::Identity);
        }
        let header = ["id", "type_id", "ownership_mode", "kind"];
        let shape = |fields: &[&str]| {
            let mut keys = header.to_vec();
            keys.extend_from_slice(fields);
            exact(value, &keys)
        };
        let kind = string(value, "kind")?;
        let ty = if kind == "block" {
            shape(&["statements", "tail"])?;
            let mut remaining = expected;
            let mut bound_ids = Vec::new();
            for statement in array(value, "statements")? {
                self.charge()?;
                exact(statement, &["kind", "binding", "value"])?;
                if string(statement, "kind")? != "let" {
                    return Err(E::Expression);
                }
                let Term::Let {
                    bound,
                    value: initializer,
                    body,
                } = remaining
                else {
                    return Err(E::Expression);
                };
                let binding = field(statement, "binding")?;
                exact(binding, &["id", "name", "type_id", "ownership_mode"])?;
                if string(binding, "id")? != bound.as_str() {
                    return Err(E::Identity);
                }
                let ty = self.expression(
                    field(statement, "value")?,
                    initializer,
                    locals,
                    calls,
                    depth + 1,
                )?;
                scalar_metadata(binding, ty)?;
                if locals.insert(bound.as_str().to_owned(), ty).is_some() {
                    return Err(E::Identity);
                }
                bound_ids.push(bound.as_str());
                remaining = body;
            }
            let ty = self.expression(field(value, "tail")?, remaining, locals, calls, depth + 1)?;
            for id in bound_ids {
                locals.remove(id);
            }
            ty
        } else {
            match (kind, expected) {
                ("int", Term::Int(expected)) => {
                    shape(&["value"])?;
                    if string(value, "value")? != expected.to_string() {
                        return Err(E::Expression);
                    }
                    KernelType::I64
                }
                ("bool", Term::Bool(expected)) => {
                    shape(&["value"])?;
                    if field(value, "value")?.as_bool() != Some(*expected) {
                        return Err(E::Expression);
                    }
                    KernelType::Bool
                }
                ("place", Term::Var(expected)) => {
                    shape(&["place"])?;
                    let place = field(value, "place")?;
                    exact(place, &["root", "projections"])?;
                    if string(place, "root")? != expected.as_str()
                        || !array(place, "projections")?.is_empty()
                    {
                        return Err(E::Identity);
                    }
                    *locals.get(expected.as_str()).ok_or(E::Identity)?
                }
                ("unary", Term::Unary(op, argument)) => {
                    shape(&["op", "value"])?;
                    let (symbol, ty) = match op {
                        UnaryOp::Neg => ("-", KernelType::I64),
                        UnaryOp::Not => ("!", KernelType::Bool),
                    };
                    if string(value, "op")? != symbol {
                        return Err(E::Expression);
                    }
                    if self.expression(
                        field(value, "value")?,
                        argument,
                        locals,
                        calls,
                        depth + 1,
                    )? != ty
                    {
                        return Err(E::Type);
                    }
                    ty
                }
                ("binary", Term::Binary(op, left, right)) => {
                    shape(&["op", "left", "right"])?;
                    let symbol = match op {
                        BinaryOp::Add => "+",
                        BinaryOp::Sub => "-",
                        BinaryOp::Mul => "*",
                        BinaryOp::Div => "/",
                        BinaryOp::Rem => "%",
                        BinaryOp::Eq => "==",
                        BinaryOp::Ne => "!=",
                        BinaryOp::Lt => "<",
                        BinaryOp::Le => "<=",
                        BinaryOp::Gt => ">",
                        BinaryOp::Ge => ">=",
                        BinaryOp::And => "&&",
                        BinaryOp::Or => "||",
                    };
                    if string(value, "op")? != symbol {
                        return Err(E::Expression);
                    }
                    let left =
                        self.expression(field(value, "left")?, left, locals, calls, depth + 1)?;
                    let right =
                        self.expression(field(value, "right")?, right, locals, calls, depth + 1)?;
                    if left != right {
                        return Err(E::Type);
                    }
                    match op {
                        BinaryOp::And | BinaryOp::Or => {
                            if left != KernelType::Bool {
                                return Err(E::Type);
                            }
                            KernelType::Bool
                        }
                        BinaryOp::Eq | BinaryOp::Ne => KernelType::Bool,
                        BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                            if left != KernelType::I64 {
                                return Err(E::Type);
                            }
                            KernelType::Bool
                        }
                        _ => {
                            if left != KernelType::I64 {
                                return Err(E::Type);
                            }
                            KernelType::I64
                        }
                    }
                }
                (
                    "if",
                    Term::If {
                        condition,
                        then_branch,
                        else_branch,
                    },
                ) => {
                    shape(&["condition", "then", "else"])?;
                    if self.expression(
                        field(value, "condition")?,
                        condition,
                        locals,
                        calls,
                        depth + 1,
                    )? != KernelType::Bool
                    {
                        return Err(E::Type);
                    }
                    let then_ty = self.expression(
                        field(value, "then")?,
                        then_branch,
                        locals,
                        calls,
                        depth + 1,
                    )?;
                    let else_ty = self.expression(
                        field(value, "else")?,
                        else_branch,
                        locals,
                        calls,
                        depth + 1,
                    )?;
                    if then_ty != else_ty {
                        return Err(E::Type);
                    }
                    then_ty
                }
                ("call", Term::Call { callee, args }) => {
                    shape(&["callee", "args"])?;
                    if string(value, "callee")? != callee.as_str() {
                        return Err(E::Calls);
                    }
                    let target = self.functions.get(callee.as_str()).ok_or(E::Calls)?;
                    let graph_args = array(value, "args")?;
                    if graph_args.len() != args.len() || args.len() != target.params.len() {
                        return Err(E::Calls);
                    }
                    calls.push(callee.as_str().to_owned());
                    for ((argument, expected), (_, ty)) in
                        graph_args.iter().zip(args).zip(&target.params)
                    {
                        if self.expression(argument, expected, locals, calls, depth + 1)? != *ty {
                            return Err(E::Type);
                        }
                    }
                    target.return_type
                }
                _ => return Err(E::Expression),
            }
        };
        scalar_metadata(value, ty)?;
        Ok(ty)
    }
}

/// This pass only recognizes containers and decoded object keys. serde_json
/// subsequently owns full JSON syntax/UTF-8/number validation. Byte/depth/work
/// bounds precede generic Value decoding; duplicate keys cannot be normalized away.
struct Scanner<'a> {
    bytes: &'a [u8],
    offset: usize,
    nodes: usize,
}
impl Scanner<'_> {
    fn document(mut self) -> Result<(), E> {
        self.value(0)?;
        self.space();
        if self.offset != self.bytes.len() {
            return Err(E::Json);
        }
        Ok(())
    }
    fn space(&mut self) {
        while self
            .bytes
            .get(self.offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.offset += 1;
        }
    }
    fn take(&mut self, byte: u8) -> Result<(), E> {
        self.space();
        if self.bytes.get(self.offset) != Some(&byte) {
            return Err(E::Json);
        }
        self.offset += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<&[u8], E> {
        self.space();
        let start = self.offset;
        self.take(b'"')?;
        while let Some(byte) = self.bytes.get(self.offset) {
            self.offset += 1;
            match byte {
                b'"' => return Ok(&self.bytes[start..self.offset]),
                b'\\' => self.offset += 1,
                _ => {}
            }
        }
        Err(E::Json)
    }
    fn value(&mut self, depth: usize) -> Result<(), E> {
        self.nodes += 1;
        if depth >= MAX_DEPTH || self.nodes > 131_072 {
            return Err(E::Capacity);
        }
        self.space();
        match self.bytes.get(self.offset).copied().ok_or(E::Json)? {
            b'{' => {
                self.offset += 1;
                self.space();
                let mut keys = BTreeSet::new();
                if self.bytes.get(self.offset) == Some(&b'}') {
                    self.offset += 1;
                    return Ok(());
                }
                loop {
                    let key: String =
                        serde_json::from_slice(self.string()?).map_err(|_| E::Json)?;
                    if !keys.insert(key) {
                        return Err(E::DuplicateKey);
                    }
                    self.take(b':')?;
                    self.value(depth + 1)?;
                    self.space();
                    if self.bytes.get(self.offset) == Some(&b'}') {
                        self.offset += 1;
                        break;
                    }
                    self.take(b',')?;
                }
            }
            b'[' => {
                self.offset += 1;
                self.space();
                if self.bytes.get(self.offset) == Some(&b']') {
                    self.offset += 1;
                    return Ok(());
                }
                loop {
                    self.value(depth + 1)?;
                    self.space();
                    if self.bytes.get(self.offset) == Some(&b']') {
                        self.offset += 1;
                        break;
                    }
                    self.take(b',')?;
                }
            }
            b'"' => {
                self.string()?;
            }
            _ => {
                let start = self.offset;
                while self
                    .bytes
                    .get(self.offset)
                    .is_some_and(|b| !b.is_ascii_whitespace() && !b",]}".contains(b))
                {
                    self.offset += 1;
                }
                if start == self.offset {
                    return Err(E::Json);
                }
            }
        }
        Ok(())
    }
}
