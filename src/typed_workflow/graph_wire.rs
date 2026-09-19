//! JSON wire decode for [`super::graph::WorkflowGraph`].
//!
//! Issue #208's typed workflow profile had no way to author, inspect, or
//! validate a workflow graph outside a Rust unit test that builds
//! [`super::graph::StepDef`]/[`super::graph::EdgeDef`] values by hand. This
//! module owns the one decode rule for a `semaprax.typed-workflow.graph.v1`
//! document; `crate::cli::typed_workflow` (the CLI front) only reads bytes
//! from disk and calls [`parse_graph`], exactly as `cli::audit` defers every
//! capsule rule to `crate::audit_capsule` rather than re-implementing it at
//! the CLI boundary.
//!
//! This is a decoder only: it builds a [`WorkflowGraph`] value from bytes and
//! performs no semantic checking of its own -- not reachability, not
//! dataflow, not any of the per-kind shape rules [`WorkflowGraph`]'s own doc
//! comments describe. Call [`super::graph::WorkflowGraph::validate`] on the
//! result for that; this module never duplicates it.
//!
//! Numeric identities (`entry`, `id`, `from`, `to`, `from_port`, `to_port`,
//! `condition_port`, `parallel`, `max_iterations`) are plain non-negative
//! JSON integers, each bounded to fit `u32`. Unlike
//! [`super::checkpoint::Checkpoint`]'s wire format, which authenticates a
//! machine-generated durable record against an exact canonical
//! re-rendering, this format is a human- or tool-authored source document:
//! there is no encoder here and no round-trip requirement, only a decoder
//! that fails closed on anything it does not recognize.

use serde_json::{Map, Value};

use crate::diagnostic::Diagnostic;

use super::graph::{
    DeclaredStepKind, EdgeDef, EdgeId, Port, PortId, PortType, StepDef, StepId, StepKind,
    WorkflowGraph, MAX_STEPS,
};

/// Schema identity every wire document must declare.
pub const GRAPH_WIRE_SCHEMA: &str = "semaprax.typed-workflow.graph.v1";

/// Largest wire document this decoder accepts, checked before any JSON
/// parsing runs. Well above what [`MAX_STEPS`] and [`MAX_EDGES`] admit once
/// parsed; those per-array bounds, not this byte bound, are what actually
/// keep a hostile document from building an oversized graph in memory.
const MAX_WIRE_BYTES: usize = 262_144;

/// Bound on the `edges` array length: [`MAX_STEPS`] steps, each with at most
/// a handful of declared out edges in any admitted [`StepKind`] shape (two,
/// for `Conditional`; one, for every other non-branching or `Parallel`
/// branch step), with slack. Checked independently of, and before,
/// [`super::graph::WorkflowGraph::validate`]'s own structural checks.
const MAX_EDGES: usize = MAX_STEPS * 4;

/// Bound on one step's `in_ports`/`out_ports` array length. No admitted
/// [`StepKind`] declares more than two fixed ports ([`super::graph::THEN_PORT`]/
/// [`super::graph::ELSE_PORT`]); this leaves generous room for a workflow
/// author's own additional typed ports without admitting an unbounded array.
const MAX_PORTS: usize = 16;

fn malformed(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io(
        "SPX-Z921",
        format!("workflow graph document: {}", message.into()),
    )
}

fn as_object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, Diagnostic> {
    value
        .as_object()
        .ok_or_else(|| malformed(format!("`{what}` must be a JSON object")))
}

/// Requires `map` to carry exactly `keys`, no more and no fewer. An unknown
/// field -- including a typo, a stray extra field, or a field belonging to a
/// different step kind -- is refused rather than ignored, the same
/// closed-key discipline [`super::checkpoint::parse_wire`] uses for its own
/// wire format.
fn closed(map: &Map<String, Value>, keys: &[&str], what: &str) -> Result<(), Diagnostic> {
    if map.len() != keys.len() || !keys.iter().all(|key| map.contains_key(*key)) {
        let mut present: Vec<&str> = map.keys().map(String::as_str).collect();
        present.sort_unstable();
        return Err(malformed(format!(
            "`{what}` must have exactly the fields {keys:?}, got {present:?}"
        )));
    }
    Ok(())
}

fn field<'a>(map: &'a Map<String, Value>, key: &str, what: &str) -> Result<&'a Value, Diagnostic> {
    map.get(key)
        .ok_or_else(|| malformed(format!("`{what}` is missing `{key}`")))
}

fn as_u32(value: &Value, what: &str) -> Result<u32, Diagnostic> {
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
        .ok_or_else(|| {
            malformed(format!(
                "`{what}` must be a non-negative integer that fits in 32 bits"
            ))
        })
}

fn as_str<'a>(value: &'a Value, what: &str) -> Result<&'a str, Diagnostic> {
    value
        .as_str()
        .ok_or_else(|| malformed(format!("`{what}` must be a string")))
}

fn as_array<'a>(value: &'a Value, what: &str) -> Result<&'a Vec<Value>, Diagnostic> {
    value
        .as_array()
        .ok_or_else(|| malformed(format!("`{what}` must be an array")))
}

fn parse_port_type(text: &str, what: &str) -> Result<PortType, Diagnostic> {
    match text {
        "unit" => Ok(PortType::Unit),
        "bool" => Ok(PortType::Bool),
        "int" => Ok(PortType::Int),
        "text" => Ok(PortType::Text),
        other => Err(malformed(format!(
            "`{what}` names an unknown port type `{other}`; expected one of \
             unit, bool, int, text"
        ))),
    }
}

fn parse_port(value: &Value, what: &str) -> Result<Port, Diagnostic> {
    let map = as_object(value, what)?;
    closed(map, &["id", "ty"], what)?;
    let id = PortId(as_u32(field(map, "id", what)?, &format!("{what}.id"))?);
    let ty = parse_port_type(
        as_str(field(map, "ty", what)?, &format!("{what}.ty"))?,
        &format!("{what}.ty"),
    )?;
    Ok(Port { id, ty })
}

fn parse_ports(value: &Value, what: &str) -> Result<Vec<Port>, Diagnostic> {
    let array = as_array(value, what)?;
    if array.len() > MAX_PORTS {
        return Err(malformed(format!(
            "`{what}` has more than {MAX_PORTS} entries"
        )));
    }
    array
        .iter()
        .enumerate()
        .map(|(index, entry)| parse_port(entry, &format!("{what}[{index}]")))
        .collect()
}

fn parse_declared_kind(text: &str, what: &str) -> Result<DeclaredStepKind, Diagnostic> {
    match text {
        "agent_call" => Ok(DeclaredStepKind::AgentCall),
        "tool_call" => Ok(DeclaredStepKind::ToolCall),
        "job" => Ok(DeclaredStepKind::Job),
        "semantic_change" => Ok(DeclaredStepKind::SemanticChange),
        "test_build" => Ok(DeclaredStepKind::TestBuild),
        "publication_request" => Ok(DeclaredStepKind::PublicationRequest),
        other => Err(malformed(format!(
            "`{what}` names an unknown declared step kind `{other}`; expected one of \
             agent_call, tool_call, job, semantic_change, test_build, publication_request"
        ))),
    }
}

/// Parses one `steps[index]` entry. `kind` is a string discriminator; the
/// exact field set a step object must carry (and no more) depends on which
/// kind it names, checked by a separate [`closed`] call per arm so a field
/// belonging to a different kind -- for example `max_iterations` on a
/// `sequential` step -- is refused rather than silently accepted or ignored.
fn parse_step(value: &Value, index: usize) -> Result<StepDef, Diagnostic> {
    let what = format!("steps[{index}]");
    let map = as_object(value, &what)?;
    let kind_text = as_str(field(map, "kind", &what)?, &format!("{what}.kind"))?;
    let kind = match kind_text {
        "sequential" => {
            closed(map, &["id", "kind", "in_ports", "out_ports"], &what)?;
            StepKind::Sequential
        }
        "conditional" => {
            closed(
                map,
                &["id", "kind", "in_ports", "out_ports", "condition_port"],
                &what,
            )?;
            StepKind::Conditional {
                condition_port: PortId(as_u32(
                    field(map, "condition_port", &what)?,
                    &format!("{what}.condition_port"),
                )?),
            }
        }
        "parallel" => {
            closed(map, &["id", "kind", "in_ports", "out_ports"], &what)?;
            StepKind::Parallel
        }
        "join" => {
            closed(
                map,
                &["id", "kind", "in_ports", "out_ports", "parallel"],
                &what,
            )?;
            StepKind::Join {
                parallel: StepId(as_u32(
                    field(map, "parallel", &what)?,
                    &format!("{what}.parallel"),
                )?),
            }
        }
        "human_gate" => {
            closed(map, &["id", "kind", "in_ports", "out_ports"], &what)?;
            StepKind::HumanGate
        }
        "loop" => {
            closed(
                map,
                &["id", "kind", "in_ports", "out_ports", "max_iterations"],
                &what,
            )?;
            StepKind::Loop {
                max_iterations: as_u32(
                    field(map, "max_iterations", &what)?,
                    &format!("{what}.max_iterations"),
                )?,
            }
        }
        "model_call" => {
            closed(
                map,
                &["id", "kind", "in_ports", "out_ports", "requested_model"],
                &what,
            )?;
            StepKind::ModelCall {
                requested_model: as_str(
                    field(map, "requested_model", &what)?,
                    &format!("{what}.requested_model"),
                )?
                .to_owned(),
            }
        }
        "terminal" => {
            closed(map, &["id", "kind", "in_ports", "out_ports"], &what)?;
            StepKind::Terminal
        }
        "declared" => {
            closed(
                map,
                &["id", "kind", "in_ports", "out_ports", "declared_kind"],
                &what,
            )?;
            StepKind::Declared(parse_declared_kind(
                as_str(
                    field(map, "declared_kind", &what)?,
                    &format!("{what}.declared_kind"),
                )?,
                &format!("{what}.declared_kind"),
            )?)
        }
        other => {
            return Err(malformed(format!(
                "`{what}.kind` names an unknown step kind `{other}`"
            )))
        }
    };
    let id = StepId(as_u32(field(map, "id", &what)?, &format!("{what}.id"))?);
    let in_ports = parse_ports(field(map, "in_ports", &what)?, &format!("{what}.in_ports"))?;
    let out_ports = parse_ports(
        field(map, "out_ports", &what)?,
        &format!("{what}.out_ports"),
    )?;
    Ok(StepDef {
        id,
        kind,
        in_ports,
        out_ports,
    })
}

fn parse_edge(value: &Value, index: usize) -> Result<EdgeDef, Diagnostic> {
    let what = format!("edges[{index}]");
    let map = as_object(value, &what)?;
    closed(map, &["id", "from", "from_port", "to", "to_port"], &what)?;
    Ok(EdgeDef {
        id: EdgeId(as_u32(field(map, "id", &what)?, &format!("{what}.id"))?),
        from: StepId(as_u32(field(map, "from", &what)?, &format!("{what}.from"))?),
        from_port: PortId(as_u32(
            field(map, "from_port", &what)?,
            &format!("{what}.from_port"),
        )?),
        to: StepId(as_u32(field(map, "to", &what)?, &format!("{what}.to"))?),
        to_port: PortId(as_u32(
            field(map, "to_port", &what)?,
            &format!("{what}.to_port"),
        )?),
    })
}

/// Decodes a [`WorkflowGraph`] from a `semaprax.typed-workflow.graph.v1`
/// wire document.
///
/// Refuses (never repairs or best-effort-parses) a document that: exceeds
/// [`MAX_WIRE_BYTES`], is not valid UTF-8, is not valid JSON, is not a
/// closed JSON object at any level, is tagged with the wrong schema, names
/// an unknown step kind/port type/declared kind, carries a numeric identity
/// that does not fit `u32`, or exceeds [`MAX_STEPS`]/[`MAX_EDGES`]/
/// [`MAX_PORTS`]. Every failure is [`Diagnostic`] `SPX-Z921`.
///
/// Purely structural: this function never calls
/// [`super::graph::WorkflowGraph::validate`] and a successful return is not
/// evidence the graph is reachable, well-typed, or otherwise semantically
/// admissible -- only that the document was a well-formed encoding of *some*
/// [`WorkflowGraph`] value.
pub fn parse_graph(bytes: &[u8]) -> Result<WorkflowGraph, Diagnostic> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(malformed(format!(
            "document is {} bytes, over the {MAX_WIRE_BYTES}-byte bound",
            bytes.len()
        )));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| malformed("document is not valid UTF-8"))?;
    let value: Value = serde_json::from_str(text)
        .map_err(|error| malformed(format!("document is not valid JSON: {error}")))?;
    let map = as_object(&value, "document")?;
    closed(map, &["schema", "entry", "steps", "edges"], "document")?;
    let schema = as_str(field(map, "schema", "document")?, "document.schema")?;
    if schema != GRAPH_WIRE_SCHEMA {
        return Err(malformed(format!(
            "`document.schema` must be `{GRAPH_WIRE_SCHEMA}`, got `{schema}`"
        )));
    }
    let entry = StepId(as_u32(field(map, "entry", "document")?, "document.entry")?);
    let steps_array = as_array(field(map, "steps", "document")?, "document.steps")?;
    if steps_array.len() > MAX_STEPS {
        return Err(malformed(format!(
            "`document.steps` has more than {MAX_STEPS} entries"
        )));
    }
    let steps = steps_array
        .iter()
        .enumerate()
        .map(|(index, entry)| parse_step(entry, index))
        .collect::<Result<Vec<_>, _>>()?;
    let edges_array = as_array(field(map, "edges", "document")?, "document.edges")?;
    if edges_array.len() > MAX_EDGES {
        return Err(malformed(format!(
            "`document.edges` has more than {MAX_EDGES} entries"
        )));
    }
    let edges = edges_array
        .iter()
        .enumerate()
        .map(|(index, entry)| parse_edge(entry, index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WorkflowGraph {
        steps,
        edges,
        entry,
    })
}

#[cfg(test)]
#[path = "graph_wire/tests.rs"]
mod tests;
