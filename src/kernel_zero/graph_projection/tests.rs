use super::super::term::{KernelFn, KernelProgram, Term};
use super::*;
use crate::ast::BinaryOp;
use crate::hir::{FunctionExecutionId, ValueId};
use serde_json::{json, Value};

fn parameter(index: usize) -> ValueId {
    ValueId::intrinsic_parameter("pair", index)
}
fn int(id: &str, value: i64) -> Value {
    json!({"id":id,"type_id":"i64","ownership_mode":"value","kind":"int","value":value.to_string()})
}
fn call(id: &str, left: Value, right: Value) -> Value {
    json!({"id":id,"type_id":"i64","ownership_mode":"value","kind":"call","callee":"pair","args":[left,right]})
}
fn result_id(id: &str) -> String {
    ValueId::result(&FunctionExecutionId::Monomorphic(DeclarationId::new(id)))
        .as_str()
        .to_owned()
}
fn function(id: &str, params: Vec<Value>, calls: Vec<&str>, body: Value) -> Value {
    let result_id = result_id(id);
    json!({"id":id,"kind":"function","name":id,"identity_origin":"explicit","persistent":true,
        "params":params,"result_id":result_id.clone(),"result":{"id":result_id,"type_id":"i64","ownership_mode":"value"},
        "return_type_id":"i64","effects":[],"requires_graph":[],"ensures_graph":[],"calls":calls,"body":body,"cleanup":{}})
}
fn fixture() -> (Value, KernelProgram) {
    let pair = KernelFn {
        id: DeclarationId::new("pair"),
        params: vec![
            (parameter(0), KernelType::I64),
            (parameter(1), KernelType::I64),
        ],
        return_type: KernelType::I64,
        body: Term::Binary(
            BinaryOp::Sub,
            Box::new(Term::Var(parameter(0))),
            Box::new(Term::Var(parameter(1))),
        ),
    };
    let make_call = |a, b| Term::Call {
        callee: pair.id.clone(),
        args: vec![Term::Int(a), Term::Int(b)],
    };
    let entry = KernelFn {
        id: DeclarationId::new("entry"),
        params: vec![],
        return_type: KernelType::I64,
        body: Term::If {
            condition: Box::new(Term::Bool(true)),
            then_branch: Box::new(make_call(1, 2)),
            else_branch: Box::new(make_call(3, 4)),
        },
    };
    let parameters = (0..2).map(|i| json!({"id":parameter(i).as_str(),"name":format!("p{i}"),"type_id":"i64","ownership_mode":"value"})).collect();
    let place = |i| json!({"id":format!("pair.e{i}"),"kind":"place","type_id":"i64","ownership_mode":"value","place":{"root":parameter(i).as_str(),"projections":[]}});
    let graph = json!({"schema":"semaprax.graph.v10","view":{"kind":"module"},"nodes":[
        function("pair", parameters, vec![], json!({"id":"pair.body","kind":"binary","type_id":"i64","ownership_mode":"value","op":"-","left":place(0),"right":place(1)})),
        function("entry", vec![], vec!["pair"], json!({"id":"entry.body","kind":"if","type_id":"i64","ownership_mode":"value",
            "condition":{"id":"condition","kind":"bool","type_id":"bool","ownership_mode":"value","value":true},
            "then":call("yes",int("one",1),int("two",2)),"else":call("no",int("three",3),int("four",4))}))]});
    (
        graph,
        KernelProgram {
            functions: vec![pair, entry],
        },
    )
}
fn check(graph: &Value, program: &KernelProgram) -> Result<ProjectionFacts, ProjectionError> {
    decode::check(&graph.to_string(), program, &DeclarationId::new("entry"))
}

#[test]
fn stable_function_order_and_repeated_lazy_calls_are_preserved() {
    let (mut graph, mut program) = fixture();
    let facts = check(&graph, &program).unwrap();
    assert_eq!(facts.functions[0].id, "entry");
    assert_eq!(facts.functions[0].call_occurrences, ["pair", "pair"]);
    graph["nodes"].as_array_mut().unwrap().reverse();
    program.functions.reverse();
    assert_eq!(check(&graph, &program), Ok(facts));
}

#[test]
fn missing_duplicate_and_nonpersistent_functions_are_refused() {
    let (graph, program) = fixture();
    let mut bad = graph.clone();
    bad["nodes"].as_array_mut().unwrap().pop();
    assert_eq!(check(&bad, &program), Err(ProjectionError::Inventory));
    let mut bad = graph.clone();
    bad["nodes"]
        .as_array_mut()
        .unwrap()
        .push(graph["nodes"][0].clone());
    assert_eq!(check(&bad, &program), Err(ProjectionError::Identity));
    for (field, value) in [
        ("persistent", json!(false)),
        ("identity_origin", json!("automatic")),
    ] {
        let mut bad = graph.clone();
        bad["nodes"][1][field] = value;
        assert_eq!(
            check(&bad, &program),
            Err(ProjectionError::UnstableIdentity)
        );
    }
    let mut bad_program = program.clone();
    bad_program.functions.push(program.functions[0].clone());
    assert_eq!(check(&graph, &bad_program), Err(ProjectionError::Inventory));
}

#[test]
fn signature_and_metadata_drift_are_not_hidden_by_body_agreement() {
    let (graph, program) = fixture();
    for (pointer, replacement) in [
        ("/nodes/0/params/0/type_id", json!("bool")),
        ("/nodes/0/params/0/ownership_mode", json!("own")),
        ("/nodes/1/body/type_id", json!("bool")),
        ("/nodes/1/result/type_id", json!("bool")),
        ("/nodes/1/return_type_id", json!("bool")),
    ] {
        let mut bad = graph.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert_eq!(
            check(&bad, &program),
            Err(ProjectionError::Type),
            "{pointer}"
        );
    }
    let mut bad = graph.clone();
    bad["nodes"][0]["params"].as_array_mut().unwrap().reverse();
    assert_eq!(check(&bad, &program), Err(ProjectionError::Identity));
}

#[test]
fn operand_argument_and_branch_permutations_fail_correspondence() {
    let (graph, program) = fixture();
    let mut bad = graph.clone();
    bad["nodes"][1]["body"]["then"]["args"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_eq!(check(&bad, &program), Err(ProjectionError::Expression));
    let mut bad = graph.clone();
    bad["nodes"][1]["body"]["then"] = graph["nodes"][1]["body"]["else"].clone();
    assert_eq!(check(&bad, &program), Err(ProjectionError::Expression));
    let mut bad = graph.clone();
    bad["nodes"][0]["body"]["left"] = graph["nodes"][0]["body"]["right"].clone();
    assert_eq!(check(&bad, &program), Err(ProjectionError::Identity));
    let mut bad = graph.clone();
    bad["nodes"][0]["body"]["op"] = json!("+");
    assert_eq!(check(&bad, &program), Err(ProjectionError::Expression));
}

#[test]
fn invented_dropped_or_duplicate_call_summary_facts_fail() {
    let (graph, program) = fixture();
    for calls in [json!([]), json!(["pair", "pair"]), json!(["entry", "pair"])] {
        let mut bad = graph.clone();
        bad["nodes"][1]["calls"] = calls;
        assert_eq!(check(&bad, &program), Err(ProjectionError::Calls));
    }
    let mut bad = graph.clone();
    bad["nodes"][1]["body"]["else"]["callee"] = json!("entry");
    assert_eq!(check(&bad, &program), Err(ProjectionError::Calls));
    let mut bad = graph.clone();
    bad["nodes"][1]["body"]["then"]["args"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert_eq!(check(&bad, &program), Err(ProjectionError::Calls));
}

#[test]
fn duplicate_expression_ids_and_surplus_semantic_fields_fail() {
    let (graph, program) = fixture();
    let mut bad = graph.clone();
    bad["nodes"][1]["body"]["else"]["id"] = json!("yes");
    assert_eq!(check(&bad, &program), Err(ProjectionError::Identity));
    let mut bad = graph.clone();
    bad["nodes"][1]["result_id"] = json!("forged.result");
    bad["nodes"][1]["result"]["id"] = json!("forged.result");
    assert_eq!(check(&bad, &program), Err(ProjectionError::Identity));
    let mut bad = graph.clone();
    let body_id = bad["nodes"][1]["body"]["id"].clone();
    bad["nodes"][1]["result_id"] = body_id.clone();
    bad["nodes"][1]["result"]["id"] = body_id;
    assert_eq!(check(&bad, &program), Err(ProjectionError::Identity));
    let mut bad = graph.clone();
    bad["nodes"][1]["body"]["then"]["hidden_argument"] = int("extra", 7);
    assert_eq!(check(&bad, &program), Err(ProjectionError::Shape));
    let mut bad = graph.clone();
    bad["nodes"][1]["effects"] = json!(["clock.read"]);
    assert_eq!(check(&bad, &program), Err(ProjectionError::Shape));
    let mut bad = graph.clone();
    bad["schema"] = json!("semaprax.graph.v999");
    assert_eq!(check(&bad, &program), Err(ProjectionError::Schema));
}

#[test]
fn duplicate_json_keys_including_escaped_spellings_fail_before_normalization() {
    let (graph, program) = fixture();
    for duplicate in [
        "\"schema\":\"semaprax.graph.v10\",",
        "\"sch\\u0065ma\":\"semaprax.graph.v10\",",
    ] {
        let bytes = format!("{{{duplicate}{}", &graph.to_string()[1..]);
        assert_eq!(
            decode::check(&bytes, &program, &DeclarationId::new("entry")),
            Err(ProjectionError::DuplicateKey)
        );
    }
    let bytes = graph.to_string().replacen(
        "\"callee\":\"pair\"",
        "\"callee\":\"pair\",\"callee\":\"pair\"",
        1,
    );
    assert_eq!(
        decode::check(&bytes, &program, &DeclarationId::new("entry")),
        Err(ProjectionError::DuplicateKey)
    );
}

#[test]
fn graph_byte_json_depth_and_function_limits_fail_closed() {
    let (graph, program) = fixture();
    let bytes = " ".repeat(MAX_GRAPH_BYTES + 1);
    assert_eq!(
        decode::check(&bytes, &program, &DeclarationId::new("entry")),
        Err(ProjectionError::Capacity)
    );
    let bytes = format!("{}0{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
    assert_eq!(
        decode::check(&bytes, &program, &DeclarationId::new("entry")),
        Err(ProjectionError::Capacity)
    );
    let mut large = program.clone();
    large.functions = vec![program.functions[0].clone(); MAX_FUNCTIONS + 1];
    assert_eq!(check(&graph, &large), Err(ProjectionError::Capacity));
    for bytes in ["", "{", "[1,]", "{} trailing", "{\"x\":\"\\"] {
        assert_eq!(
            decode::check(bytes, &program, &DeclarationId::new("entry")),
            Err(ProjectionError::Json)
        );
    }
}

#[test]
fn disconnected_expected_functions_and_forged_cycles_fail() {
    let (graph, program) = fixture();
    assert_eq!(
        decode::check(&graph.to_string(), &program, &DeclarationId::new("pair")),
        Err(ProjectionError::Inventory)
    );
    let mut graph = graph;
    let mut program = program;
    program.functions[0].body = Term::Call {
        callee: DeclarationId::new("entry"),
        args: vec![],
    };
    graph["nodes"][0]["calls"] = json!(["entry"]);
    graph["nodes"][0]["body"] = json!({"id":"recursive","kind":"call","type_id":"i64","ownership_mode":"value","callee":"entry","args":[]});
    assert_eq!(check(&graph, &program), Err(ProjectionError::Calls));
}

#[test]
fn digest_binds_exact_utf8_bytes_and_length() {
    assert_eq!(graph_digest(b"{}"), graph_digest(b"{}"));
    assert_ne!(graph_digest(b"{}"), graph_digest(b"{}\n"));
    assert_ne!(graph_digest(b"ab"), graph_digest(b"a\0b"));
}
