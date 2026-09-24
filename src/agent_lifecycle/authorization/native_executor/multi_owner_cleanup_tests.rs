use super::*;

const MULTI_OWNER_SOURCE: &str = r#"
module fixture.multi_owner;

@id("fixture.multi_owner.Input")
record Input {
    @id("fixture.multi_owner.Input.left")
    left: Bytes,
    @id("fixture.multi_owner.Input.right")
    right: Bytes,
}

@id("fixture.multi_owner.Output")
record Output {
    @id("fixture.multi_owner.Output.first")
    first: Bytes,
    @id("fixture.multi_owner.Output.second")
    second: Bytes,
}

@id("fixture.multi_owner.transform")
fn transform(input: borrow Input, owned: own Bytes) -> Output
{
    let owned_view = bytes_as_slice(owned);
    let copied = bytes_copy(owned_view);
    Output {
        first: copied,
        second: owned,
    }
}

@id("fixture.multi_owner.main")
fn main() -> i64
{
    0
}
"#;

fn settlement(owner: &str, counter: &str) -> String {
    format!(
        "    spx_bytes_drop(&({owner}));\n    if (({owner}).ptr != NULL || ({owner}).len != 0) return 91;\n    ++{counter};\n"
    )
}

fn record(record: &str, fields: &[(&str, RetainedValue)]) -> RetainedValue {
    RetainedValue::Record(RetainedRecord {
        record: DeclarationId::new(record),
        fields: fields
            .iter()
            .map(|(name, value)| RetainedField {
                field: DeclarationId::new(format!("{record}.{name}")),
                value: value.clone(),
            })
            .collect(),
    })
}

fn expected_result() -> RetainedValue {
    record(
        "fixture.multi_owner.Output",
        &[
            ("first", RetainedValue::Bytes(b"owned".to_vec())),
            ("second", RetainedValue::Bytes(b"owned".to_vec())),
        ],
    )
}

#[test]
fn native_multi_owner_cleanup_order_is_physical_and_hostile_mutants_reject() {
    let host = crate::agent_lifecycle::tests::native_stage_host()
        .expect("native cleanup evidence requires held clang");
    let program = hir::resolve(
        &crate::check(MULTI_OWNER_SOURCE, Path::new("multi-owner.spx"))
            .expect("multi-owner fixture checks"),
    )
    .expect("multi-owner fixture resolves");
    let entry = program
        .functions
        .iter()
        .find(|function| function.id.as_str() == "fixture.multi_owner.transform")
        .expect("transform entry exists");
    let arguments = [
        record(
            "fixture.multi_owner.Input",
            &[
                ("left", RetainedValue::Bytes(b"left".to_vec())),
                ("right", RetainedValue::Bytes(b"right!".to_vec())),
            ],
        ),
        RetainedValue::Bytes(b"owned".to_vec()),
    ];
    let (base_body, borrowed_count) = render_driver(&program, entry, &arguments).unwrap();
    assert_eq!(borrowed_count, 2);

    let left_arg = format!(
        "spx_native_exec_arg_1.{}",
        field_symbol(&DeclarationId::new("fixture.multi_owner.Input.left"))
    );
    let right_arg = format!(
        "spx_native_exec_arg_1.{}",
        field_symbol(&DeclarationId::new("fixture.multi_owner.Input.right"))
    );
    let output_first = format!(
        "(spx_native_exec_result).{}",
        field_symbol(&DeclarationId::new("fixture.multi_owner.Output.first"))
    );
    let output_second = format!(
        "(spx_native_exec_result).{}",
        field_symbol(&DeclarationId::new("fixture.multi_owner.Output.second"))
    );

    let mut argument_emitter = Emitter::new();
    argument_emitter.bytes_expr(b"left");
    argument_emitter.bytes_expr(b"right!");
    let original_owned_expression = argument_emitter.bytes_expr(b"owned");
    assert_eq!(base_body.matches(&original_owned_expression).count(), 1);
    let captured_owned_expression =
        format!("(test_original_owned = {original_owned_expression}, test_original_owned)");
    let mut body = base_body.replacen(&original_owned_expression, &captured_owned_expression, 1);
    body.insert_str(0, "    spx_bytes_v1 test_original_owned = {0};\n");

    let call_prefix = format!(
        "    spx_status_token spx_native_exec_token = {}(",
        function_symbol(&entry.id)
    );
    let call_start = body.find(&call_prefix).expect("entry call rendered");
    let call_end = body[call_start..]
        .find('\n')
        .map(|offset| call_start + offset + 1)
        .expect("entry call line ends");
    let identity_probe = format!(
        "    if ((void *)({output_second}).ptr != (void *)test_original_owned.ptr || (void *)({output_first}).ptr == (void *)test_original_owned.ptr) return 94;\n    test_expected[0] = (void *)({left_arg}).ptr;\n    test_expected[1] = (void *)({right_arg}).ptr;\n    test_expected[2] = (void *)test_original_owned.ptr;\n    test_expected[3] = (void *)({output_first}).ptr;\n"
    );
    body.insert_str(call_end, &identity_probe);

    let left_drop = settlement(&left_arg, "spx_borrowed_settled");
    let right_drop = settlement(&right_arg, "spx_borrowed_settled");
    assert_eq!(body.matches(&left_drop).count(), 1);
    assert_eq!(body.matches(&right_drop).count(), 1);
    let right_then_left = body.find(&right_drop).expect("borrowed cleanup is emitted")
        < body.find(&left_drop).expect("borrowed cleanup is emitted");
    assert!(
        right_then_left,
        "borrowed fields settle in reverse field order"
    );

    let output_second_drop = settlement(&output_second, "spx_result_settled");
    assert_eq!(body.matches(&output_second_drop).count(), 1);
    let terminal_assertions = "    if (test_allocs != 4 || test_frees != 4) return 92;\n    if (test_free_order[0] != 1 || test_free_order[1] != 0 || test_free_order[2] != 2 || test_free_order[3] != 3) return 93;\n";
    assert_eq!(body.matches("    return 0;\n").count(), 1);
    body = body.replace(
        "    return 0;\n",
        &format!("{terminal_assertions}    return 0;\n"),
    );

    let generated_body = crate::codegen::emit_hir_c(&program).unwrap();
    let generated = format!(
        r#"#include <stdlib.h>
static void *test_live[32];
static void *test_expected[4];
static unsigned test_allocs, test_frees, test_free_order[32];
static void *test_malloc(size_t n) {{
    void *p = malloc(n); if (!p || test_allocs == 32) abort();
    test_live[test_allocs++] = p; return p;
}}
static void test_free(void *p) {{
    if (!p) return;
    for (unsigned i=0; i<4; ++i) if (test_expected[i] == p) {{
        for (unsigned j=0; j<test_allocs; ++j) if (test_live[j] == p) {{
            test_live[j] = NULL; test_free_order[test_frees++] = i; free(p); return;
        }}
        abort();
    }}
    abort();
}}
#define malloc test_malloc
#define free test_free
{generated_body}"#
    );

    for optimization in ["-O0", "-O2"] {
        for mutation in ["none", "wrong-order", "extra-own-drop", "omit-result-drop"] {
            let mut selected_body = body.clone();
            match mutation {
                "wrong-order" => {
                    selected_body = selected_body
                        .replace(&right_drop, "__RIGHT_BORROW_DROP__")
                        .replace(&left_drop, &right_drop)
                        .replace("__RIGHT_BORROW_DROP__", &left_drop);
                }
                "extra-own-drop" => {
                    selected_body = selected_body.replace(
                        &output_second_drop,
                        &format!("    test_free(test_expected[2]);\n{output_second_drop}"),
                    );
                }
                "omit-result-drop" => {
                    selected_body = selected_body.replace(
                        &output_second_drop,
                        &format!(
                            "    ({output_second}).ptr = NULL; ({output_second}).len = 0;\n    ++spx_result_settled;\n"
                        ),
                    );
                }
                _ => {}
            }
            let root = ProbeDirectory::create().unwrap();
            let result =
                compile_and_run(&generated, &selected_body, &root, &host, optimization, None);
            root.cleanup();
            if mutation == "none" {
                let stdout = result.unwrap();
                let declaration = nominal_declaration(&entry.return_type).unwrap();
                let evaluation =
                    decode(entry.id.clone(), declaration, &stdout, 1000, borrowed_count).unwrap();
                assert_eq!(
                    evaluation.outcome,
                    RetainedCallOutcome::Returned(expected_result())
                );
                assert_eq!(
                    evaluation.cleanup_events,
                    [OwnedDataCleanupEvent::CopyOutAndSettleBytes; 2]
                );
            } else {
                let error = result.expect_err("physical cleanup-order mutant must reject");
                assert!(
                    error.message.contains("native_executor.run"),
                    "{mutation} at {optimization} must execute and trip the physical probe: {error:?}"
                );
            }
        }
    }
}
