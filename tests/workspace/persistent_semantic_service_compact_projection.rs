use semaprax::compact_semantic_projection::{encode_selected, ProjectionSelection};
use semaprax::project::{
    ProjectFrontendCache, ProjectFrontendSource, ProjectManifest, ProjectRevision,
};
use semaprax::semantic_service_transport::SemanticWorkspaceStdioSession;
use serde_json::{json, Value};
use std::sync::Arc;

fn revision() -> Arc<ProjectRevision> {
    let manifest = ProjectManifest::parse(include_str!(
        "../../examples/frame-payload-project/semaprax.toml"
    ))
    .unwrap();
    let sources = [
        (
            "src/app.spx",
            include_str!("../../examples/frame-payload-project/src/app.spx"),
        ),
        (
            "src/frame.spx",
            include_str!("../../examples/frame-payload-project/src/frame.spx"),
        ),
        (
            "src/tests.spx",
            include_str!("../../examples/frame-payload-project/src/tests.spx"),
        ),
    ]
    .into_iter()
    .map(|(path, source)| ProjectFrontendSource::new(path, source).unwrap())
    .collect::<Vec<_>>();
    ProjectFrontendCache::new_with_semantic_cache()
        .build(&manifest, &sources)
        .unwrap()
        .into_revision()
}

fn call(session: &mut SemanticWorkspaceStdioSession, id: u64, params: Value) -> Value {
    let request = json!({
        "jsonrpc":"2.0",
        "id":id,
        "method":"workspace/compact-projection",
        "params":params,
    });
    serde_json::from_slice(
        &session
            .handle_frame(request.to_string().as_bytes())
            .unwrap(),
    )
    .unwrap()
}

fn success(response: &Value) -> &Value {
    assert!(response.get("error").is_none(), "{response}");
    &response["result"]
}

#[test]
fn compact_projection_is_exactly_selected_from_the_retained_project_revision() {
    let revision = revision();
    let expected = encode_selected(ProjectionSelection::ApiSurface {
        revision: revision.as_ref(),
    })
    .unwrap();
    let mut session = SemanticWorkspaceStdioSession::open(Arc::clone(&revision)).unwrap();
    let opened = json!({"jsonrpc":"2.0","id":0,"method":"workspace/open","params":{}});
    let _ = session.handle_frame(opened.to_string().as_bytes()).unwrap();
    let workspace = session
        .service()
        .active_generation()
        .workspace_revision()
        .to_owned();

    let response = call(
        &mut session,
        1,
        json!({
            "expected_workspace_revision":workspace,
            "profile":"api-surface-v8-owned-data",
            "encoding":"text",
        }),
    );
    let response = success(&response);
    let payload = &response["payload"];
    assert_eq!(response["authority"], false);
    assert_eq!(payload["authority"], false);
    assert_eq!(payload["profile"], expected.profile());
    assert_eq!(payload["root"], expected.root());
    assert_eq!(payload["source_revision"], expected.source_revision());
    assert_eq!(payload["source_digest"], expected.source_digest());
    assert_eq!(payload["value"], expected.to_text());
    let model = call(
        &mut session,
        2,
        json!({
            "expected_workspace_revision": workspace,
            "profile": "api-surface-v8-owned-data", "encoding": "model-text"
        }),
    );
    let model = &success(&model)["payload"];
    assert_eq!(model["format_version"], 2);
    assert_eq!(model["authority"], false);
    let decoded = semaprax::compact_semantic_projection::decode_model_text(
        model["value"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    assert_eq!(
        decoded.reconstructed().unwrap(),
        expected.reconstructed().unwrap()
    );
}

#[test]
fn compact_projection_refuses_stale_revisions_and_unknown_parameters() {
    let mut session = SemanticWorkspaceStdioSession::open(revision()).unwrap();
    let opened = json!({"jsonrpc":"2.0","id":0,"method":"workspace/open","params":{}});
    let _ = session.handle_frame(opened.to_string().as_bytes()).unwrap();
    let current = session
        .service()
        .active_generation()
        .workspace_revision()
        .to_owned();

    let stale = call(
        &mut session,
        1,
        json!({
            "expected_workspace_revision":format!("sha256:{}", "0".repeat(64)),
            "profile":"api-surface-v8-owned-data",
            "encoding":"binary",
        }),
    );
    assert_eq!(stale["error"]["data"]["diagnostics"][0]["code"], "SPX-G530");

    let unknown = call(
        &mut session,
        2,
        json!({
            "expected_workspace_revision":current,
            "profile":"api-surface-v8-owned-data",
            "encoding":"binary",
            "path":"/host/path",
        }),
    );
    assert_eq!(
        unknown["error"]["data"]["diagnostics"][0]["code"],
        "SPX-G548"
    );
}
