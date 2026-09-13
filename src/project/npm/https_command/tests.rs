use std::path::Path;

#[cfg(not(windows))]
struct Output(std::path::PathBuf);

#[cfg(not(windows))]
impl Drop for Output {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const POST_SOURCE: &str = r#"
module test.https_post_npm;
permit { network.http, process.stdout.write }
@id("test.https_post_npm.run")
fn run() -> bool uses { network.http, process.stdout.write } {
    let url = [104u8, 116u8, 116u8, 112u8, 115u8, 58u8, 47u8, 47u8, 101u8, 120u8, 97u8, 109u8, 112u8, 108u8, 101u8, 46u8, 116u8, 101u8, 115u8, 116u8, 47u8];
    let body = [111u8, 107u8];
    let response = https_post(array_as_slice(url), array_as_slice(body), 1024usize);
    stdout_append(bytes_as_slice(response)) > 0usize
}
@id("main") fn main() -> i64 { 0 }
"#;

#[test]
fn post_programs_bind_the_v4_fixture_runtime() {
    let program =
        crate::hir::resolve(&crate::parse(POST_SOURCE, Path::new("https-post-npm.spx")).unwrap())
            .unwrap();
    let wasm = crate::wasm::emit_resolved_https_command_io_v1(&program, "test.https_post_npm.run")
        .unwrap();
    let artifacts = super::render_package(
        "post-test",
        "1.0.0",
        "test.https_post_npm.run",
        &wasm,
        super::requires_fixture_v4(&program),
    );
    let metadata =
        std::str::from_utf8(super::artifact_bytes(&artifacts, "semaprax.https.json").unwrap())
            .unwrap();
    let runtime =
        std::str::from_utf8(super::artifact_bytes(&artifacts, "semaprax.js").unwrap()).unwrap();
    let declarations =
        std::str::from_utf8(super::artifact_bytes(&artifacts, "semaprax.bindings.d.ts").unwrap())
            .unwrap();
    assert!(metadata.contains("\"provider\":\"fixture-only.v4\""));
    assert!(runtime.contains("spx_https_post_v1"));
    assert!(runtime.contains("if(!input.httpsPost)return 6"));
    assert!(declarations.contains("HttpsFixtureDocumentV4"));
    assert!(declarations.contains("https_post"));
}

#[cfg(not(windows))]
#[test]
fn post_package_executes_the_exact_v4_fixture_request_under_node() {
    let program = crate::hir::resolve(
        &crate::parse(POST_SOURCE, Path::new("https-post-npm-node.spx")).unwrap(),
    )
    .unwrap();
    let wasm = crate::wasm::emit_resolved_https_command_io_v1(&program, "test.https_post_npm.run")
        .unwrap();
    let artifacts =
        super::render_package("post-test", "1.0.0", "test.https_post_npm.run", &wasm, true);
    let output = Output(
        std::env::temp_dir().join(format!("semaprax-https-post-npm-{}", std::process::id())),
    );
    std::fs::create_dir_all(&output.0).unwrap();
    for artifact in &artifacts {
        std::fs::write(output.0.join(artifact.path()), artifact.bytes()).unwrap();
    }
    let script = r#"import fs from'node:fs';import{createFixture,createInvocation,instantiate}from'./semaprax.bindings.js';const wasm=new Uint8Array(fs.readFileSync('./app.wasm'));const fixture=createFixture({schema:'semaprax.network-fixture.v4',connections:[],https:[],https_post:[{url:'https://example.test/',body:'ok',response:'reply'}]});const result=await instantiate(wasm,createInvocation([],new Uint8Array(),fixture));if(!result.result||new TextDecoder().decode(result.stdout)!=='reply')throw Error('POST result');const denied=createFixture({schema:'semaprax.network-fixture.v3',connections:[],https:[]});let error;try{await instantiate(wasm,createInvocation([],new Uint8Array(),denied))}catch(value){error=value}if(!error||error.domain!=='semaprax.http.v1'||error.code!==6)throw Error('POST default deny');for(const url of['https://user@example.test/','https://example.test/#fragment']){let rejected=false;try{createFixture({schema:'semaprax.network-fixture.v4',connections:[],https:[],https_post:[{url,body:'ok',response:'reply'}]})}catch{rejected=true}if(!rejected)throw Error('POST URL fixture');}"#;
    let run = std::process::Command::new("node")
        .current_dir(&output.0)
        .args(["--input-type=module", "--eval", script])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(run.stdout.is_empty());
}
