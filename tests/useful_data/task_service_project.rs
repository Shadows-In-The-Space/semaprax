//! The task-service reference application carried end to end.
//!
//! `examples/task-service-project` is issue #194's reference application: it
//! composes the bundled `std.auth` and `std.jobs` dependencies into a full
//! register/log-in/create-update-record/enqueue-complete-job/query-status/
//! log-out scenario, plus row-level-unauthorized and invalid-input rejection,
//! in deterministic fixture mode. Its own README and
//! `docs/COMPLETION-MATRIX.md` record that this project was, until this
//! module, "manually observed to pass" only -- no test under `tests/` or
//! `src/**/tests.rs` executed `check`/`test`/`run` over it, so nothing
//! regressed it in CI. This module is that regression gate.
//!
//! Canonical formatting for every module under `examples/task-service-project`
//! is already covered by `tests/examples.rs::every_example_below_the_top_level_is_canonical`,
//! so this module does not repeat that check.
//!
//! `docs/COMPLETION-MATRIX.md`'s reference-application row (and issue #194's
//! own audit trail) recorded a real gap here: unlike its two sibling
//! Useful-Data-v1 reference projects (`agent_response_project.rs`,
//! `vector_stats_project.rs`), this project's regression gate only ever ran
//! the interpreter lane -- no test exercised native C11 or Core Wasm. That
//! meant a native- or Wasm-backend miscompile of the byte-slice grammar
//! checks (`identifier_is_valid`, `method_is_rejected`) or the auth/jobs
//! scalar state machines this reference application exists to demonstrate
//! could pass CI silently. `entry_and_conformance_return_zero_on_interpreter_native_and_wasm`
//! below closes that gap the same way the sibling projects already do.

use std::path::{Path, PathBuf};
use std::process::Command;

use semaprax::project::{
    ProjectCandidate, SemanticQuery, SemanticTransaction, SemanticTransactionRenameDisplayName,
    SemanticTransactionReplaceExpression, SemanticTransactionV2, SemanticWorkspaceService,
};
use semaprax::workspace_analysis::{
    WorkspaceAnalysisTargetKind, WorkspaceContextOptions, WorkspaceImpactOptions,
};
use semaprax::{codegen, project};
use serde_json::json;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/task-service-project")
}

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "semaprax-task-service-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path.canonicalize().unwrap()
}

fn compile_c(source: &str, output: &Path, optimization: &str) {
    let c_path = output.with_extension("c");
    std::fs::write(&c_path, source).unwrap();
    let result = Command::new("clang")
        .args(["-std=c11", optimization, "-Wall", "-Wextra", "-Werror"])
        .arg(&c_path)
        .arg("-o")
        .arg(output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "clang {optimization} failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn run_returns_zero(path: &Path) {
    let output = Command::new(path).output().unwrap();
    assert!(output.status.success(), "{} failed", path.display());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "0",
        "{} did not report success",
        path.display()
    );
}

/// `check`, `test`, and `run` all pass on the interpreter, and the manifest's
/// bundled dependencies resolve to the compiler's own source rather than
/// anything vendored by hand.
///
/// Negative control (performed manually, not committed): flipping
/// `task_service.core.task_owner_authorized`'s `&&` to `||` makes
/// `task_service.tests.unauthorized_is_rejected` false, so
/// `task_service.tests.main` returns `1` and this assertion on
/// `execute_test()`'s outcome fails. Restoring the source turns the gate
/// green again. This proves the gate actually exercises the row-level
/// authorization the reference application exists to demonstrate, rather
/// than passing regardless of the project's behavior.
#[test]
fn check_test_and_run_pass_on_the_interpreter() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        assert!(
            snapshot
                .workspace_manifest()
                .contains("dependencies/std.auth/0.1.0"),
            "the workspace does not carry the bundled std.auth source"
        );
        assert!(
            snapshot
                .workspace_manifest()
                .contains("dependencies/std.jobs/0.1.0"),
            "the workspace does not carry the bundled std.jobs source"
        );
        assert!(
            snapshot
                .workspace_manifest()
                .contains("dependencies/std.metrics/0.1.0"),
            "the workspace does not carry the bundled std.metrics source"
        );
        assert!(
            snapshot
                .workspace_manifest()
                .contains("dependencies/std.export.policy/0.1.0"),
            "the workspace does not carry the bundled std.export.policy source"
        );
        let options = project::ProjectExecutionOptions::default();
        assert_eq!(
            snapshot.execute_entry(&options)?.outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "the acceptance scenario entry did not report success"
        );
        assert_eq!(
            snapshot.execute_test(&options)?.outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "the project's own named test cases (success, unauthorized, \
             invalid, duplicate-enqueue) did not all pass"
        );
        Ok(())
    })
    .unwrap();
}

/// The manifest's declared `[exports].web` roots are real public functions
/// reachable in the retained revision's semantic graph, the same shape
/// `tests/useful_data/agent_response_project.rs` asserts for its sibling
/// reference project.
#[test]
fn the_declared_web_exports_are_reachable_public_functions() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let public = snapshot.retain_revision();
        let ids = public
            .public_api_program()
            .functions
            .iter()
            .map(|function| function.id.clone())
            .collect::<Vec<_>>();
        // Guard against the vacuous pass: an empty selection would make the
        // loop below assert nothing at all. This project declares exactly
        // two roots in its `[exports].web`.
        assert_eq!(
            snapshot.manifest().web_exports().len(),
            2,
            "the reference application must still declare its two web export roots"
        );
        for selected in snapshot.manifest().web_exports() {
            assert!(
                ids.iter().any(|id| id.as_str() == selected.as_str()),
                "missing selected export root {selected}"
            );
            assert!(snapshot.semantic_graph().contains(selected));
        }
        Ok(())
    })
    .unwrap();
}

/// Entry and conformance both return `0` on the interpreter and native C11 at
/// `-O0` and `-O2`; Core Wasm under Node executes the conformance closure
/// only. The Wasm harness below is the same generic byte-slice ABI shim
/// `tests/useful_data/agent_response_project.rs` uses (this project's own
/// `borrow Slice<u8>` grammar checks -- `identifier_is_valid`,
/// `method_is_rejected` -- need the same `spx_bytes_*` import set that
/// project's byte-slice scan functions do).
///
/// Negative control (performed manually, not committed): swapping
/// `method_is_valid`'s `value <= 90u8` bound to `value <= 89u8` makes the
/// reference application's own `GET` acceptance check fail identically on
/// all three lanes -- `execute_test`, the compiled C binaries, and the Node
/// Wasm run all stop returning `0`. Restoring the source turns every lane
/// green again, which is what proves this gate actually drives native and
/// Wasm codegen rather than only the interpreter path the older gate ran.
#[test]
fn entry_and_conformance_return_zero_on_interpreter_native_and_wasm() {
    let scratch = scratch("lanes");
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let options = project::ProjectExecutionOptions::default();
        assert_eq!(
            snapshot.execute_entry(&options)?.outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "the entry failed on the interpreter"
        );
        assert_eq!(
            snapshot.execute_test(&options)?.outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "conformance failed on the interpreter"
        );
        for (role, program) in [
            ("entry", snapshot.entry_program()),
            ("tests", snapshot.test_program()),
        ] {
            let c = codegen::emit_hir_c(program).map_err(|error| vec![error])?;
            for optimization in ["-O0", "-O2"] {
                let binary = scratch.join(format!("{role}{}", optimization.to_lowercase()));
                compile_c(&c, &binary, optimization);
                run_returns_zero(&binary);
            }
        }
        let wasm = snapshot.test_wasm_module()?;
        let wasm_path = scratch.join("tests.wasm");
        std::fs::write(&wasm_path, wasm).unwrap();
        let script = scratch.join("tests.mjs");
        std::fs::write(
            &script,
            r#"import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
const bytes = await readFile("./tests.wasm");
const checked = (operation) => (a, b) => { const value = operation(a, b); if (value < -(1n<<63n) || value > (1n<<63n)-1n) throw new RangeError(); return value; };
const entries = new Map(); let next = 1; let linked;
const decode = carrier => { const word = BigInt.asUintN(64, carrier), length = Number(word & 0xffffffffn), root = Number((word >> 32n) & 0xffffffffn); return { word, length, root, tagged: (root & 0x80000000) !== 0, token: root & 0x7fffffff }; };
const read = decoded => { if ((decoded.root & 0xc0000000) === 0x40000000) { const pointer = (decoded.root & 0xffff) * 8, key = (decoded.root >>> 16) & 0x1fff, view = new DataView((linked.instance.exports.__spx_byte_memory ?? linked.instance.exports.memory).buffer); if (pointer + 32 > view.byteLength || view.getUint32(pointer, true) !== key || view.getUint32(pointer + 4, true) !== pointer || Number(view.getBigUint64(pointer + 24, true)) !== decoded.length) throw new Error("corrupt range descriptor"); const root = view.getBigInt64(pointer + 8, true), offset = Number(view.getBigUint64(pointer + 16, true)), all = read(decode(root)); if (offset > all.length || decoded.length > all.length - offset) throw new Error("byte range"); return all.slice(offset, offset + decoded.length); } if (decoded.tagged) { const value = entries.get(decoded.token); if (!(value instanceof Uint8Array) || value.length !== decoded.length) throw new Error("stale byte token"); return value; } const memory = new Uint8Array((linked.instance.exports.__spx_byte_memory ?? linked.instance.exports.memory).buffer); if (decoded.root > memory.length - decoded.length) throw new Error("byte range"); return memory.slice(decoded.root, decoded.root + decoded.length); };
const allocate = bytes => { const token = next++, owned = new Uint8Array(bytes); entries.set(token, owned); return BigInt.asIntN(64, ((0x80000000n | BigInt(token)) << 32n) | BigInt(owned.length)); };
const imports = {env:{spx_add:checked((a,b)=>a+b),spx_sub:checked((a,b)=>a-b),spx_mul:checked((a,b)=>a*b),spx_div:(a,b)=>a/b,spx_rem:(a,b)=>a%b,spx_neg:(a)=>-a,spx_contract_fail:()=>{throw new Error();},
spx_bytes_copy:c=>allocate(read(decode(c))),spx_bytes_get:(c,i)=>{ const b = read(decode(c)), u = BigInt.asUintN(64, i); return u >= BigInt(b.length) ? -1 : b[Number(u)]; },spx_bytes_drop:c=>{ const d = decode(c); read(d); entries.delete(d.token); },spx_bytes_as_slice:c=>{ const d = decode(c); read(d); return BigInt.asIntN(64, d.word); }}};
linked = await WebAssembly.instantiate(bytes, imports);
assert.equal(linked.instance.exports.semaprax_main(), 0n);
"#,
        )
        .unwrap();
        let node = Command::new("node")
            .arg(script.file_name().unwrap())
            .current_dir(&scratch)
            .output()
            .unwrap();
        assert!(
            node.status.success(),
            "Node conformance closure failed: {}",
            String::from_utf8_lossy(&node.stderr)
        );
        Ok(())
    })
    .unwrap();
    let _ = std::fs::remove_dir_all(scratch);
}

/// Issue #194 step 7's complete stable-ID workflow: inspect, context,
/// impact, preview, candidate apply, and retest. The target is the real
/// public domain wrapper rather than an unused helper, so this proves that a
/// human-facing rename preserves its web-export identity and migrates checked
/// in-module callers without changing the service outcome.
///
/// `src/core.spx` is deliberately comment-free canonical because it is the
/// source this operation rewrites. `src/app.spx`, `src/tests.spx`, and the
/// bundled dependency closure retain their own comments; issue #274's
/// differential precondition preserves every untouched source byte exactly.
/// Applying here means producing an immutable `ProjectCandidate`, not writing
/// or publishing any checked-in source.
#[test]
fn stable_id_rename_inspect_preview_apply_and_retest_preserve_the_service() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let revision = snapshot.retain_revision();
        let target = "task_service.core.identifier_is_valid";
        let old_name = "identifier_is_valid";
        let new_name = "identifier_name_is_valid";
        let base_core = revision
            .sources()
            .iter()
            .find(|source| source.path() == "src/core.spx")
            .expect("the retained project must carry src/core.spx")
            .source()
            .to_owned();
        let (_, core_comments) =
            semaprax::parse_with_comments(&base_core, Path::new("src/core.spx")).unwrap();
        assert!(
            core_comments.items.is_empty(),
            "the selected rename source must remain comment-free canonical"
        );

        let service = SemanticWorkspaceService::open(revision.clone())?;
        let workspace_revision = service.active_generation().workspace_revision().to_owned();
        let discovery = SemanticQuery::available_operations(&workspace_revision, target)?;
        let discovery = service.query(discovery.to_json().as_bytes())?;
        let payload: serde_json::Value = serde_json::from_str(discovery.payload())
            .expect("available-operations payload must be valid JSON");
        let rename_operation = payload["operations"]
            .as_array()
            .expect("available-operations payload must carry an operations array")
            .iter()
            .find(|operation| operation["kind"] == "rename_display_name")
            .expect("a monomorphic, explicitly-identified, non-main function must offer rename");
        let discovered_old_name = rename_operation["expected_old_value"]
            .as_str()
            .expect("rename_display_name must report the function's current display name");
        assert_eq!(
            discovered_old_name, old_name,
            "inspect must report this declaration's real current name"
        );

        let context = revision.semantic_context(
            WorkspaceAnalysisTargetKind::Declaration,
            target,
            WorkspaceContextOptions::default(),
        )?;
        assert!(
            context.contains(target),
            "context must mention the declaration under rename"
        );

        let impact = revision.semantic_impact(
            WorkspaceAnalysisTargetKind::Declaration,
            target,
            WorkspaceImpactOptions::default(),
        )?;
        assert!(
            impact.contains(target),
            "impact must mention the declaration under rename"
        );

        let transaction = SemanticTransaction::rename_display_name(
            &workspace_revision,
            SemanticTransactionRenameDisplayName::new(target, discovered_old_name, new_name),
        )?;
        let artifacts = service.validate_transaction(transaction.to_json().as_bytes())?;
        assert!(artifacts.impact().contains(target));
        assert!(artifacts.review().contains(target));
        let candidate = artifacts.candidate();
        let candidate_revision = candidate.revision();
        assert_ne!(
            candidate_revision.project_revision(),
            revision.project_revision()
        );
        assert!(candidate_revision.semantic_graph().contains(target));
        assert!(
            candidate_revision
                .manifest()
                .web_exports()
                .iter()
                .any(|export| export.as_str() == target),
            "the stable web-export identity must survive its display rename"
        );
        let candidate_core = candidate_revision
            .sources()
            .iter()
            .find(|source| source.path() == "src/core.spx")
            .expect("the candidate must retain src/core.spx")
            .source();
        assert!(candidate_core.contains("@id(\"task_service.core.identifier_is_valid\")"));
        assert!(candidate_core.contains("fn identifier_name_is_valid("));
        assert!(candidate_core.contains("identifier_name_is_valid(username)"));
        assert!(candidate_core.contains("identifier_name_is_valid(array_as_slice(table_name))"));
        assert!(
            candidate_core.contains("!identifier_name_is_valid(array_as_slice(bad_identifier))")
        );
        assert_eq!(
            candidate_revision
                .execute_entry(&project::ProjectExecutionOptions::default())?
                .outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "the renamed candidate entry must preserve the acceptance scenario"
        );
        assert_eq!(
            candidate_revision
                .execute_test(&project::ProjectExecutionOptions::default())?
                .outcome(),
            &project::ProjectExecutionOutcome::Returned(0),
            "the renamed candidate must preserve every named conformance case"
        );
        assert_eq!(
            revision
                .sources()
                .iter()
                .find(|source| source.path() == "src/core.spx")
                .expect("the immutable base must retain src/core.spx")
                .source(),
            base_core,
            "candidate application must not mutate the checked-in base source"
        );
        Ok(())
    })
    .unwrap();
}

/// Issue #277's acceptance criterion, using this project's real
/// `std.auth`/`std.jobs` closure rather than a synthetic fixture: a
/// `ReplaceExpression` v2 preview succeeds against a project whose own
/// edited source is comment-free while its bundled dependency closure still
/// carries comments (`std.auth` alone carries 253 `//` lines, `std.jobs`
/// 34). The v1 workflow above rewrites the checked-in comment-free
/// `src/core.spx`; this v2 case separately proves that comments in all
/// untouched own and bundled sources do not widen the rewrite domain.
#[test]
fn replace_expression_v2_succeeds_against_the_commented_bundled_dependency_closure() {
    let scratch = scratch("v2-bundled-comments");
    std::fs::create_dir_all(scratch.join("src")).unwrap();
    std::fs::copy(
        fixture().join("semaprax.toml"),
        scratch.join("semaprax.toml"),
    )
    .unwrap();
    for file in ["src/app.spx", "src/tests.spx"] {
        let source = std::fs::read_to_string(fixture().join(file)).unwrap();
        let (program, comments) = semaprax::parse_with_comments(&source, Path::new(file)).unwrap();
        assert!(
            !comments.items.is_empty(),
            "{file} must really carry comments in the checked-in project, or this copy is not \
             exercising the strip this test relies on"
        );
        std::fs::write(scratch.join(file), semaprax::format::canonical(&program)).unwrap();
    }
    std::fs::copy(fixture().join("src/core.spx"), scratch.join("src/core.spx")).unwrap();

    project::with_authenticated_project(&scratch.join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let revision = snapshot.retain_revision();

        let core_source = revision
            .sources()
            .iter()
            .find(|source| source.path() == "src/core.spx")
            .expect("revision must carry src/core.spx");
        let (_, core_comments) =
            semaprax::parse_with_comments(core_source.source(), Path::new("src/core.spx")).unwrap();
        assert!(
            core_comments.items.is_empty(),
            "src/core.spx must be comment-free"
        );
        for path in ["src/app.spx", "src/tests.spx"] {
            let own_source = revision
                .sources()
                .iter()
                .find(|source| source.path() == path)
                .unwrap_or_else(|| panic!("revision must carry {path}"));
            let (_, comments) =
                semaprax::parse_with_comments(own_source.source(), Path::new(path)).unwrap();
            assert!(
                !comments.items.is_empty(),
                "{path} must retain comments because v2 does not rewrite it"
            );
        }
        for (dependency, path) in [
            ("std.auth", "dependencies/std.auth/0.1.0/auth.spx"),
            ("std.jobs", "dependencies/std.jobs/0.1.0/jobs.spx"),
        ] {
            let dependency_source = revision
                .sources()
                .iter()
                .find(|source| source.path() == path)
                .unwrap_or_else(|| panic!("revision must carry bundled {dependency}"));
            let (_, comments) =
                semaprax::parse_with_comments(dependency_source.source(), Path::new(path)).unwrap();
            assert!(
                !comments.items.is_empty(),
                "bundled {dependency} must still carry its checked-in comments, or this test is \
                 not exercising the bundled-dependency closure issue #277 is about"
            );
        }

        // Select `task_service.core.identifier_byte_ok`'s last disjunct
        // (`byte == 95u8`) and replace it with itself: this test's claim is
        // that the *preview validates*, not that the replacement changes
        // behavior (`ReplaceExpression`'s own nonclaims explicitly exclude
        // behavioral equivalence).
        let target = "task_service.core.identifier_byte_ok";
        let candidate =
            ProjectCandidate::open(revision.clone(), revision.project_revision()).unwrap();
        let catalog: serde_json::Value =
            serde_json::from_str(&candidate.expression_catalog(target).unwrap()).unwrap();
        let owner_path = catalog["source"]["path"].as_str().unwrap().to_owned();
        let owner_source = revision
            .sources()
            .iter()
            .find(|source| source.path() == owner_path)
            .unwrap()
            .source();
        let row = catalog["expressions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| {
                row["phase"] == "body"
                    && row["replaceable"] == true
                    && row["source_span"]["start"]
                        .as_u64()
                        .zip(row["source_span"]["end"].as_u64())
                        .and_then(|(start, end)| owner_source.get(start as usize..end as usize))
                        == Some("byte == 95u8")
            })
            .expect("identifier_byte_ok must offer a replaceable `byte == 95u8` body expression");
        let expression_id = row["expression_id"].as_str().unwrap().to_owned();

        let workspace = revision.canonical_workspace_revision()?;
        let transaction = SemanticTransactionV2::replace_expression(
            workspace.workspace_revision(),
            SemanticTransactionReplaceExpression::new(
                target,
                &expression_id,
                "byte == 95u8",
                json!({
                    "kind": "binary", "op": "==",
                    "left": {"kind": "place", "name": "byte"},
                    "right": {"kind": "u8", "value": 95}
                }),
            ),
        )?;
        let _ = transaction
            .validate(revision.clone())
            .unwrap_or_else(|errors| {
                panic!(
                "ReplaceExpression v2 must succeed against a comment-free own source even though \
                 the bundled std.auth/std.jobs closure carries comments (issue #277): {errors:?}"
            )
            });
        Ok(())
    })
    .unwrap();
}

/// The real reference application composes database, HTTP, metric, exporter,
/// and tracing decision layers. Pin the direct packages and transitive
/// closures; source-level tests cover request, migration, metric and export
/// refusals, while the cross-backend gate below executes them. These remain
/// pure policy dependencies, not database, transport, emission, export, or
/// span support.
#[test]
fn observability_policy_packages_fit_the_real_reference_application() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let manifest = snapshot.workspace_manifest();
        for package in [
            "dependencies/std.db/0.1.0",
            "dependencies/std.http/0.1.0",
            "dependencies/std.metrics/0.1.0",
            "dependencies/std.export.policy/0.1.0",
            "dependencies/std.tracing/0.1.0",
            "dependencies/std.encoding/0.1.0",
            "dependencies/std.log.redact/0.1.0",
            "dependencies/std.num.overflow/0.1.0",
        ] {
            assert!(
                manifest.contains(package),
                "the workspace does not carry `{package}` from the observability policy closure"
            );
        }
        Ok(())
    })
    .expect("the checked-in observability policy closure must fit under SPX-G171");
}
