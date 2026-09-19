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
    SemanticQuery, SemanticTransaction, SemanticTransactionRenameDisplayName,
    SemanticWorkspaceService,
};
use semaprax::workspace_analysis::{
    WorkspaceAnalysisTargetKind, WorkspaceContextOptions, WorkspaceImpactOptions,
};
use semaprax::{codegen, project};

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
/// bundled dependencies resolve to the compiler's own `std.auth`/`std.jobs`
/// source rather than anything vendored by hand.
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

/// Entry and conformance both return `0` on all three execution lanes:
/// interpreter, native C11 at `-O0` and `-O2`, and Core Wasm under Node. The
/// Wasm harness below is the same generic byte-slice ABI shim
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

/// Issue #194 step 7 asks for one stable-ID rename walked end to end --
/// inspect, context, impact, preview, apply, retest -- against the reference
/// application. Inspect/context/impact all work on this project exactly as
/// designed: this test pins that. The write side does not, and this test
/// pins that too, rather than routing around it or asserting only the parts
/// that pass.
///
/// **New evidence, not previously documented**: Universal Semantic
/// Transaction v1's `rename_display_name` requires the *entire* workspace --
/// this project's own three modules **and every bundled dependency source
/// reached**, per `comment_free_canonical_workspace` in
/// `src/project/semantic_transaction.rs` iterating `revision.sources()`,
/// which `src/project/build.rs::build_owned` populates from the same vector
/// `standard_dependencies::extend_sources` appends bundled package source
/// into -- to be entirely comment-free. `std.auth` carries 253 `//` comment
/// lines and `std.jobs` 34 (`rg -c '//' std/auth/src/auth.spx
/// std/jobs/src/jobs.spx`), so `preview` below fails closed with
/// `SPX-G525` ("semantic transaction v1 requires comment-free canonical
/// source") on first use, before any candidate is derived. Because that
/// dependency source is compiler-bundled and immutable
/// (`src/project/standard_dependencies.rs`), no project consuming
/// `std.auth`/`std.jobs`/`std.log`/any other commented bundled package can
/// ever satisfy this precondition by editing its own source -- this is not a
/// gap in this project's authoring, it is a standing architectural
/// intersection between the comment-free-source requirement and having any
/// commented bundled dependency at all. `SPX-G525` and `SPX-G171` (this
/// project's README) are two independent capacity/precondition ceilings that
/// both happen to bite the same two-dependency reference application.
///
/// This assertion is a stable regression, not a shrug: if a future change
/// lifts or narrows the comment-free-workspace precondition (e.g. scoping it
/// to only the renamed function's own module), this test starts failing on
/// the `Err` match and must be revisited to demonstrate the full apply/retest
/// steps this issue's acceptance criterion actually asks for.
#[test]
fn stable_id_rename_inspect_and_context_succeed_preview_pins_the_comment_precondition() {
    project::with_authenticated_project(&fixture().join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let revision = snapshot.retain_revision();
        let target = "task_service.core.identifier_byte_ok";
        let old_name = "identifier_byte_ok";

        // 1. Inspect: what operations are legal on this declaration, and its
        // exact current display name, discovered rather than assumed. The
        // selected revision comes from the service's own active generation
        // (the same source `semaprax change preview` reads via its
        // `selected_revision` helper), not the plain `ProjectRevision`'s own
        // digest -- the two are computed differently and a query against the
        // wrong one fails closed with `SPX-G533` ("stale") rather than
        // silently matching.
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

        // 2. Context: bounded forward/reverse neighborhood of the target.
        let context = revision.semantic_context(
            WorkspaceAnalysisTargetKind::Declaration,
            target,
            WorkspaceContextOptions::default(),
        )?;
        assert!(
            context.contains(target),
            "context must mention the declaration under rename"
        );

        // 3. Impact: what the workspace's reverse dependency closure is.
        let impact = revision.semantic_impact(
            WorkspaceAnalysisTargetKind::Declaration,
            target,
            WorkspaceImpactOptions::default(),
        )?;
        assert!(
            impact.contains(target),
            "impact must mention the declaration under rename"
        );

        // 4. Preview: this is where the walk stops. Validating the exact
        // rename transaction against the selected workspace revision fails
        // closed on the bundled dependency source's comments, not on
        // anything this project's own three files contain.
        let transaction = SemanticTransaction::rename_display_name(
            &workspace_revision,
            SemanticTransactionRenameDisplayName::new(
                target,
                discovered_old_name,
                "identifier_char_is_safe",
            ),
        )?;
        let outcome = service.validate_transaction(transaction.to_json().as_bytes());
        let Err(diagnostics) = outcome else {
            panic!(
                "rename preview unexpectedly succeeded; if the comment-free-workspace \
                 precondition was narrowed or lifted, replace this test with the full \
                 apply/retest walk issue #194 step 7 actually asks for"
            );
        };
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "SPX-G525"),
            "expected SPX-G525 (comment-free canonical source), got {diagnostics:?}"
        );
        Ok(())
    })
    .unwrap();
}
