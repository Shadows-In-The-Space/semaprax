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
/// **Issue #274 narrowed the precondition, and this project still refuses --
/// for a different, caller-actionable reason.** Universal Semantic
/// Transaction v1 used to require the *entire* workspace, every bundled
/// dependency source included, to be comment-free canonical, because
/// `ProjectCandidate::apply`'s `materialize` step re-derived every source
/// through the comment-dropping canonical formatter. `std.auth` carries 253
/// `//` lines and `std.jobs` 34, and that source is compiler-bundled and
/// immutable (`src/project/standard_dependencies.rs`), so the precondition
/// was unsatisfiable by construction for any consumer of a commented bundled
/// package. `materialize` now preserves an untouched source's exact base
/// bytes, and `src/project/canonical_sources.rs` (shared by the v1 and v2
/// transaction kernels since issue #277) requires comment-free canonical
/// source only of the sources a transaction actually
/// rewrites. Verified directly: with this project's own three modules copied
/// out and stripped of comments, `semaprax change preview <copy>
/// rename-display-name task_service.core.identifier_byte_ok
/// identifier_char_is_safe` now succeeds against the same commented
/// `std.auth` + `std.jobs` closure.
///
/// What still refuses here is this project's **own** source: `src/core.spx`,
/// which owns `task_service.core.identifier_byte_ok` and is therefore the
/// source the rename rewrites, carries 29 comment lines of its own (issue
/// #274's summary asserted the project's three modules were comment-free;
/// they are not). A rewritten source's comments would be dropped by the
/// canonical formatter, so refusing is correct -- and now fixable by editing
/// this project, which the old whole-workspace scope never was.
///
/// `SPX-G525` and `SPX-G171` (this project's README) remain two independent
/// ceilings that both happen to bite the same two-dependency reference
/// application.
///
/// This assertion is a stable regression, not a shrug: if this project's own
/// `src/core.spx` is ever authored comment-free, this test starts failing on
/// the `Err` match and must be revisited to demonstrate the full apply/retest
/// steps issue #194 step 7's acceptance criterion actually asks for.
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
        // closed on the comments in this project's own `src/core.spx` -- the
        // source the rename rewrites -- no longer on the immutable bundled
        // dependency source the project cannot edit (issue #274).
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

/// Issue #277's acceptance criterion, using this project's real
/// `std.auth`/`std.jobs` closure rather than a synthetic fixture: a
/// `ReplaceExpression` v2 preview succeeds against a project whose own
/// edited source is comment-free while its bundled dependency closure still
/// carries comments (`std.auth` alone carries 253 `//` lines, `std.jobs`
/// 34). This is the v2 counterpart of
/// `stable_id_rename_inspect_and_context_succeed_preview_pins_the_comment_precondition`
/// above, which pins the *same* comment precondition for v1's
/// `rename_display_name` against the checked-in project (whose own
/// `src/core.spx` still carries comments, so that v1 preview still refuses
/// for a project-actionable reason). Here the project's own three modules
/// are copied out and stripped of comments first -- `std.auth` and
/// `std.jobs` are compiler-bundled and untouched either way -- so nothing
/// about the source this transaction actually rewrites can trip `SPX-G525`,
/// and only the ported #277 fix (`src/project/canonical_sources.rs`'s
/// differential, rewrite-domain check, shared by v1 and v2) lets this
/// succeed.
#[test]
fn replace_expression_v2_succeeds_against_the_commented_bundled_dependency_closure() {
    let scratch = scratch("v2-bundled-comments");
    std::fs::create_dir_all(scratch.join("src")).unwrap();
    std::fs::copy(
        fixture().join("semaprax.toml"),
        scratch.join("semaprax.toml"),
    )
    .unwrap();
    for file in ["src/app.spx", "src/core.spx", "src/tests.spx"] {
        let source = std::fs::read_to_string(fixture().join(file)).unwrap();
        let (program, comments) = semaprax::parse_with_comments(&source, Path::new(file)).unwrap();
        assert!(
            !comments.items.is_empty(),
            "{file} must really carry comments in the checked-in project, or this copy is not \
             exercising the strip this test relies on"
        );
        std::fs::write(scratch.join(file), semaprax::format::canonical(&program)).unwrap();
    }

    project::with_authenticated_project(&scratch.join("semaprax.toml"), |snapshot| {
        snapshot.check()?;
        let revision = snapshot.retain_revision();

        // The fixture really is non-vacuous: this project's own three
        // modules are now comment-free, but the bundled `std.auth` and
        // `std.jobs` closure this project depends on still carries its
        // checked-in comments untouched.
        for path in ["src/app.spx", "src/core.spx", "src/tests.spx"] {
            let own_source = revision
                .sources()
                .iter()
                .find(|source| source.path() == path)
                .unwrap_or_else(|| panic!("revision must carry {path}"));
            let (_, comments) =
                semaprax::parse_with_comments(own_source.source(), Path::new(path)).unwrap();
            assert!(
                comments.items.is_empty(),
                "{path} must be comment-free after the strip"
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

/// `docs/COMPLETION-MATRIX.md`'s reference-application row names two
/// concrete, checkable follow-ons: whether `std.log` and `std.tracing` can
/// be wired into this project so it emits structured log events and trace
/// context, and whether this project's manifest qualifies for `semaprax
/// build --target oci`. This test pins the first: adding `std.tracing` --
/// the lighter of the two candidates, since `std.encoding` is its only
/// transitive dependency, against `std.log`'s four (`std.data.json.utf8`,
/// `std.data.json.write`, `std.io`, `std.log.redact`) -- to this project's
/// existing `std.auth` + `std.jobs` closure is refused by `SPX-G171` before
/// this project's own three source files are even resolved: the static
/// admission pre-charge sums only the five dependency modules reached
/// (`std.auth`, `std.bytes`, `std.encoding`, `std.jobs`, `std.tracing`, in
/// canonical path order) to 19,160,008 bytes against the 18,874,368-byte
/// cap -- 101.5%, over before a single byte of this project's own source is
/// counted. `std.log`'s heavier five-package closure was independently
/// confirmed refused the same way in this session (manual reproduction, not
/// committed as a second test to avoid duplicating this one's shape): its
/// pre-charge reaches 19,080,680 bytes from only the first five
/// alphabetically-ordered dependency modules, before `std.jobs`, `std.log`,
/// or `std.log.redact` are even reached. Because the pre-charge sums whole
/// reachable *modules* regardless of which functions this project's own
/// source calls (`docs/COMPLETION-MATRIX.md`'s own recorded measurement),
/// no reduction of this project's own three files -- which this test does
/// not even need to touch, since the probe module below is one trivial
/// extra function -- can close this gap: the project's checked-in baseline
/// (`std.auth` + `std.jobs`) alone already sits at roughly 92.7% of the cap
/// (this project's own README), leaving no room for either candidate
/// package's whole-file charge. This is why neither package is wired into
/// the checked-in project today, and it is a stable regression: if a future
/// change to `SPX-G171`'s accounting (or to the baseline closure) ever
/// admits this composition, this test starts failing on the `Err` match and
/// must be replaced with the real `std.log`/`std.tracing` wiring issue #194
/// asks for.
#[test]
fn adding_std_tracing_to_the_dependency_closure_exceeds_the_builder_bytes_cap() {
    let scratch = scratch("tracing-overflow");
    std::fs::create_dir_all(scratch.join("src")).unwrap();

    let manifest = std::fs::read_to_string(fixture().join("semaprax.toml")).unwrap();
    let augmented_manifest = manifest.replacen(
        "std.jobs = \"=0.1.0\"\n",
        "std.jobs = \"=0.1.0\"\nstd.tracing = \"=0.1.0\"\n",
        1,
    );
    assert_ne!(
        augmented_manifest, manifest,
        "the manifest's std.jobs dependency line must still be present to patch"
    );
    std::fs::write(scratch.join("semaprax.toml"), augmented_manifest).unwrap();

    std::fs::copy(fixture().join("src/app.spx"), scratch.join("src/app.spx")).unwrap();
    std::fs::copy(
        fixture().join("src/tests.spx"),
        scratch.join("src/tests.spx"),
    )
    .unwrap();

    // A single trivial probe function is enough: `SPX-G171`'s pre-charge
    // (see the doc comment above) sums whole reachable dependency modules
    // before this project's own source is resolved at all, so the probe's
    // own size plays no role in the refusal this test pins.
    let core = std::fs::read_to_string(fixture().join("src/core.spx")).unwrap();
    let augmented_core = core.replacen(
        "module task_service.core;\n",
        "module task_service.core;\nuse function @id(\"std.tracing.traceparent_shape_admitted\") from std.tracing as traceparent_shape_admitted;\n",
        1,
    ) + "\n@id(\"task_service.core.trace_header_probe\")\nfn trace_header_probe(header: borrow Slice<u8>) -> bool\n{\n    traceparent_shape_admitted(header)\n}\n";
    assert_ne!(
        augmented_core, core,
        "the module header must still be present to patch"
    );
    std::fs::write(scratch.join("src/core.spx"), augmented_core).unwrap();

    let outcome = project::with_authenticated_project(&scratch.join("semaprax.toml"), |snapshot| {
        snapshot.check()
    });
    let Err(diagnostics) = outcome else {
        panic!(
            "adding std.tracing to this project's dependency closure unexpectedly fit under \
             SPX-G171; if the builder_bytes accounting was narrowed or the baseline closure's \
             own charge dropped, replace this test with the real std.log/std.tracing wiring \
             issue #194 asks for"
        );
    };
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "SPX-G171"),
        "expected SPX-G171 (builder_bytes cap), got {diagnostics:?}"
    );
    let _ = std::fs::remove_dir_all(scratch);
}
