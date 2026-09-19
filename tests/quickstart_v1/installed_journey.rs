//! The one gap SPX-AI-045 left open: every other case in this harness drives
//! `super::standalone_binary()`, the dev-built `CARGO_BIN_EXE_semaprax` from
//! this checkout's own `cargo test`, and reads paths through
//! `CARGO_MANIFEST_DIR` (this checkout). That proves the CLI grammar, not that
//! an installed toolchain works away from this checkout.
//!
//! This module installs the standalone `semaprax` binary into a throwaway
//! prefix with the exact command `docs/QUICKSTART.md` and `docs/INSTALL.md`
//! document (`cargo install --locked --path .`), then drives the resulting
//! binary from a working directory and `HOME` with no relationship to this
//! checkout, walking discover -> create -> check -> test -> run -> build.
//!
//! `cargo install` compiles the whole binary, so the case is `#[ignore]`d.
//! Run it with `scripts/run-installed-journey-test.sh` (also documented in
//! `docs/INSTALLED-JOURNEY-TEST.md`); do not add an `#[ignore]` here without
//! keeping that runner and its documentation in sync.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

/// A private target directory under *this* checkout's own `target/`, never
/// the shared `target/debug` / `target/release` that concurrent `cargo
/// build`/`cargo test` invocations elsewhere use. See
/// docs/DEVELOPMENT.md#verification and AGENTS.md's "Prohibited shortcuts":
/// a `target-dir` shared with another build lets that build's fingerprints
/// silently replace this one's, and this is exactly the kind of install-time
/// build this repository must not let corrupt another agent's output.
fn private_target_dir() -> PathBuf {
    checkout().join("target/private/quickstart-installed-journey")
}

fn checkout() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn cargo_command() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
}

/// The exact command `docs/QUICKSTART.md`/`docs/INSTALL.md` document, split
/// into argv, so this case tracks the documented install command instead of
/// carrying its own possibly-drifted copy.
fn documented_install_argv() -> Vec<String> {
    let mut words = super::QUICKSTART_INSTALL_COMMANDS
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(
        words.remove(0),
        "cargo",
        "the documented install command must start with `cargo`"
    );
    words
}

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("semaprax-installed-journey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Self {
            root: root.canonicalize().unwrap(),
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

/// Runs the installed binary with a fully scrubbed environment: only `HOME`
/// (the scratch home) and a minimal `PATH` survive, so nothing can resolve
/// through an inherited variable back into this checkout or the developer's
/// real home.
fn run_installed(binary: &Path, home: &Path, directory: &Path, arguments: &[&str]) -> Output {
    Command::new(binary)
        .args(arguments)
        .current_dir(directory)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap_or_else(|error| panic!("run installed semaprax {arguments:?}: {error}"))
}

#[test]
#[ignore = "compiles the whole standalone binary with `cargo install`; run via scripts/run-installed-journey-test.sh"]
fn clean_installed_toolchain_walks_the_documented_journey() {
    let checkout = checkout();
    let scratch = Scratch::new();
    let install_root = scratch.root.join("cargo-install-root");
    let target_dir = private_target_dir();
    let _ = std::fs::remove_dir_all(&target_dir);

    // --- Install into the scratch prefix with the exact documented command,
    // run from the checkout root (installing is inherently checkout-rooted;
    // only *driving* the result must be checkout-independent). ---
    let mut install = cargo_command();
    install
        .args(documented_install_argv())
        .arg("--offline")
        .arg("--root")
        .arg(&install_root)
        .arg("--target-dir")
        .arg(&target_dir)
        .current_dir(&checkout);
    let install_output = install
        .output()
        .unwrap_or_else(|error| panic!("run `cargo install`: {error}"));
    // Reclaim the private target directory immediately; nothing downstream
    // needs the intermediate build artifacts, only the installed binary.
    let _ = std::fs::remove_dir_all(&target_dir);
    assert!(
        install_output.status.success(),
        "cargo install --locked --path . failed:\nstdout:\n{}\nstderr:\n{}",
        stdout(&install_output),
        stderr(&install_output),
    );

    let binary_name = if cfg!(windows) {
        "semaprax.exe"
    } else {
        "semaprax"
    };
    let binary = install_root.join("bin").join(binary_name);
    assert!(
        binary.is_file(),
        "cargo install reported success but did not produce {}",
        binary.display()
    );

    // --- Guard: the binary genuinely came from the scratch install, not the
    // dev build this same test crate links against as CARGO_BIN_EXE_semaprax.
    // A regression that quietly substitutes the dev binary here (the exact
    // failure mode this case exists to catch) fails both assertions below:
    // the dev binary lives under this checkout's own `target/`, never under
    // `install_root`, and its canonical path differs from the freshly
    // installed one. ---
    let canonical_installed = binary.canonicalize().unwrap();
    let dev_binary = Path::new(env!("CARGO_BIN_EXE_semaprax"));
    let canonical_dev = dev_binary.canonicalize().unwrap();
    assert_ne!(
        canonical_installed, canonical_dev,
        "the installed binary must not resolve to the dev-built CARGO_BIN_EXE_semaprax"
    );
    assert!(
        canonical_installed.starts_with(install_root.canonicalize().unwrap()),
        "the installed binary must live under the scratch install root, found {}",
        canonical_installed.display()
    );
    assert!(
        !canonical_installed.starts_with(&checkout),
        "the installed binary must not live inside the checkout, found {}",
        canonical_installed.display()
    );

    // --- Drive it from a working directory and HOME with no relationship to
    // this checkout. ---
    let home = scratch.root.join("home");
    let work = scratch.root.join("work");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&work).unwrap();
    assert!(!home.starts_with(&checkout));
    assert!(!work.starts_with(&checkout));

    let mut transcript = Vec::new();
    let mut run = |directory: &Path, arguments: &[&str]| -> Output {
        let output = run_installed(&binary, &home, directory, arguments);
        transcript.push((
            arguments
                .iter()
                .map(|word| word.to_string())
                .collect::<Vec<_>>(),
            stdout(&output),
            stderr(&output),
        ));
        output
    };

    // Discover.
    let help = run(&work, &["--help"]);
    assert!(help.status.success());
    assert!(stdout(&help).starts_with("SEMAPRAX — Meaning in. Verified machine code out.\n"));
    let new_help = run(&work, &["help", "new"]);
    assert!(new_help.status.success(), "{}", stderr(&new_help));
    assert!(stdout(&new_help).starts_with("Usage:\n"));

    // Create, via the newly admitted service template.
    let created = run(
        &work,
        &["new", "clean-install-service", "--template", "service"],
    );
    assert!(created.status.success(), "{}", stderr(&created));
    assert_eq!(
        stdout(&created),
        "created service project clean-install-service\n"
    );
    let project = work.join("clean-install-service");
    assert!(project.join("semaprax.toml").is_file());

    // Check.
    let check = run(&project, &["check", "."]);
    assert!(check.status.success(), "{}", stderr(&check));
    let check_stdout = stdout(&check);
    assert!(check_stdout.starts_with("verified project clean-install-service (sha256:"));
    // `check` prints the project revision digest in parentheses. Assert its
    // exact shape rather than only the prefix: this is the value a caller
    // feeds back as a base revision, so a malformed or absent digest here is
    // a real defect even though nothing in this test consumes it today (the
    // step that did is removed below, see issue #272).
    let revision = check_stdout
        .trim_end()
        .strip_prefix("verified project clean-install-service (")
        .and_then(|rest| rest.strip_suffix(')'))
        .expect("check output must carry the project revision digest in parentheses");
    assert!(
        revision.starts_with("sha256:") && revision.len() == 71,
        "the printed project revision is not a sha256 digest: {revision}"
    );

    // Test.
    let tested = run(&project, &["test", "."]);
    assert!(tested.status.success(), "{}", stderr(&tested));
    assert_eq!(stdout(&tested), "project tests passed\n");

    // Run.
    let ran = run(&project, &["run", "."]);
    assert!(ran.status.success(), "{}", stderr(&ran));
    assert_eq!(stdout(&ran), "0\n");

    // Build. `web` needs no external C toolchain, unlike `native`/
    // `native-callable`, so the scrubbed PATH above cannot hide a missing
    // `clang` behind a false pass.
    let built = run(
        &project,
        &["build", ".", "--target", "web", "-o", "dist/web"],
    );
    assert!(built.status.success(), "{}", stderr(&built));
    assert!(project.join("dist/web/app.wasm").is_file());
    // The `service` template's two `[exports].web` entries take byte-slice
    // arguments, so the emitted manifest is `data-exports`, not
    // `scalar-exports`. Assert the loader and bindings too: a web package
    // that ships only `app.wasm` is not usable by the documented flow.
    for artifact in [
        "semaprax.data-exports.json",
        "semaprax.js",
        "semaprax.bindings.js",
        "package.json",
    ] {
        assert!(
            project.join("dist/web").join(artifact).is_file(),
            "the installed toolchain's web package must contain {artifact}"
        );
    }

    // Inspect evidence. `project-assurance-manifest` is a public command of
    // the same installed binary, over the same manifest `check` just
    // verified; assert it reports real, source-derived facts (this project's
    // own three `.spx` sources and at least one per-declaration obligation),
    // not an empty or stubbed envelope.
    //
    // ISSUE #271, pinned here rather than worked around silently: at the
    // DEFAULT budget this command REFUSES on a project the toolchain itself
    // just generated. `DEFAULT_MAX_BYTES` is 262,144 and the `service`
    // template's manifest is 317,698 bytes. That refusal is asserted first,
    // so a fix for #271 flips this test loudly instead of leaving a stale
    // workaround behind; when the default is raised, delete this block and
    // the `--max-bytes` argument below together.
    let refused = run(&project, &["project-assurance-manifest", "semaprax.toml"]);
    assert!(
        !refused.status.success(),
        "issue #271 appears fixed: the default budget now admits the service \
         template. Drop this negative assertion and the explicit --max-bytes below."
    );
    assert!(
        stderr(&refused).contains("SPX-Z102"),
        "expected the budget refusal of issue #271, got: {}",
        stderr(&refused)
    );
    let assurance = run(
        &project,
        &[
            "project-assurance-manifest",
            "semaprax.toml",
            "--max-bytes",
            "1048576",
        ],
    );
    assert!(assurance.status.success(), "{}", stderr(&assurance));
    let assurance_stdout = stdout(&assurance);
    let assurance_json: Value =
        serde_json::from_str(assurance_stdout.trim_end()).unwrap_or_else(|error| {
            panic!("project-assurance-manifest did not print JSON: {error}\n{assurance_stdout}")
        });
    assert_eq!(
        assurance_json["schema"], "semaprax.project-assurance-manifest.v1",
        "{assurance_json}"
    );
    let sources = assurance_json["payload"]["sources"]
        .as_array()
        .unwrap_or_else(|| {
            panic!("assurance manifest must list the project's sources: {assurance_json}")
        })
        .iter()
        .map(|source| source["path"].as_str().unwrap())
        .collect::<Vec<_>>();
    // The manifest covers the whole checked closure, not just the project's
    // own files: the three bundled dependency sources the `service` template
    // composes are in it too, and `std.bytes` is there transitively. That is
    // the right scope for an assurance manifest -- obligations arise from
    // every checked declaration, including the ones a dependency contributes
    // -- so this asserts the exact six rather than the three a reader might
    // expect. A dependency silently dropping out of the closure is precisely
    // what this would catch.
    assert_eq!(
        sources,
        vec![
            "dependencies/std.auth/0.1.0/auth.spx",
            "dependencies/std.bytes/0.1.0/bytes.spx",
            "dependencies/std.jobs/0.1.0/jobs.spx",
            "src/app.spx",
            "src/core.spx",
            "src/tests.spx",
        ]
    );
    let obligations = assurance_json["payload"]["obligations"]
        .as_array()
        .unwrap_or_else(|| panic!("assurance manifest must carry obligations: {assurance_json}"));
    assert!(
        !obligations.is_empty(),
        "the installed toolchain's assurance manifest must carry real per-declaration \
         obligations, not an empty stub: {assurance_json}"
    );

    // A semantic-repair preview step belonged here and is deliberately absent.
    // `project-candidate-preview` refuses this project with
    // `error[SPX-G174]: Semantic Workspace path-set values are not canonical`,
    // as does `semantic-cache-persist`; the `calculator` template gets past the
    // same point and the `service` template does not. Which of the six
    // path-set conditions actually fires cannot be determined, because
    // `normalize_parser_diagnostics` flattens all but one of them into that
    // single message. Filed as issue #272. Re-add the step once the diagnostic
    // says which condition failed and the route's admissibility for a
    // bundled-dependency project is decided.

    // No command's output ever names this checkout: nothing fell back to a
    // compiled-in or ambient path rooted here.
    let checkout_text = checkout.to_string_lossy().into_owned();
    for (arguments, out, err) in &transcript {
        assert!(
            !out.contains(&checkout_text) && !err.contains(&checkout_text),
            "installed run of {arguments:?} named this checkout in its output:\nstdout:\n{out}\nstderr:\n{err}"
        );
    }
}
