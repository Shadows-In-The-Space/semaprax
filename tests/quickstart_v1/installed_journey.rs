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
    assert!(stdout(&check).starts_with("verified project clean-install-service (sha256:"));

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
