# Installed toolchain journey test

Status: living contributor test-runner reference.

Audience: contributors verifying the clean-install journey described in
[Install](INSTALL.md) and [Quickstart](QUICKSTART.md).

## Why this exists

Other cases in `tests/quickstart_v1.rs` run the checkout's dev-built
`CARGO_BIN_EXE_semaprax` and use its `CARGO_MANIFEST_DIR`. They verify CLI
grammar against source, not whether the documented install command
(`cargo install --locked --path .`) produces a binary that works away from
this checkout, with no repository, prior package cache, or ambient home
directory to fall back on.

`installed_journey::clean_installed_toolchain_walks_the_documented_journey`,
a module of that same harness (`tests/quickstart_v1/installed_journey.rs`),
closes that gap: it runs the exact documented install command into a scratch
prefix, then drives the resulting binary from a working directory and `HOME`
outside this checkout through discover (`--help`, `help new`), create
(`semaprax new … --template service`), `check`, `test`, `run`, and `build`.
It exercises both the browser package and the local `--target oci` route: the
latter must contain exactly one replayed Wasm layer and retain explicit
nonclaims for a runnable container, base layer, operating-system rootfs,
signature, and publication. It is an offline OCI artifact assertion, not a
registry, signing, or deployment claim.

## Run it

```sh
scripts/run-installed-journey-test.sh
```

This runs `cargo test --locked -p semaprax --test quickstart_v1 -- --ignored
installed_journey::`. The case is `#[ignore]`d because `cargo install`
compiles the whole standalone binary from scratch; it is not part of
`scripts/quality.sh full` or any other default profile. Pass extra `cargo
test` binary arguments through the script, e.g. `scripts/run-installed-journey-test.sh --nocapture`.

## What it does and does not prove

The install step runs with `--offline` and a private `CARGO_TARGET_DIR` under
this checkout's own `target/private/`, so it reuses this machine's already
populated Cargo registry cache instead of requiring network access during the
test, and never touches the shared `target/debug`/`target/release` directory
other concurrent builds in this checkout use. `--offline` is a test-harness
concession, not a documented install step: [Install](INSTALL.md) correctly
states that `cargo install` fetches dependencies over the network on a truly
clean machine.

Once installed, the case asserts the resolved binary path lies under the
scratch install root and differs from `CARGO_BIN_EXE_semaprax`, so a
regression that quietly substitutes the dev binary for the installed one
(the failure mode this case exists to catch) fails immediately rather than
passing by accident.
