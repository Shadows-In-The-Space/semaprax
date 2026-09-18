#!/usr/bin/env sh
# Runs the clean-install toolchain journey test documented in
# docs/INSTALLED-JOURNEY-TEST.md. This is the named command that reaches the
# #[ignore]d `installed_journey::clean_installed_toolchain_walks_the_documented_journey`
# case in tests/quickstart_v1.rs; do not leave that case reachable only by a
# hand-typed selector.
#
# The case runs `cargo install --locked --path .` into a throwaway prefix
# (compiling the whole standalone binary), so it is slow and not part of any
# default profile. It uses a private CARGO_TARGET_DIR under this checkout's
# own `target/private/`, never the shared `target/debug` or `target/release`,
# so it is safe to run alongside other concurrent builds in this checkout.
set -eu

exec cargo test --locked -p semaprax --test quickstart_v1 -- \
    --ignored installed_journey:: --test-threads=1 --nocapture "$@"
