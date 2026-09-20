#!/usr/bin/env bash
# Run the offline doctor's ignored physical lifecycle tests on native Linux
# AArch64, directly, without the x86-64-only production release/capsule
# pipeline.
#
# THIS IS NOT scripts/doctor-provisioned-linux-gate.py AND IS NOT THE
# REQUIRED GATE ISSUE #61 OR docs/DOCTOR-PROVISIONED-LINUX-GATE-V1.md
# DESCRIBE. That gate admits exactly one target, x86-64
# (`ADMITTED_MACHINE = "x86_64"` in doctor-provisioned-linux-gate.py, and its
# own --self-test asserts that "aarch64" is one of the architectures it must
# reject). This script exists precisely because that gate must never be
# widened to accept AArch64: issue #61's own acceptance criteria require
# AArch64 support to stay separately tracked and never generalized from one
# Linux environment. Nothing this script produces changes WP-05's status in
# docs/COMPLETION-MATRIX.md, changes docs/DOCTOR-PROVISIONED-LINUX-GATE-V1.md,
# or may be cited as x86-64 evidence.
#
# What it DOES cover: a fixed, explicit twenty-four-test subset of the two
# `#[ignore]`d Rust suites that does not require a signed release capsule or a
# packaged real-distribution bundle. Every test name is supplied with
# `--exact`; adding a matching ignored test cannot silently widen this probe.
# The selected fixtures are built and run as native AArch64 binaries, inside a
# real (non-emulated) AArch64 Linux kernel, with the fixed namespace
# acknowledgements the fixtures themselves assert on. It reuses the existing
# hostile fixtures unmodified; it adds no fixture and weakens none.
#
# What it does NOT cover: the two fixtures that need a provisioned real
# Clang/Node/Rust distribution bundle and selector
# (`real_launched_handoff::production_launcher_reports_all_roles_from_provisioned_real_distributions`
# and `provisioned_real_clang_node_rust_distributions`) -- those need
# SEMAPRAX_DOCTOR_REAL_SELECTOR, SEMAPRAX_DOCTOR_REAL_BUNDLE and matching
# SEMAPRAX_DOCTOR_EXPECTED_{CLANG,NODE,RUST}_DETAIL, none of which this
# script invents. Run without them, those two fixtures fail fast on a
# missing-precondition panic, not a confinement failure, and this script
# reports that explicitly rather than skipping them silently.
#
# Usage from a non-Linux development host (e.g. macOS with Docker Desktop,
# whose Linux VM is native AArch64 on Apple Silicon -- not emulated):
#
#   docker run --rm --privileged --cgroupns=private \
#     -v "$(pwd)":/repo -v <cargo-registry-cache>:/usr/local/cargo/registry \
#     rust:1-slim-bookworm bash /repo/scripts/doctor-provisioned-linux-aarch64-local-lifecycle.sh
#
# Usage directly on a disposable AArch64 Linux host: run this script as-is
# from the repository root.
#
# Refuses (does not skip) unless Linux on AArch64, cargo is on PATH, and
# unshare(1) can create a private user+mount namespace -- missing
# provisioning is a failure here too, exactly as issue #61 requires of the
# x86-64 gate.

set -o errexit
set -o nounset
set -o pipefail

fail() {
	printf 'error: %s\n' "$1" >&2
	printf 'This is a failure, not a skip.\n' >&2
	exit 1
}

require_host() {
	local system machine
	system="$(uname -s)"
	machine="$(uname -m)"
	[ "${system}" = "Linux" ] || fail "host system is '${system}', not 'Linux'"
	case "${machine}" in
	aarch64 | arm64) ;;
	*) fail "host architecture is '${machine}', not AArch64; use doctor-provisioned-linux-provision.sh for x86-64" ;;
	esac
}

require_user_namespaces() {
	command -v unshare >/dev/null 2>&1 || fail "unshare(1) is not installed"
	unshare --user --map-root-user --mount --net --ipc --uts true >/dev/null 2>&1 ||
		fail "cannot create a private user+mount namespace as this user"
}

require_cargo() {
	command -v cargo >/dev/null 2>&1 || fail "cargo is not on PATH"
}

readonly REPOSITORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly TARGET_DIR="${CARGO_TARGET_DIR:-${REPOSITORY}/target-aarch64-local}"

# This is deliberately an enumerated plan, rather than a broad libtest filter:
# the local 24/26 historical result is meaningful only for this exact set.
# Keep the two omitted real-distribution fixtures in their explicit --skip
# positions below, even though --exact makes the list closed independently.
readonly -a PLATFORM_LIFECYCLE_TESTS=(
	"doctor::offline_root::linux::tests::provisioned_close_uncertainty_is_fail_stop"
	"doctor::offline_root::linux::tests::provisioned_detached_root_bytes_modes_and_read_only"
	"doctor::offline_root::linux::tests::provisioned_metadata_mismatches_feed_actual_admission"
	"doctor::offline_root::linux::tests::provisioned_setup_and_exact_write_failures_return_no_root"
	"doctor::offline_root::linux::tests::provisioned_wrong_page_cost_stops_before_tree_writes"
	"doctor::offline_worker::tests::hostile::provisioned_capability_operations_and_process_creation_are_denied"
	"doctor::offline_worker::tests::hostile::provisioned_root_hides_real_outside_file_and_rejects_write_opens"
	"doctor::offline_worker::tests::hostile::provisioned_stdin_is_eof_and_nonstandard_descriptors_are_closed"
	"doctor::offline_worker::tests::lifecycle::post_exec_capabilities_and_supervisor_death_are_observed_externally"
	"doctor::offline_worker::tests::provisioned_materializer_exec_and_socket_denial"
	"doctor::offline_worker::tests::provisioned_missing_role_bad_hash_and_invalid_request_emit_no_frame"
	"doctor::offline_worker::tests::provisioned_overflow_and_timeout_publish_only_settled_failure"
)
readonly -a COLLECTOR_LIFECYCLE_TESTS=(
	"actual_worker_materializes_executes_and_settles_before_canonical_report"
	"complete_frame_and_capture_eof_each_still_require_worker_exit"
	"complete_literal_frame_followed_by_nonzero_exit_never_becomes_a_report"
	"created_handoff::production_created_native_and_all_files_reach_worker_and_reject_digest_drift"
	"launched_handoff::production_launcher_rejects_both_image_defects_and_digest_drift"
	"launched_handoff::production_launcher_rejects_structural_collector_with_missing_loader"
	"launched_handoff::production_launcher_reports_native_and_all_from_literal_transport_files"
	"literal_reply_surrogates_reject_cross_binding_and_malformed_frames"
	"nonchild::nonchild_pidfd_rejects_without_killing_or_stopping_the_owned_sentinel"
	"physical_reports::all_three_roles_settle_and_tool_failure_is_an_ordinary_exit_one_report"
	"physical_reports::closed_report_sink_fails_after_collection_without_successful_delivery"
	"prepared_handoff::prepared_native_and_all_role_handoffs_preserve_literal_wire_and_reject_transport_drift"
)
readonly TRACKING_FIXTURE_COUNT=24

require_tracking_plan() {
	[ "${#PLATFORM_LIFECYCLE_TESTS[@]}" -eq 12 ] || fail "platform lifecycle plan is not 12 fixtures"
	[ "${#COLLECTOR_LIFECYCLE_TESTS[@]}" -eq 12 ] || fail "collector lifecycle plan is not 12 fixtures"
	[ "$(( ${#PLATFORM_LIFECYCLE_TESTS[@]} + ${#COLLECTOR_LIFECYCLE_TESTS[@]} ))" -eq "${TRACKING_FIXTURE_COUNT}" ] || \
		fail "AArch64 tracking plan is not ${TRACKING_FIXTURE_COUNT} fixtures"
}

main() {
	require_host
	require_user_namespaces
	require_cargo
	require_tracking_plan
	cd "${REPOSITORY}"
	export CARGO_TARGET_DIR="${TARGET_DIR}"

	echo "== building current-head worker, launcher and collector for $(uname -m) =="
	cargo build --locked -p semaprax-native-rust-interop-platform-sys \
		--bin semaprax-doctor-worker --bin semaprax-doctor-launcher
	cargo build --locked -p semaprax-doctor-collector --bin semaprax-doctor-collector

	export SEMAPRAX_DOCTOR_WORKER_TEST_CONTEXT="private-mapped-user-mount-clean-worker-cgroup-v1"
	export SEMAPRAX_DOCTOR_ROOT_TEST_CONTEXT="private-user-mount-v1"
	export SEMAPRAX_DOCTOR_WORKER="${TARGET_DIR}/debug/semaprax-doctor-worker"
	export SEMAPRAX_DOCTOR_LAUNCHER="${TARGET_DIR}/debug/semaprax-doctor-launcher"
	export SEMAPRAX_DOCTOR_COLLECTOR="${TARGET_DIR}/debug/semaprax-doctor-collector"

	echo "== running the platform-sys-lib ignored lifecycle suite =="
	echo "   (excludes the real-distribution fixture, run separately below)"
	unshare --user --map-root-user --mount --net --ipc --uts -- \
		cargo test --locked --offline -p semaprax-native-rust-interop-platform-sys --lib -- \
		--ignored --exact --test-threads=1 \
		--skip doctor::offline_worker::tests::provisioned_real_clang_node_rust_distributions \
		"${PLATFORM_LIFECYCLE_TESTS[@]}"
	echo "== running the doctor-collector 'provisioned' ignored lifecycle suite =="
	echo "   (excludes the two real-distribution fixtures; see the file header)"
	unshare --user --map-root-user --mount --net --ipc --uts -- \
		cargo test --locked --offline -p semaprax-doctor-collector --test provisioned -- \
		--ignored --exact --test-threads=1 \
		--skip real_launched_handoff::production_launcher_reports_all_roles_from_provisioned_real_distributions \
		"${COLLECTOR_LIFECYCLE_TESTS[@]}"

	echo "== running the platform-sys real-distribution fixture explicitly =="
	echo "   (expected to fail fast on the missing SEMAPRAX_DOCTOR_REAL_SELECTOR"
	echo "    precondition unless the caller has provisioned a real bundle)"
	unshare --user --map-root-user --mount --net --ipc --uts -- \
		cargo test --locked --offline -p semaprax-native-rust-interop-platform-sys --lib -- \
		--ignored --exact --test-threads=1 doctor::offline_worker::tests::provisioned_real_clang_node_rust_distributions ||
		echo "   (nonzero exit expected without a provisioned real bundle -- not a confinement failure)"

	echo "== done: this is AArch64-local exploratory evidence only =="
	echo "   It is not the x86-64 gate, does not change WP-05, and must never"
	echo "   be cited as x86-64 confinement evidence."
}

main "$@"
