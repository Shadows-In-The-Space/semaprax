#!/usr/bin/env python3
"""Prepare and dry-run-check a maintained preview of one generated package.

GitHub issue #145 asks for a maintained, reproducible consumer route for one
deliberately chosen existing generated-package preview -- the Project v8
`owned-data-api.v1` profile's generated npm package and Native Rust owned-data
SDK (see docs/PUBLIC-OWNED-DATA-API-V1.md) -- without publishing anything and
without promoting the separate public-generic-ABI decision. This script is
the release-preparation and dry-run layer *around* the compiler's own
generated package output; it never edits, regenerates, or reinterprets that
output's bytes, and it never contacts a registry.

Two subcommands:

  prepare --kind {npm,rust} --package-dir DIR --project-name NAME \\
      --project-version VERSION [--commit SHA] --output DIR
      Validates DIR's inventory is exactly the closed set of files the chosen
      profile produces (see NPM_OWNED_DATA_FILES / RUST_OWNED_DATA_*), scans
      every byte for secret-shaped and local-host-path-shaped substrings,
      checks the Rust crate cannot be published by `cargo publish` (`publish
      = false`, no path/private dependency) and the npm package carries none
      of the supply-chain-risk keys the compiler itself already forbids
      (dependencies/devDependencies/scripts/private), then copies the exact
      input bytes into `<output>/payload/` and adds deterministic wrapping
      documents (README.md, LICENSE, a checksum manifest) alongside it. This
      never invokes npm or cargo and never calls the network.

  check --kind {npm,rust} --prepared-dir DIR [--publish] \\
      [--npm-bin PATH] [--cargo-bin PATH]
      Recomputes and diffs `<DIR>/package-preview-manifest.json` against the
      files actually on disk (tamper detection), then, only in the default
      dry-run mode, optionally exercises a real `npm pack --dry-run` or
      `cargo publish --dry-run` if an explicit absolute tool path is supplied
      (never discovered from PATH). `--publish` is always refused: this tool
      implements no live-publish code path, by design -- registry writes and
      signing require separate maintainer approval (issue #145 step 6,
      #168's signing policy) that this repository does not grant here.

Both subcommands refuse outright, before touching any file, if a live
publish-credential-shaped environment variable is set: this tooling has no
legitimate use for one and must never run anywhere near a real credential.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PREVIEW_SCHEMA = "semaprax.generated-package-preview.v1"

NPM_OWNED_DATA_FILES = (
    "app.wasm",
    "semaprax.js",
    "semaprax.bindings.js",
    "semaprax.bindings.d.ts",
    "semaprax.api.json",
    "package.json",
)
NPM_DESCRIPTOR_FILE = "semaprax.api.json"
NPM_FORBIDDEN_PACKAGE_JSON_KEYS = ("dependencies", "devDependencies", "scripts", "private")

RUST_OWNED_DATA_FIXED_FILES = (
    "Cargo.toml",
    "build.rs",
    "lib.rs",
    "owned_data_ffi.rs",
    "descriptor.json",
)
RUST_OWNED_DATA_ARCHIVE_NAMES = (
    "libsemaprax_native_rust_owned_data_sdk.a",
    "semaprax_native_rust_owned_data_sdk.lib",
)
RUST_OWNED_DATA_MANIFEST_NAMES = ("semaprax.native-rust-owned-data-sdk.json",)
RUST_DESCRIPTOR_FILE = "descriptor.json"

# This tool must never run near a live publish credential: it has no
# legitimate use for one, so its presence alone is refused before any file is
# touched, in either subcommand.
FORBIDDEN_CREDENTIAL_ENV_VARS = (
    "NPM_TOKEN",
    "NPM_AUTH_TOKEN",
    "NODE_AUTH_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "CARGO_REGISTRY_DEFAULT_TOKEN",
    "CARGO_REGISTRIES_CRATES_IO_TOKEN",
)

SECRET_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        rb"ghp_[A-Za-z0-9]{20,}",
        rb"gho_[A-Za-z0-9]{20,}",
        rb"github_pat_[A-Za-z0-9_]{20,}",
        rb"xox[baprs]-[A-Za-z0-9-]{10,}",
        rb"AKIA[0-9A-Z]{16}",
        rb"npm_[A-Za-z0-9]{20,}",
        rb"sk-[A-Za-z0-9]{20,}",
    )
)


class Rejected(ValueError):
    """A preparation or check input failed a closed admission rule."""


def reject(message):
    raise Rejected(message)


def assert_no_credential_env(environ):
    present = [name for name in FORBIDDEN_CREDENTIAL_ENV_VARS if environ.get(name)]
    if present:
        reject(
            "refusing to run near a live publish credential: unset "
            + ", ".join(sorted(present))
            + " and rerun; real publication is issue #145 step 6, gated on "
            "separate maintainer approval, and is not implemented by this tool"
        )


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def sha256_digest(data):
    return "sha256:" + sha256_hex(data)


def scan_bytes(name, data, forbidden_substrings):
    for pattern in SECRET_PATTERNS:
        match = pattern.search(data)
        if match:
            reject(f"{name} contains a secret-shaped substring: {match.group(0)[:12]!r}...")
    for substring in forbidden_substrings:
        if substring and substring.encode("utf-8", "surrogateescape") in data:
            reject(f"{name} contains a local host path: {substring!r}")


def local_path_substrings(package_dir):
    """Absolute paths that must never leak into a preview package's bytes."""
    substrings = {
        str(package_dir.resolve()),
        str(package_dir.absolute()),
        str(ROOT.resolve()),
        str(ROOT.absolute()),
    }
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    if home:
        substrings.add(home)
    return sorted(s for s in substrings if s and s not in ("/", "\\"))


def list_plain_files(directory):
    """Every direct child's name, rejecting subdirectories and symlinks.

    A generated-package preview is a flat file inventory; a subdirectory or a
    symlink is either an unexpected shape this profile never produces or a
    local artifact (a build cache, a stray checkout) that must not enter the
    prepared package.
    """
    names = []
    for entry in sorted(os.scandir(directory), key=lambda item: item.name):
        info = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            reject(f"{entry.name} is a symlink; a preview package inventory must be plain files")
        if not stat.S_ISREG(info.st_mode):
            reject(f"{entry.name} is not a plain file; a preview package inventory admits none")
        names.append(entry.name)
    return names


def expected_rust_inventory(names):
    archives = [name for name in names if name in RUST_OWNED_DATA_ARCHIVE_NAMES]
    manifests = [name for name in names if name in RUST_OWNED_DATA_MANIFEST_NAMES]
    if len(archives) != 1:
        reject(f"expected exactly one native archive, found {archives!r}")
    if len(manifests) != 1:
        reject(f"expected exactly one SDK manifest, found {manifests!r}")
    expected = set(RUST_OWNED_DATA_FIXED_FILES) | set(archives) | set(manifests)
    if set(names) != expected:
        reject(
            "Rust owned-data package inventory is not exactly the closed set: "
            f"got {sorted(names)!r}, expected {sorted(expected)!r}"
        )
    return archives[0], manifests[0]


def validate_rust_cargo_toml(text):
    """The generated crate must remain structurally unpublishable by Cargo.

    `cargo publish` refuses a crate whose manifest sets `publish = false`;
    this is the existing generated-crate shape (see
    crates/semaprax-native-rust-owned-data-package/src/render.rs), and this
    check keeps that guarantee true of whatever bytes this tool wraps, rather
    than trusting the caller's claim that the input came from that renderer.
    It also refuses any `[dependencies]` table: today's generated crate has
    none, and a path/registry dependency slipping in here is exactly the
    "private workspace crate becomes a public transitive dependency by
    accident" failure mode issue #145 names.
    """
    if not re.search(r'(?m)^publish\s*=\s*false\s*$', text):
        reject("generated Cargo.toml must set publish = false")
    if re.search(r'(?m)^\[dependencies(\.|\]|$)', text):
        reject("generated Cargo.toml must not declare a [dependencies] table")
    if re.search(r'path\s*=\s*"\.\.', text):
        reject("generated Cargo.toml must not declare a parent-relative path dependency")


def validate_npm_package_json(text):
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        reject(f"package.json is not valid JSON: {error}")
    for key in NPM_FORBIDDEN_PACKAGE_JSON_KEYS:
        if key in parsed:
            reject(f"package.json must not declare {key!r}")
    if "name" not in parsed or "version" not in parsed:
        reject("package.json must declare name and version")
    return parsed


def node_engine_requirement(package_json):
    engines = package_json.get("engines")
    if isinstance(engines, dict) and isinstance(engines.get("node"), str):
        return engines["node"]
    return "unspecified"


def rust_version_requirement(cargo_toml_text):
    match = re.search(r'(?m)^rust-version\s*=\s*"([^"]+)"\s*$', cargo_toml_text)
    return match.group(1) if match else "unspecified"


def render_readme(kind, project_name, project_version, commit, descriptor_sha256, toolchain):
    commit_line = commit if commit else "unrecorded (supply --commit for a release build)"
    return (
        f"# {project_name} ({kind}) -- generated-package preview\n"
        "\n"
        "**Status: PREVIEW / UNPUBLISHED.** This package is compiler output for one\n"
        "exact SEMAPRAX Project, prepared by `scripts/generated-package-release.py`\n"
        "as a maintained, reproducible consumer route candidate under GitHub issue\n"
        "#145. It has not been published to any registry, and no registry write or\n"
        "signature has ever been produced for it. See\n"
        "docs/PUBLIC-OWNED-DATA-API-V1.md for the owning profile contract and\n"
        "docs/GENERATED-PACKAGE-PUBLICATION-DECISION-DRAFT-V1.md for the pending,\n"
        "unapproved maintainer publication decision.\n"
        "\n"
        f"- Project: `{project_name}` version `{project_version}`\n"
        f"- Kind: `{kind}`\n"
        f"- Source commit: `{commit_line}`\n"
        f"- Public API descriptor digest: `sha256:{descriptor_sha256}`\n"
        f"- Declared supported toolchain: `{toolchain}`\n"
        "\n"
        "## Compatibility\n"
        "\n"
        "This package is tied to the exact public API descriptor digest above. A\n"
        "later build of the same Project with a changed export set, signature, or\n"
        "profile changes that digest; consumers must treat a digest change as a\n"
        "potentially breaking change regardless of the declared package version,\n"
        "until this profile's rename/compatibility guarantees are formally\n"
        "promoted. See docs/PUBLIC-OWNED-DATA-API-V1.md for the exact admitted\n"
        "surface.\n"
        "\n"
        "## Rollback / deprecation\n"
        "\n"
        "Nothing under this status has ever been published, so there is no live\n"
        "artifact to roll back. Deprecating a future published version means\n"
        "ceasing to prepare or publish new releases of it; it does not retroactively\n"
        "change an already-published artifact's bytes.\n"
        "\n"
        "## Nonclaims\n"
        "\n"
        "This package is unsigned. Its checksum manifest\n"
        "(`package-preview-manifest.json`) records integrity digests, not\n"
        "signatures, provenance, or publisher authentication.\n"
    )


def payload_manifest(payload_dir):
    entries = []
    for name in sorted(os.listdir(payload_dir)):
        path = payload_dir / name
        data = path.read_bytes()
        entries.append({"path": f"payload/{name}", "sha256": sha256_hex(data), "size": len(data)})
    return entries


def prepare(kind, package_dir, project_name, project_version, commit, output_dir):
    assert_no_credential_env(os.environ)
    package_dir = Path(package_dir)
    output_dir = Path(output_dir)
    if not package_dir.is_dir() or package_dir.is_symlink():
        reject(f"--package-dir must be one physical directory: {package_dir}")
    if output_dir.exists():
        reject(f"--output must not already exist: {output_dir}")
    if not project_name or not project_version:
        reject("--project-name and --project-version must not be empty")

    names = list_plain_files(package_dir)
    forbidden_substrings = local_path_substrings(package_dir)

    if kind == "npm":
        if set(names) != set(NPM_OWNED_DATA_FILES):
            reject(
                "npm owned-data package inventory is not exactly the closed set: "
                f"got {sorted(names)!r}, expected {sorted(NPM_OWNED_DATA_FILES)!r}"
            )
        descriptor_file = NPM_DESCRIPTOR_FILE
    elif kind == "rust":
        expected_rust_inventory(names)
        descriptor_file = RUST_DESCRIPTOR_FILE
    else:
        reject(f"unknown --kind: {kind!r}")

    contents = {}
    for name in names:
        data = (package_dir / name).read_bytes()
        scan_bytes(name, data, forbidden_substrings)
        contents[name] = data

    if kind == "rust":
        validate_rust_cargo_toml(contents["Cargo.toml"].decode("utf-8"))
        package_json = None
        cargo_text = contents["Cargo.toml"].decode("utf-8")
        toolchain = f"rust {rust_version_requirement(cargo_text)}"
    else:
        package_json = validate_npm_package_json(contents["package.json"].decode("utf-8"))
        toolchain = f"node {node_engine_requirement(package_json)}"

    descriptor_sha256 = sha256_hex(contents[descriptor_file])

    payload_dir = output_dir / "payload"
    output_dir.mkdir(parents=True)
    payload_dir.mkdir()
    for name in names:
        (payload_dir / name).write_bytes(contents[name])

    readme = render_readme(kind, project_name, project_version, commit, descriptor_sha256, toolchain)
    (output_dir / "README.md").write_text(readme, encoding="utf-8")
    scan_bytes("README.md", readme.encode("utf-8"), forbidden_substrings)
    license_bytes = (ROOT / "LICENSE").read_bytes()
    (output_dir / "LICENSE").write_bytes(license_bytes)

    manifest = {
        "schema": PREVIEW_SCHEMA,
        "kind": kind,
        "project_name": project_name,
        "project_version": project_version,
        "commit": commit,
        "descriptor_file": descriptor_file,
        "descriptor_sha256": descriptor_sha256,
        "status": "preview-unpublished",
        "registry_write_performed": False,
        "files": sorted(
            payload_manifest(payload_dir)
            + [
                {"path": "README.md", "sha256": sha256_hex(readme.encode("utf-8")), "size": len(readme.encode("utf-8"))},
                {"path": "LICENSE", "sha256": sha256_hex(license_bytes), "size": len(license_bytes)},
            ],
            key=lambda entry: entry["path"],
        ),
    }
    (output_dir / "package-preview-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def describe_prepared(prepared_dir):
    """Recompute every file's digest currently on disk under `prepared_dir`."""
    entries = []
    for relative in ("README.md", "LICENSE"):
        path = prepared_dir / relative
        if not path.is_file():
            reject(f"prepared directory is missing {relative}")
        data = path.read_bytes()
        entries.append({"path": relative, "sha256": sha256_hex(data), "size": len(data)})
    payload_dir = prepared_dir / "payload"
    if not payload_dir.is_dir():
        reject("prepared directory is missing payload/")
    entries.extend(payload_manifest(payload_dir))
    return sorted(entries, key=lambda entry: entry["path"])


def run_closed(command, cwd, path_dirs, extra_env=None, timeout=120):
    """Run one dry-run tool with a minimal, explicit environment.

    `PATH` is built only from the caller-supplied tool directories plus the
    fixed system directories those tools' own shebangs/helpers may need; it
    is never inherited from the ambient environment, and no *_TOKEN/registry
    credential is ever passed through (`assert_no_credential_env` already
    refused before this can run if one is set).
    """
    env = {"PATH": ":".join([*path_dirs, "/usr/bin", "/bin"]), "LC_ALL": "C"}
    if extra_env:
        env.update({key: value for key, value in extra_env.items() if value})
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def check(kind, prepared_dir, publish, npm_bin=None, cargo_bin=None):
    if publish:
        reject(
            "live publish is not implemented by this tool: it requires a "
            "separate maintainer-approved registry credential and, once "
            "issue #168 lands, a signing key. Neither is available here."
        )
    assert_no_credential_env(os.environ)
    prepared_dir = Path(prepared_dir)
    manifest_path = prepared_dir / "package-preview-manifest.json"
    if not manifest_path.is_file():
        reject(f"missing package-preview-manifest.json under {prepared_dir}")
    on_disk = json.loads(manifest_path.read_text(encoding="utf-8"))
    if on_disk.get("kind") != kind:
        reject(f"prepared directory kind {on_disk.get('kind')!r} does not match --kind {kind!r}")
    recomputed = describe_prepared(prepared_dir)
    if on_disk.get("files") != recomputed:
        reject(
            "prepared package has been tampered with since `prepare`: recorded "
            "and on-disk file digests disagree"
        )

    report = ["generated-package-release check: manifest and on-disk digests agree"]
    payload_dir = prepared_dir / "payload"
    if kind == "npm":
        if npm_bin is None:
            report.append("npm dry-run skipped: no --npm-bin supplied")
        else:
            # Deliberately not resolved: an nvm-style `npm` launcher is
            # itself a symlink whose target directory does not contain the
            # sibling `node` binary it needs on PATH, unlike the directory
            # the caller-supplied path itself lives in.
            npm_bin = Path(npm_bin)
            if not npm_bin.is_absolute():
                reject("--npm-bin must be an absolute path")
            npm_bin = str(npm_bin)
            result = run_closed(
                [npm_bin, "pack", "--dry-run", "--json"],
                cwd=payload_dir,
                path_dirs=[str(Path(npm_bin).parent)],
                extra_env={"npm_config_offline": "true", "HOME": os.environ.get("HOME", "")},
            )
            if result.returncode != 0:
                reject(f"npm pack --dry-run failed: {result.stderr.decode(errors='replace')}")
            report.append("npm pack --dry-run succeeded (no file was written, no network used)")
    else:
        if cargo_bin is None:
            report.append("cargo dry-run skipped: no --cargo-bin supplied")
        else:
            cargo_bin = Path(cargo_bin)
            if not cargo_bin.is_absolute():
                reject("--cargo-bin must be an absolute path")
            cargo_bin = str(cargo_bin)
            result = run_closed(
                [
                    cargo_bin,
                    "publish",
                    "--dry-run",
                    "--offline",
                    "--allow-dirty",
                    "--manifest-path",
                    str(payload_dir / "Cargo.toml"),
                ],
                cwd=payload_dir,
                path_dirs=[str(Path(cargo_bin).parent)],
                extra_env={"HOME": os.environ.get("HOME", ""), "CARGO_HOME": os.environ.get("CARGO_HOME", "")},
            )
            stderr = result.stderr.decode(errors="replace")
            if result.returncode == 0:
                reject(
                    "cargo publish --dry-run unexpectedly succeeded for a crate that "
                    "must declare publish = false"
                )
            if "publish" not in stderr.lower():
                reject(f"cargo publish --dry-run failed for an unexpected reason: {stderr}")
            report.append(
                "cargo publish --dry-run independently refused (publish = false), as expected"
            )
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--kind", choices=("npm", "rust"), required=True)
    prepare_parser.add_argument("--package-dir", type=Path, required=True)
    prepare_parser.add_argument("--project-name", required=True)
    prepare_parser.add_argument("--project-version", required=True)
    prepare_parser.add_argument("--commit", default=None)
    prepare_parser.add_argument("--output", type=Path, required=True)

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--kind", choices=("npm", "rust"), required=True)
    check_parser.add_argument("--prepared-dir", type=Path, required=True)
    check_parser.add_argument("--publish", action="store_true")
    check_parser.add_argument("--npm-bin", type=Path, default=None)
    check_parser.add_argument("--cargo-bin", type=Path, default=None)

    args = parser.parse_args(argv)

    if args.command == "prepare":
        manifest = prepare(
            args.kind,
            args.package_dir,
            args.project_name,
            args.project_version,
            args.commit,
            args.output,
        )
        print(f"generated-package-release: prepared {args.output} ({manifest['descriptor_sha256'][:12]}...)")
        return 0

    report = check(
        args.kind,
        args.prepared_dir,
        args.publish,
        npm_bin=args.npm_bin,
        cargo_bin=args.cargo_bin,
    )
    for line in report:
        print(f"generated-package-release: {line}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Rejected as error:
        print(f"generated-package-release rejected: {error}", file=sys.stderr)
        sys.exit(2)
