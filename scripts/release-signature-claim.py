#!/usr/bin/env python3
"""Build (or byte-check) `semaprax.release-signature-claim.v1` (#168).

This is the narrow, authority-free bridge from a completed `cosign sign-blob`
v0.3 *message-signature* bundle to the structural claim consumed by
`src/release_provenance.rs`.  It receives the exact provenance and bundle
bytes as explicit paths, derives the SHA-256 subject digest from the former,
and copies the latter's certificate and signature encodings verbatim.  It
does not sign, verify a signature, contact a transparency log, download a
trust root, read CI environment variables, or publish anything.

The independent Rust decoder owns complete v0.3 bundle framing and all
manifest/provenance/claim binding.  This builder deliberately admits only the
small message-signature projection needed to construct the claim, then makes
the already-produced bundle the sole source for its copied cryptographic
material.  A later caller with explicit offline verification authority must
still verify the exact bundle against an explicitly supplied trusted root.

Modes:

  --provenance PATH --bundle PATH [--output PATH]
      Build the deterministic claim and print it (or write it to PATH).

  --provenance PATH --bundle PATH --check PATH
      Rebuild the deterministic claim and require PATH to be byte-exact.
"""

import argparse
import base64
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

SCHEMA = "semaprax.release-signature-claim.v1"
PROVENANCE_SCHEMA = "semaprax.release-provenance.v1"
ALGORITHM = "sigstore-cosign-bundle-v0.3"
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
TRUSTED_ISSUER = "https://token.actions.githubusercontent.com"
TRUSTED_REPOSITORY = "wavect/semaprax"
TRUSTED_WORKFLOW_PATH = ".github/workflows/ci.yml"
MAX_PROVENANCE_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_CLAIM_BYTES = 64 * 1024

VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def reject(message):
    raise ValueError(message)


def sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_bounded(path, limit, what):
    """Read at most `limit` bytes without trusting a pre-read file size.

    A signing workflow normally supplies small regular files, but the offline
    replay tool must not turn a malformed path into an unbounded allocation.
    The one-byte probe catches growth while the file was read without relying
    on a potentially stale metadata length.
    """
    with path.open("rb") as source:
        data = source.read(limit + 1)
        if len(data) > limit or source.read(1):
            reject(f"{what} exceeds the {limit}-byte bound")
    if not data:
        reject(f"{what} must not be empty")
    return data


def require_object(value, what):
    if not isinstance(value, dict):
        reject(f"{what} must be a JSON object")
    return value


def require_exact_keys(value, expected, what):
    require_object(value, what)
    if set(value) != set(expected):
        reject(f"{what} keys must be exactly {sorted(expected)!r}, found {sorted(value)!r}")


def require_text(value, what):
    if not isinstance(value, str) or not value:
        reject(f"{what} must be a non-empty string")
    return value


def parse_json(bytes_value, what):
    def closed_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                reject(f"{what} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(bytes_value, object_pairs_hook=closed_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"{what} is not UTF-8 JSON: {error}")


def canonical_base64(value, what, expected_bytes=None):
    value = require_text(value, what)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        reject(f"{what} must be padded standard base64: {error}")
    if base64.b64encode(decoded).decode("ascii") != value:
        reject(f"{what} must be canonical padded standard base64")
    if expected_bytes is not None and len(decoded) != expected_bytes:
        reject(f"{what} must decode to exactly {expected_bytes} bytes")
    return value


def provenance_identity(provenance_bytes):
    provenance = parse_json(provenance_bytes, "provenance")
    require_exact_keys(
        provenance,
        {
            "schema", "version", "tag", "commit", "prerelease", "required_checks",
            "artifacts", "manifest_digest", "source", "builder", "toolchain",
            "build_host_class", "nonclaims",
        },
        "provenance",
    )
    if provenance["schema"] != PROVENANCE_SCHEMA:
        reject(f"provenance schema must be {PROVENANCE_SCHEMA!r}")
    version = require_text(provenance["version"], "provenance.version")
    tag = require_text(provenance["tag"], "provenance.tag")
    if not VERSION_RE.fullmatch(version) or tag != f"v{version}":
        reject("provenance version/tag must be canonical and agree")
    commit = require_text(provenance["commit"], "provenance.commit")
    if not COMMIT_RE.fullmatch(commit):
        reject("provenance.commit must be 40 lowercase hexadecimal characters")
    source = provenance["source"]
    require_exact_keys(source, {"repository", "commit", "tag"}, "provenance.source")
    if (
        source["repository"] != TRUSTED_REPOSITORY
        or source["commit"] != commit
        or source["tag"] != tag
    ):
        reject("provenance source must name the pinned repository and exact top-level commit/tag")
    builder = provenance["builder"]
    require_exact_keys(builder, {"workflow_identity", "run_id", "run_attempt"}, "provenance.builder")
    expected_workflow_ref = f"{TRUSTED_REPOSITORY}/{TRUSTED_WORKFLOW_PATH}@refs/tags/{tag}"
    if builder["workflow_identity"] != expected_workflow_ref:
        reject("provenance builder.workflow_identity does not match the pinned workflow for its tag")
    return tag, expected_workflow_ref


def bundle_material(bundle_bytes, provenance_bytes):
    bundle = parse_json(bundle_bytes, "Sigstore message-signature bundle")
    require_exact_keys(
        bundle,
        {"mediaType", "messageSignature", "verificationMaterial"},
        "Sigstore message-signature bundle",
    )
    if bundle["mediaType"] != SIGSTORE_BUNDLE_MEDIA_TYPE:
        reject(f"Sigstore bundle mediaType must be {SIGSTORE_BUNDLE_MEDIA_TYPE!r}")
    signature = bundle["messageSignature"]
    require_exact_keys(signature, {"messageDigest", "signature"}, "messageSignature")
    signature_bytes = canonical_base64(signature["signature"], "messageSignature.signature")
    digest = signature["messageDigest"]
    require_exact_keys(digest, {"algorithm", "digest"}, "messageSignature.messageDigest")
    if digest["algorithm"] != "SHA2_256":
        reject("messageSignature.messageDigest.algorithm must be SHA2_256")
    raw_digest = canonical_base64(
        digest["digest"], "messageSignature.messageDigest.digest", expected_bytes=32
    )
    expected_digest = hashlib.sha256(provenance_bytes).digest()
    if base64.b64decode(raw_digest) != expected_digest:
        reject("messageSignature message digest does not match the exact provenance bytes")
    material = bundle["verificationMaterial"]
    require_exact_keys(
        material,
        {"certificate", "timestampVerificationData", "tlogEntries"},
        "verificationMaterial",
    )
    certificate = material.get("certificate")
    require_exact_keys(certificate, {"rawBytes"}, "verificationMaterial.certificate")
    certificate_bytes = canonical_base64(
        certificate["rawBytes"], "verificationMaterial.certificate.rawBytes"
    )
    timestamps = require_object(
        material["timestampVerificationData"],
        "verificationMaterial.timestampVerificationData",
    )
    if timestamps:
        require_exact_keys(
            timestamps,
            {"rfc3161Timestamps"},
            "verificationMaterial.timestampVerificationData",
        )
        records = timestamps["rfc3161Timestamps"]
        if not isinstance(records, list) or not (1 <= len(records) <= 8):
            reject("verificationMaterial timestamp records must contain 1 through 8 entries")
        for record in records:
            require_exact_keys(record, {"signedTimestamp"}, "RFC3161 timestamp")
            canonical_base64(record["signedTimestamp"], "RFC3161 signed timestamp")
    entries = material["tlogEntries"]
    if not isinstance(entries, list) or not (1 <= len(entries) <= 8):
        reject("verificationMaterial.tlogEntries must contain 1 through 8 entries")
    for entry in entries:
        require_exact_keys(
            entry,
            {
                "canonicalizedBody", "integratedTime", "inclusionPromise",
                "inclusionProof", "kindVersion", "logId", "logIndex",
            },
            "verificationMaterial.tlogEntries[]",
        )
        kind = require_object(entry["kindVersion"], "tlog kindVersion")
        require_exact_keys(kind, {"kind", "version"}, "tlog kindVersion")
        if kind != {"kind": "hashedrekord", "version": "0.0.1"}:
            reject("message-signature tlog entry must be hashedrekord v0.0.1")
    return signature_bytes, certificate_bytes


def build_claim(provenance_bytes, bundle_bytes):
    tag, workflow_ref = provenance_identity(provenance_bytes)
    signature, certificate = bundle_material(bundle_bytes, provenance_bytes)
    return {
        "schema": SCHEMA,
        "subject_digest": sha256_digest(provenance_bytes),
        "subject_name": "release-provenance.json",
        "identity": {
            "issuer": TRUSTED_ISSUER,
            "subject": f"repo:{TRUSTED_REPOSITORY}:ref:refs/tags/{tag}",
            "workflow_ref": workflow_ref,
        },
        "algorithm": ALGORITHM,
        "signature": signature,
        "certificate": certificate,
    }


def render_claim(claim):
    return (json.dumps(claim, indent=2) + "\n").encode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args(argv)
    if args.output is not None and args.check is not None:
        reject("--output and --check are mutually exclusive")

    rendered = render_claim(
        build_claim(
            read_bounded(args.provenance, MAX_PROVENANCE_BYTES, "provenance"),
            read_bounded(args.bundle, MAX_BUNDLE_BYTES, "Sigstore message-signature bundle"),
        )
    )
    if args.check is not None:
        existing = read_bounded(args.check, MAX_CLAIM_BYTES, "existing signature claim")
        if existing != rendered:
            reject(f"{args.check} does not byte-match the deterministic signature claim")
        print(f"release signature claim: {args.check} byte-matches recomputed evidence")
    elif args.output is not None:
        args.output.parent.mkdir(parents=False, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=args.output.parent, prefix=".release-signature-claim-", delete=False
            ) as target:
                temporary = Path(target.name)
                target.write(rendered)
                target.flush()
            temporary.replace(args.output)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
        print(f"release signature claim: wrote {args.output}")
    else:
        sys.stdout.buffer.write(rendered)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"release signature claim rejected: {error}", file=sys.stderr)
        sys.exit(2)
