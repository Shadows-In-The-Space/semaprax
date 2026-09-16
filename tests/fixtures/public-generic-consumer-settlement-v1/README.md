# Native consumer settlement v1

`cases.json` is canonical ASCII JSON with sorted keys, compact separators and a
single LF. It is rendered by `scripts/public_generic_consumer_cases.py`; the
runtime gate rejects stale or modified manifest bytes. Recipes are deterministic
flat owned byte leaves, not nested generic compiler fixtures. Expected input
and successful-result digests bind exact little-endian length-framed payloads.

The production-template route and actual Rust-generator-checked route are
explicitly different evidence labels. The owning specification is
[Settlement Corpus v1](../../../docs/PUBLIC-GENERIC-SETTLEMENT-CORPUS-V1.md#native-calling-consumer-continuation-issue-162).

From the root: `python3 scripts/public_generic_consumer_settlement.py --sanitizers --output target/pg-consumers`.
Replay recompiles trusted sources. No payload, submitted executable or public
support authority is embedded in the evidence artifact.
