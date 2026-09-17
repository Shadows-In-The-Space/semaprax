# TypeScript host-owned settlement fixture v1

Owning specification: [Settlement Corpus v1](../../../docs/PUBLIC-GENERIC-SETTLEMENT-CORPUS-V1.md#typescript-host-owned-caller-continuation-issue-162).

`cases.json` is canonical sorted compact ASCII JSON with one final LF. Regenerate
it with `python3 scripts/public_generic_typescript_cases.py > tests/fixtures/public-generic-typescript-settlement-v1/cases.json`.
The full gate refuses a stale manifest. Existing C/C++ carrier recipes and
manifest digests are reused, not restated per engine.

The corpus has 108 cases. Separate closed test inventories cover 32 host groups
and 13 authenticated module fixtures. Expected traces are literal host-frame
observations, not the compiler's CarrierCallMachine trace. Only the reversal
endpoint executes in hand-assembled Wasm bytecode; allocation/handles remain
host-owned. No compiler-derived generic endpoint/provider ABI is claimed.

Run `python3 scripts/public_generic_typescript_settlement.py --native --output target/pg-typescript`.
Node 22 and TypeScript 5.8.3 are required. No toolchain absence is a passing skip.
Use `--replay target/pg-typescript/typescript-settlement.json` with identical
options and trusted sources for independent re-execution. The separate Cargo
bridge is required to claim actual Rust-generator byte equality and execution.
