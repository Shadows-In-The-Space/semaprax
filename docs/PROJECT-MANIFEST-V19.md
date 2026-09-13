# Project Manifest v19: Filesystem I/O v3

Status: **implemented with local conformance.** Project v19 admits the private
`filesystem-io.v3` profile and its checked atomic-write route.

Audience: compiler, project-tooling, and standard-library contributors.

Project v19 selects the private `filesystem-io.v3` profile. It adds checked
atomic publication while preserving the frozen Project v18 and filesystem I/O
v2 authority and wire contracts. The operation and provider semantics are owned
by [Host Operation Outcome v1](HOST-OPERATION-OUTCOME-V1.md).

## Manifest

The standard-library package uses this canonical v19 projection:

```toml
schema = "semaprax.manifest.v1"

[package]
name = "std-fs"
version = "0.1.0"
profile = "filesystem-io.v3"

[modules]
entry = "std.fs.examples"
sources = ["src/examples.spx", "src/fs.spx", "src/tests.spx"]
tests = ["std.fs.tests"]

[exports]
web = []

[command]
function = "std.fs.examples.roundtrip"

[capabilities]
required = ["fs.read", "fs.write"]

[dependencies]
std.io = "^0.1.0"
std.path.value = "^0.1.0"
```

The profile requires a private `fn() -> bool` command, explicit filesystem
capabilities, and no public Web exports. `filesystem-io.v3` is additive: the
legacy `filesystem-io.v2` profile and its `file_write_atomic` behavior remain
unchanged. The v3 project schema is Project v19 and its semantic graph
projection is V46.

## Checked operation boundary

`file_write_atomic_checked` is admitted under `FilesystemV3` and returns a
checked publication value. Native callbacks and status are separate outputs;
invalid or unwritten outcome values fail with status `5`, while valid `0`, `1`,
and `2` values are returned. The standard-library
`std.fs.write_atomic_checked` wrapper maps those values to the fieldless
`WriteOutcome` variants.

Wasm appends the import
`env.spx_filesystem_write_atomic_checked_v3` with seven `i32` parameters, an
`i32` status result, and an out `u64` value. The v3 status export is
`__spx_filesystem_status_v3`; the v2 status export remains unchanged.

The physical provider reports `1` for pre-commit failure, `2` only for rename
`EIO` where publication is uncertain, and `0` for known rename success,
including cleanup failure after that success. These outcomes make no
filesystem durability claim. The authoritative rename contract is the
[POSIX `rename()` specification](https://pubs.opengroup.org/onlinepubs/9799919799/functions/rename.html).

## Non-claims and acceptance

This document does not claim hosted-green or public filesystem-provider support.
The local `project` harness `filesystem_v3` gate executes the interpreter,
native, and Wasm routes, the three valid outcomes, invalid and unwritten
callback values, and nested path refusal. Provider and legacy filesystem
regressions retain their separate owning gates. Network operations, durable
job composition, and public Web exports remain outside this profile.
