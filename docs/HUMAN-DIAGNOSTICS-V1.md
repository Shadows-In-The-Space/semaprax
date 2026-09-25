# Human Diagnostic Locations v1

Status: implemented bounded diagnostic presentation; **HOSTED GREEN** under the
[v0.4.0 release baseline](RELEASE-0.4.0-STATUS.md).
General diagnostic/repair and public-support requirements remain separate.

Audience: compiler users, editor authors, and compiler contributors.

This contract displays a diagnostic's existing source path in terminal output.
It changes neither diagnostic selection nor severity, code, message, help,
source span, exit status, or machine-readable JSON fields.

## Human rendering

A diagnostic with both a path and span renders its location after the message:

```text
error[SPX-P104]: expected `module` at src/main.spx:1:1
```

The location spelling is `path:line:column`. A path without a span renders as
`at path`. A span without a path retains the prior `at line:column` spelling,
and a diagnostic with neither retains its prior output. Help remains on the
following indented line.

The renderer escapes path control characters deterministically with Rust-style
escapes. A filename therefore cannot inject terminal control sequences or extra
diagnostic lines. Ordinary ASCII and Unicode path characters stay readable.

## Preservation and authority

Use the unchanged `Diagnostic::json()` interface for automation. Its `path`,
`location`, and `help` fields keep their existing values and null behavior.
Human-readable locations only describe a path. Rendering one does not read or
navigate to it, grant filesystem authority, or authenticate current source bytes.

Executable evidence covers path plus span, path only, span only, absent
locations, help placement, control-character escaping, unchanged JSON, and an
actual `semaprax check` failure.
