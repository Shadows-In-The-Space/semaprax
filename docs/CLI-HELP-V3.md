# Capability-Aware CLI Recovery v3

Status: implemented bounded profile; **HOSTED GREEN** under the
[v0.4.0 release baseline](RELEASE-0.4.0-STATUS.md). Historical local,
authoring-time, ignored, device/simulator, or separately provisioned evidence
below retains its narrower scope; public promotion, registry publication and
broader product completion remain separately gated.

Audience: CLI users, release engineers, and compiler contributors.

When a known command rejects an invocation, v3 points the user directly to its
scoped usage. The v1 catalog and help bytes and v2 typo behavior stay unchanged.

## Recovery hint

When a capability-visible known command returns invocation status 2, the CLI
appends this exact stderr line after the command's diagnostic:

```text
hint: run `semaprax check --help` for usage
```

The hint repeats the entered command name or alias exactly. It is not shown
for success, status-1 compiler or execution failures, empty invocations,
unknown or capability-hidden commands, `help`, or invocations with misplaced
`--help` or `-h`. These exclusions preserve existing exact output and prevent
private commands from being revealed.

Only the executable's static capability-visible catalog and final exit status
determine the hint. It inspects no source, filesystem, environment, target,
plugin, process, or network state and grants no command authority.

## Preservation and evidence

Global and scoped help stdout, command diagnostics, statuses, and side effects
remain unchanged; v3 adds only the recovery line to admitted status-2 cases.
The machine-readable diagnostic formats of commands that support JSON are
unchanged.

Executable evidence covers public standalone and private full-toolchain
commands, exact stderr and status, empty working directories, and preservation
of unknown-command, hidden-command, malformed-help-position, and successful
help output.
