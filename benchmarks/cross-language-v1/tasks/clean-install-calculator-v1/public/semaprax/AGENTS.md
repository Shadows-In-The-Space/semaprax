# Agent guide for clean-install-calculator

This is a SEMAPRAX project. `semaprax.toml` lists its modules; the compiler
is the authority on what the language admits. Read `semaprax help language`
before writing source.

## Commands

- `semaprax check .` parses, resolves, type-checks, and verifies every module.
- `semaprax test .` runs `clean_install_calculator.tests`; `semaprax run .` runs the entry and prints its `i64`.
- `semaprax fmt <file>` rewrites one file in canonical form.
- `semaprax build . --target web -o dist/web` emits a browser package.
- `semaprax help <command>` prints one command's exact grammar.

## Rules that differ from other languages

- Every file starts with `module dotted.name;`, and every declaration carries
  `@id("...")`. The id is the stable identity: rename freely, never change an id.
- A function body is statements followed by exactly one tail expression. There
  is no `return`, `for`, `else if`, tuple, or unit value.
- `if` always has `else`; a `while` body ends with the bool that decides
  whether to loop again.
- Contracts are `requires` and `ensures` lines; effects are `permit` at module
  level plus `uses` on every function that performs or calls into one.
- Check the whole project, not one file: modules import each other, so a
  single file reports `SPX-G172` or `SPX-T105`.
- A new module must be listed in `sources` in `semaprax.toml`, and a test
  module in `tests`.
- Tests live in the `tests` module: `fn main() -> i64` returns 0 on success, and
  every `fn test_<name>() -> i64` with an `@id` runs as a named case that
  `semaprax test .` reports on failure.
- Diagnostics carry stable `SPX-` codes and, where the compiler knows the fix,
  a `help:` line. `semaprax check . --json` prints one diagnostic per line.

## Project v1 function boundaries

Function parameters and results are Copy scalars. Records, classes, variants,
`Option`, and `Result` may stay inside scalar-signature functions but cannot
cross their boundaries; `SPX-G174` points at a declaration that must change.

## Installed Agent Skill workflow

The installed compiler also publishes `semaprax.agent-skill.v1` (`semaprax
agent skill`), a small, authority-labeled public workflow over the commands
above. The list below is generated from that installed bundle, so it always
matches this compiler; each entry names its authority class and the exact
CLI command it wraps:

- `apply` (source_write): `semaprax apply-semantic-workspace-change-evidence <root> <proposal.json> <evidence.json>`
- `context` (read_only): `semaprax context <file|project> <symbol|stable-id> [--direction forward|reverse|both] [--depth N] [--max-bytes N] [--max-nodes N] [--filters ...]`
- `impact` (read_only): `semaprax impact <file> <patch.spatch> [--depth N] [--max-bytes N] [--max-nodes N]`
- `inspect` (read_only): `semaprax graph <file>`
- `propose` (candidate_only): `semaprax change preview <project> <operation> ... [--evidence|--structural-diff]`
- `publish` (publication): `semaprax project-candidate-git-publish <manifest> <capsule.json> <approved-candidate-digest> <host-policy.json>`
- `rebase` (candidate_only): `semaprax change rebase <base-project> <operation> ... --onto <onto-project> [--revision digest] [--onto-revision digest]`
- `repair` (source_write): `semaprax repair <file> <repair-id> --persistent-id <persistent-id>`
- `review` (read_only): `semaprax review <file> <patch.spatch>`
- `test` (test_execute): `semaprax test [<dir>|semaprax.toml|--manifest-path path] [--json] [--max-steps N] [--max-bytes N]`
