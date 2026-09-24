# First contribution

Status: living contributor guide. Audience: first-time contributors and agents.

This page shows the order of work, not new project rules. Read
[`AGENTS.md`](https://github.com/wavect/semaprax/blob/main/AGENTS.md) for invariants,
[Development](DEVELOPMENT.md) for required references,
[Quality gates](QUALITY-GATES.md) for verification, and the
[Completion matrix](COMPLETION-MATRIX.md) for feature status.

## 1. Choose a small change

A broken link, missing documentation metadata, or one example is a good first
task. A change to evaluation order, ownership, cleanup, capabilities, or an
evidence boundary is not: those need coordinated compiler and backend work.

The `changed` quality profile recognizes only certain paths, such as
documentation, CLI, and editor files. Other paths widen to `full`. See
`src/quality_route.rs` and preview the route in step 6 before running it.

## 2. Find the owner of the change

Start with the repository context graph. It points to the code and documents
that own a question:

```sh
graft map
graft ask '<topic or exact symbol>' --source
```

Then use [Development](DEVELOPMENT.md#read-before-changing-semantics) for the
required reading order and [Quality gates](QUALITY-GATES.md) for the test that
proves your change. For an exhaustive search, use `graft grep`; ranked `ask`
results are not exhaustive. An exact diagnostic code is a useful query:

```sh
graft ask 'SPX-U105' --source
```

Check both the owning specification and the emitter before changing wording.

## 3. Find the completion-matrix rows

```sh
rg -n -i '<topic>' docs/COMPLETION-MATRIX.md
```

Read the [status rules](COMPLETION-MATRIX.md#status-rules) before making a
claim. Local, hosted, private, public, and proof-only evidence are different.
Change a matrix row only when its status or required gate actually changes.

## 4. Ask the compiler about `.spx` meaning

For one declaration, use the bounded `context` command. Use `graph` only when
you need the whole module:

```sh
cargo run --locked -p semaprax -- context examples/meaning.spx math.add --depth 1
cargo run --locked -p semaprax -- graph examples/meaning.spx
```

`math.add` is a declaration's stable `@id`. Both commands print JSON.
`context` reports if it truncated the answer; raise its depth or byte budget
instead of guessing. Use `rg` for bounded Rust searches. Read
[ADR 0001](decisions/0001-graphify.md) before adding a repository-wide index.

## 5. Put the test in the harness that owns its subject

Add a case to the harness that owns it. Each new top-level test file links the
whole compiler again; [Architecture](ARCHITECTURE.md#integration-test-harnesses)
lists the exceptions.

```sh
ls tests/*.rs                 # the harness roots; pick the one owning the subject
ls tests/language/            # that harness's modules
rg -n '^mod |^#\[path' tests/language.rs
```

Put the case in `tests/<group>/<name>.rs` and declare it from the harness root
with `#[path]`:

```rust
#[path = "<group>/<name>.rs"]
mod <name>;
```

Run the narrow selector. Keep the `module::` prefix; otherwise libtest may
interpret the name as another filter:

```sh
cargo test --locked -p semaprax --test <group> <name>::<case>
```

Use a unique fixture prefix within the harness. Declare shared
`tests/support/*.rs` modules once in its root.

## 6. Run a profile

Preview the route without running tests:

```sh
scripts/quality.sh changed --plan
```

The plan names the profile, why it was chosen, and each gate in order. A
documentation-only change normally routes to `changed`; an unmapped source
file widens it to `full`.

| Profile | What it runs |
| --- | --- |
| `quick` | Diff, formatting, workspace check, and advisory tests. |
| `changed` | `quick` plus package Clippy, agent-context tests, and package rustdoc; CLI or editor tests only when those paths changed. |
| `full` | Workspace-wide checks, tests, docs, release build, package check, and example loops. This can use more than 10 GB of build space. |

The plan uses `semaprax.quality-route.v2`. Its route labels explain why a
profile was selected:

| Labels | Meaning |
| --- | --- |
| `documentation-truth`, `agent-context-economics` | Documentation or bounded agent-context work. |
| `cli-surface`, `editor-adapter` | CLI or editor-facing changes. |
| `broad-compiler-or-graph-dispatch`, `unmapped-or-wide` | Changes that need the full profile. |
| `complete-git-state-has-narrow-mappings` | All changed paths have narrow mappings. |
| `git-state-includes-wide-or-unmapped-path` | At least one path widens the profile. |
| `changed-worktree-is-empty` | No changed paths were found, so routing widens. |

The executor reports gate names in order. The narrow routes include
`diff-check`, `fmt-check`, `check-workspace`, `test-advisory`,
`clippy-package`, `test-agent-context`, `rustdoc-package`, `test-cli`, and
`test-editor` as applicable. The full route also uses `clippy-workspace`,
`test-workspace`, `doctest-workspace`, `rustdoc-workspace`, `build-release`,
`package`, `example-checks`, and `example-fmt`.

The exact gate commands live in `scripts/quality.sh`; do not duplicate them.
Use [Quality gates](QUALITY-GATES.md) for the required profile and focused
evidence. Prose edits do not prove technical claims.

Two `changed` routing surprises:

- It needs a base commit. Fetch `origin/main`, then set
  `SEMAPRAX_QUALITY_BASE=$(git merge-base origin/main HEAD)` if your
  environment has no configured base.
- A clean worktree widens to `full`. Preview after you have edits.

If the base is missing, the router says "changed quality routing requires
SEMAPRAX_QUALITY_BASE, SEMAPRAX_QUALITY_TARGET_REF, or configured origin/HEAD".
If a target ref is not a remote-tracking ref, it says "must be an exact
refs/remotes/ reference". Fix the Git input, then preview again.

For documentation-only changes, see the
[documentation gate](QUALITY-GATES.md#documentation-changes). The owning
specification may require more focused checks.

## 7. Local hazards you will otherwise hit

- **A library test aborts on an unmodified tree.**
  `cargo test --locked -p semaprax --lib` overflows the stack in
  `wasm::internal_strings::tests::nesting::nested_if_compile_on_default_stack`
  on a default-stack debug build. It is not your change; skip it with
  `-- --skip nested_if_compile_on_default_stack`. See
  [`CLAUDE.md`](https://github.com/wavect/semaprax/blob/main/CLAUDE.md).
- **Disk, not time, is the binding limit on `full`.** A
  `--workspace --all-targets` test build links several hundred integration
  binaries and needs well over 10 GB. Build with `CARGO_INCREMENTAL=0` and
  `CARGO_PROFILE_TEST_DEBUG=0` when disk is short.
- **Never `git stash` in this repository.** The stash is one stack shared by
  every worktree, and dozens are usually registered, so a push or pop reaches
  another agent's uncommitted work. Commit to a scratch branch, or use a
  worktree.
- **Clippy runs with `-D warnings`.** One unused import fails the build. Run
  `cargo fmt --all` before any gate; `fmt-check` is the second gate in every
  profile, so a formatting slip wastes the whole run.
- **1500 lines per Rust file.** `tests/module_size.rs` fails above that unless
  `tests/module-size-budget.tsv` records the file, and a recorded file may not
  grow past its recorded size. Prefer a new submodule. Regenerate the ledger
  only after a legitimate split, with
  `cargo test --locked -p semaprax --test module_size -- --ignored regenerate`.
  Before splitting, `rg` the module's path across `tests/` and `crates/*/src`
  for `include_str!` and path reads: a hit is a [source-locked
  contract](ARCHITECTURE.md#source-locked-contracts) whose join must follow the
  code, or it keeps passing while covering less. Move bodies verbatim — dedenting
  a relocated body silently rewrites the interior of multi-line string literals,
  where leading whitespace is content.
- **Windows checkouts need long paths before cloning**, not after; see
  [Windows checkouts](DEVELOPMENT.md#windows-checkouts).

## 8. What to update at the end

Update exactly the owner of each fact you changed, and nothing else:

| Update | Only when |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Implementation ownership or a trust boundary moved |
| [Completion matrix](COMPLETION-MATRIX.md) | A row's status or its stated gate changed |
| [Roadmap](ROADMAP.md) | Sequencing changed — never to assert something is done |
| [Changelog](https://github.com/wavect/semaprax/blob/main/CHANGELOG.md) | Always: this is where history goes |
| The owning versioned specification | Its exact syntax, schema, ABI, diagnostics or admission changed |

New or renamed `docs/*.md` files also need a `docs/SUMMARY.md` entry, an H1 as
the first line, and `Status:` and `Audience:` within the first 12 lines.
`tests/documentation.rs` enforces links, metadata and catalog coverage.

Do not describe local, private, proof-only, simulator or prior-head evidence as
public, hosted, physical-device, current-head or production support.

## 9. Before you open the pull request

Walk the [change protocol](https://github.com/wavect/semaprax/blob/main/AGENTS.md#change-protocol) items in order; it is
the checklist, and this page only sequenced the tooling around it. Then confirm
the two things that belong to this page: the routed profile passed together
with the focused evidence the owning specification names, and nothing outside
the owners in step 8 was edited.
