# Task equivalence: `booking-window-conflict-v1`

This held-out repair task measures a small but realistic scheduling rule: two
nonempty half-open booking windows conflict exactly when they share at least
one instant. It is deliberately distinct from the suite's scalar digest,
bounded-state repair, record validation, and imported-invoice families.

## Problem and oracle

`conflicts(a_start, a_end, b_start, b_end)` receives two valid, nonempty
integer time windows, `[a_start, a_end)` and `[b_start, b_end)`, and returns
`1` when they overlap and `0` otherwise. The required predicate is:

```
a_start < b_end && b_start < a_end
```

The end boundary is exclusive. Thus a booking ending at time `20` and one
starting at time `20` do not conflict. A common repair changes both strict
comparisons to `<=`, treating an adjacent handoff as an overlap. That repair
passes the public cases because none use an equal boundary, but fails hidden
adjacency cases in both directions.

All inputs are literal signed integers and remain far inside the common exact
range of Rust `i64`, SEMAPRAX `i32`, and JavaScript `number`. The fixture
does not test malformed or empty windows; each input has `start < end`.

## Ports and overlays

Rust, TypeScript, and SEMAPRAX Project ports each put the candidate predicate
in its own module. Public and hidden phases use the same candidate source;
the hidden overlay replaces only the assertion entry point. Therefore the
runner's hidden phase tests a solver-authored candidate rather than a second
reference implementation.

| Language | Invocation | Success signal |
| --- | --- | --- |
| Rust | `rustc --edition 2021 --test main.rs -o test_bin`, then `./test_bin` | exit code `0` |
| TypeScript | `tsc --strict --target ES2020 --module commonjs index.ts`, then `node index.js` | exit code `0` |
| SEMAPRAX Project | `semaprax run .` | stdout `0` |

## Vectors

Public vectors cover a proper overlap, containment, and a gap strictly wider
than zero. Hidden vectors cover forward and reverse adjacency, which catch a
plausible inclusive-end candidate while preserving the half-open contract.

This fixture is held out. Its vectors and repair transcript must not be used
to tune a language adapter or admitted feature set.
