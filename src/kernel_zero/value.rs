//! Kernel-0 values and the runtime faults its reduction can reach.
//!
//! [`docs/SEMANTIC-KERNEL-V1.md`](../../../docs/SEMANTIC-KERNEL-V1.md)'s
//! "Operational semantics" section states only total reduction rules --
//! `n1 op n2 = n ("ordinary arithmetic")` with no side condition -- and its
//! "Paper safety proof" reads Progress as "every compound form ... let[s]
//! the form's own base rule fire". Real `i64` arithmetic is not total:
//! `Div`/`Rem` are undefined at a zero divisor, `Div`/`Rem`/`Neg` are
//! undefined at `i64::MIN` paired with `-1` (`Neg` alone at `i64::MIN`), and
//! `Add`/`Sub`/`Mul` are undefined outside `i64`'s range. The document's own
//! grammar admits exactly these operators on exactly `i64`, so this gap is
//! reachable by an admitted Kernel-0 program, not merely a theoretical
//! concern -- see this module's doc on [`Fault`] and the top-level report
//! this task produces for the consequence for the document's Progress
//! theorem as literally written.
//!
//! [`Fault`] is this reference interpreter's from-scratch resolution of that
//! gap: reaching one of these operand combinations gets stuck at no
//! reduction rule the document states, so [`super::eval`] treats it as a
//! distinct third outcome (alongside "reduces to a value" and, in principle,
//! "diverges", which Kernel-0's acyclic call graph rules out) rather than
//! silently wrapping or panicking. This choice is independent of the real
//! compiler: it was derived by reading which `i64` operations are partial,
//! not by inspecting `src/interpreter.rs`'s `combine`/`StatusCase` handling
//! (read only afterward, to compare -- see the differential test).

/// A Kernel-0 value (`v ::= n | true | false` in the grammar).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Value {
    Int(i64),
    Bool(bool),
}

/// A stuck point reachable from an admitted Kernel-0 term: an operand
/// combination the document's `n1 op n2 = n` rule does not cover because
/// ordinary `i64` arithmetic is partial there. See the module doc.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fault {
    AddOverflow,
    SubOverflow,
    MulOverflow,
    DivisionByZero,
    DivisionOverflow,
    RemainderByZero,
    RemainderOverflow,
    NegationOverflow,
}
