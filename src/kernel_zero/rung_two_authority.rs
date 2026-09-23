//! Conservative production boundary for the five Kernel-0 renderer lanes.
//!
//! The formatter owns both its Rust reference bytes and this fixed output
//! token. A lane is evaluated first, after its own exact-source replay, but
//! may contribute bytes only when they exactly equal the Rust bytes. A
//! refusal, oversized token, or disagreement selects the same Rust borrow.

use crate::ast::{BinaryOp, UnaryOp};

use super::{
    canonical_bool_renderer, canonical_char_renderer, canonical_int_renderer,
    canonical_operator_renderer, canonical_string_renderer,
};

/// Four lanes fit in 12 bytes; decimal `i64::MIN` is exactly 20 bytes, so the
/// one closed caller-owned representation uses that justified exact maximum.
pub(crate) const MAX_TOKEN_BYTES: usize = 20;

thread_local! {
    /// A renderer's exact-source replay can itself canonicalize compiler data.
    /// That nested formatting must not re-enter a candidate lane and recurse.
    static CANDIDATE_ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct CandidateScope {
    previous: bool,
}

impl CandidateScope {
    fn enter() -> Self {
        let previous = CANDIDATE_ACTIVE.with(|active| active.replace(true));
        Self { previous }
    }

    fn active() -> bool {
        CANDIDATE_ACTIVE.with(std::cell::Cell::get)
    }
}

impl Drop for CandidateScope {
    fn drop(&mut self) {
        CANDIDATE_ACTIVE.with(|active| active.set(self.previous));
    }
}

pub(super) fn in_candidate_scope<T>(work: impl FnOnce() -> T) -> T {
    let _scope = CandidateScope::enter();
    work()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Lane {
    Char,
    Bool,
    Int,
    Operator,
    StringScalar,
}

impl Lane {
    #[cfg(test)]
    const fn index(self) -> usize {
        match self {
            Self::Char => 0,
            Self::Bool => 1,
            Self::Int => 2,
            Self::Operator => 3,
            Self::StringScalar => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateRefusal {
    Refused,
    Oversized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Token {
    bytes: [u8; MAX_TOKEN_BYTES],
    len: usize,
}

impl Token {
    fn from_bytes(bytes: &[u8]) -> Result<Self, CandidateRefusal> {
        if bytes.len() > MAX_TOKEN_BYTES {
            return Err(CandidateRefusal::Oversized);
        }
        let mut token = Self {
            bytes: [0; MAX_TOKEN_BYTES],
            len: bytes.len(),
        };
        token.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(token)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Candidate storage is copied into the caller-owned token only after exact
/// comparison. Recovery retains the original Rust pointer, not a clone.
#[derive(Debug)]
enum Selected<'a> {
    Candidate(Token),
    Rust(&'a [u8]),
}

impl Selected<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Candidate(token) => token.as_bytes(),
            Self::Rust(bytes) => bytes,
        }
    }

    fn copy_to(&self, output: &mut [u8; MAX_TOKEN_BYTES]) -> usize {
        let bytes = self.bytes();
        assert!(
            bytes.len() <= MAX_TOKEN_BYTES,
            "renderer token bound drifted"
        );
        output[..bytes.len()].copy_from_slice(bytes);
        bytes.len()
    }
}

fn select<'a>(lane: Lane, rust: &'a str, candidate: Result<String, ()>) -> Selected<'a> {
    // Candidate evaluation is deliberately first. The Rust bytes are only a
    // comparison/fallback borrow and no target process is invoked here.
    let selected = match candidate
        .map_err(|_| CandidateRefusal::Refused)
        .and_then(|text| Token::from_bytes(text.as_bytes()))
    {
        Ok(token) if token.as_bytes() == rust.as_bytes() => Selected::Candidate(token),
        Ok(_) | Err(_) => Selected::Rust(rust.as_bytes()),
    };
    record(lane);
    selected
}

fn copy_into(
    lane: Lane,
    rust: &str,
    candidate: impl FnOnce() -> Result<String, ()>,
    output: &mut [u8; MAX_TOKEN_BYTES],
) -> usize {
    // Replaying an embedded component parses/resolves compiler data, whose
    // diagnostics and reports may canonicalize source. Nested formatter work
    // is Rust-only to prevent recursive derivation. Bounded-output callers
    // are Rust-only too: evidence may not spend their output-work budget.
    if CandidateScope::active() || crate::bounded_output::active_limit().is_some() {
        return Selected::Rust(rust.as_bytes()).copy_to(output);
    }
    let candidate = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_candidate_scope(|| candidate().and_then(super::rung_two_owned_handoff::handoff))
    }))
    .unwrap_or(Err(()));
    let selected = select(lane, rust, candidate);
    selected.copy_to(output)
}

#[cfg(test)]
#[test]
fn owned_handoff_panic_restores_fallback_and_reentry() {
    let mut output = [0; MAX_TOKEN_BYTES];
    // Initialize before arming the after-staging hook.
    assert_eq!(
        copy_into(Lane::Int, "abc", || Ok("abc".into()), &mut output),
        3
    );
    let before = super::rung_two_owned_handoff::handoffs();
    crate::interpreter::retained_call::owned_handoff::panic_on_next_staging();
    assert_eq!(
        copy_into(Lane::Int, "rust", || Ok("candidate".into()), &mut output),
        4
    );
    assert_eq!(&output[..4], b"rust");
    assert!(!CandidateScope::active());
    assert_eq!(super::rung_two_owned_handoff::handoffs(), before);
    assert_eq!(
        copy_into(Lane::Int, "abc", || Ok("abc".into()), &mut output),
        3
    );
    assert_eq!(super::rung_two_owned_handoff::handoffs(), before + 1);
}

#[cfg(test)]
#[test]
fn owned_handoff_refusal_and_candidate_panic_keep_rust_bytes() {
    let mut output = [0; MAX_TOKEN_BYTES];
    let before = crate::interpreter::retained_call::owned_handoff::staged_count();
    assert_eq!(
        copy_into(Lane::Int, "rust", || Ok("x".repeat(21)), &mut output),
        4
    );
    assert_eq!(&output[..4], b"rust");
    assert_eq!(
        crate::interpreter::retained_call::owned_handoff::staged_count(),
        before
    );
    assert_eq!(
        copy_into(
            Lane::Int,
            "rust",
            || panic!("candidate failure"),
            &mut output
        ),
        4
    );
    assert_eq!(&output[..4], b"rust");
    assert!(!CandidateScope::active());
}

pub(crate) fn char_into(value: u32, rust: &str, output: &mut [u8; MAX_TOKEN_BYTES]) -> usize {
    copy_into(
        Lane::Char,
        rust,
        || canonical_char_renderer::render(value).map_err(|_| ()),
        output,
    )
}

pub(crate) fn bool_into(value: bool, rust: &str, output: &mut [u8; MAX_TOKEN_BYTES]) -> usize {
    copy_into(
        Lane::Bool,
        rust,
        || canonical_bool_renderer::render(value).map_err(|_| ()),
        output,
    )
}

pub(crate) fn int_into(value: i64, rust: &str, output: &mut [u8; MAX_TOKEN_BYTES]) -> usize {
    copy_into(
        Lane::Int,
        rust,
        || canonical_int_renderer::render(value).map_err(|_| ()),
        output,
    )
}

pub(crate) fn binary_operator_into(
    op: BinaryOp,
    rust: &str,
    output: &mut [u8; MAX_TOKEN_BYTES],
) -> usize {
    copy_into(
        Lane::Operator,
        rust,
        || canonical_operator_renderer::render_binary(op).map_err(|_| ()),
        output,
    )
}

pub(crate) fn unary_operator_into(
    op: UnaryOp,
    rust: &str,
    output: &mut [u8; MAX_TOKEN_BYTES],
) -> usize {
    copy_into(
        Lane::Operator,
        rust,
        || canonical_operator_renderer::render_unary(op).map_err(|_| ()),
        output,
    )
}

pub(crate) fn string_scalar_into(
    value: u32,
    rust: &str,
    output: &mut [u8; MAX_TOKEN_BYTES],
) -> usize {
    copy_into(
        Lane::StringScalar,
        rust,
        || canonical_string_renderer::render(value).map_err(|_| ()),
        output,
    )
}

#[cfg(test)]
thread_local! {
    static COUNTS: std::cell::Cell<Option<[usize; 5]>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn record(lane: Lane) {
    COUNTS.with(|counts| {
        if let Some(mut next) = counts.get() {
            next[lane.index()] += 1;
            counts.set(Some(next));
        }
    });
}

#[cfg(not(test))]
fn record(_: Lane) {}

#[cfg(test)]
pub(crate) fn with_counts<T>(operation: impl FnOnce() -> T) -> (T, [usize; 5]) {
    COUNTS.with(|counts| {
        assert!(
            counts.replace(Some([0; 5])).is_none(),
            "renderer count scope cannot nest"
        );
    });
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            COUNTS.set(None);
        }
    }
    let restore = Restore;
    let value = operation();
    let counts = COUNTS
        .take()
        .expect("renderer count scope must remain active");
    drop(restore);
    (value, counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_mismatch_and_oversize_keep_the_pointer_exact_rust_borrow() {
        let rust = "rust";
        for candidate in [Err(()), Ok("wrong".to_owned()), Ok("x".repeat(21))] {
            match select(Lane::Char, rust, candidate) {
                Selected::Rust(bytes) => {
                    assert_eq!(bytes, rust.as_bytes());
                    assert_eq!(bytes.as_ptr(), rust.as_bytes().as_ptr());
                }
                Selected::Candidate(_) => panic!("nonmatching candidate became authority"),
            }
        }
    }

    #[test]
    fn match_copies_only_to_caller_owned_fixed_storage() {
        let mut output = [0; MAX_TOKEN_BYTES];
        let selected = select(Lane::Bool, "true", Ok("true".to_owned()));
        assert_eq!(selected.copy_to(&mut output), 4);
        assert_eq!(&output[..4], b"true");
    }

    #[test]
    fn nested_candidate_scope_uses_rust_and_does_not_leak() {
        let mut outer = [0; MAX_TOKEN_BYTES];
        let mut nested = [0; MAX_TOKEN_BYTES];
        let mut nested_candidate_ran = false;
        let outer_len = copy_into(
            Lane::Char,
            "outer",
            || {
                let nested_len = copy_into(
                    Lane::Bool,
                    "true",
                    || {
                        nested_candidate_ran = true;
                        Ok("wrong".to_owned())
                    },
                    &mut nested,
                );
                assert_eq!(&nested[..nested_len], b"true");
                Ok("outer".to_owned())
            },
            &mut outer,
        );
        assert_eq!(&outer[..outer_len], b"outer");
        assert!(!nested_candidate_ran, "nested candidate must not execute");

        let mut after = [0; MAX_TOKEN_BYTES];
        let mut after_candidate_ran = false;
        let after_len = copy_into(
            Lane::Bool,
            "true",
            || {
                after_candidate_ran = true;
                Ok("true".to_owned())
            },
            &mut after,
        );
        assert!(
            after_candidate_ran,
            "candidate scope leaked after outer return"
        );
        assert_eq!(&after[..after_len], b"true");
    }

    #[test]
    fn candidate_scope_restores_after_panic() {
        let panic = std::panic::catch_unwind(|| {
            in_candidate_scope(|| panic!("injected scope panic"));
        });
        assert!(panic.is_err());
        assert!(!CANDIDATE_ACTIVE.with(|active| active.get()));

        let before = super::super::rung_two_owned_handoff::handoffs();
        let fallback = std::panic::catch_unwind(|| {
            let mut output = [0; MAX_TOKEN_BYTES];
            let len = copy_into(
                Lane::Char,
                "x",
                || -> Result<String, ()> { panic!("injected candidate panic") },
                &mut output,
            );
            assert_eq!(&output[..len], b"x");
        });
        assert!(fallback.is_ok(), "candidate panic escaped Rust fallback");
        assert!(!CANDIDATE_ACTIVE.with(|active| active.get()));
        assert_eq!(super::super::rung_two_owned_handoff::handoffs(), before);

        let mut output = [0; MAX_TOKEN_BYTES];
        let mut candidate_ran = false;
        let len = copy_into(
            Lane::Char,
            "x",
            || {
                candidate_ran = true;
                Ok("x".to_owned())
            },
            &mut output,
        );
        assert!(candidate_ran, "panic left the candidate scope active");
        assert_eq!(&output[..len], b"x");
        assert_eq!(super::super::rung_two_owned_handoff::handoffs(), before + 1);
    }

    #[test]
    fn bounded_output_scope_bypasses_candidates_without_leaking() {
        let (_, counts) = with_counts(|| {
            let mut bounded = [0; MAX_TOKEN_BYTES];
            let mut bounded_candidate_ran = false;
            let (len, overflowed) = crate::bounded_output::with_limit(64, || {
                assert_eq!(crate::bounded_output::active_limit(), Some(64));
                copy_into(
                    Lane::Char,
                    "x",
                    || {
                        bounded_candidate_ran = true;
                        Ok("wrong".to_owned())
                    },
                    &mut bounded,
                )
            });
            assert!(
                !overflowed,
                "Rust-only token copy must not spend the budget"
            );
            assert_eq!(&bounded[..len], b"x");
            assert!(
                !bounded_candidate_ran,
                "bounded formatter caller must not evaluate evidence"
            );
            assert_eq!(crate::bounded_output::active_limit(), None);

            let mut after = [0; MAX_TOKEN_BYTES];
            let mut after_candidate_ran = false;
            let len = copy_into(
                Lane::Char,
                "x",
                || {
                    after_candidate_ran = true;
                    Ok("x".to_owned())
                },
                &mut after,
            );
            assert!(
                after_candidate_ran,
                "bounded scope leaked into later formatter work"
            );
            assert_eq!(&after[..len], b"x");
        });
        assert_eq!(counts, [1, 0, 0, 0, 0]);
    }

    #[test]
    fn package_report_generation_completes_without_formatter_recursion() {
        let report = crate::package_report_v2::generate(
            std::path::Path::new("examples/meaning.spx"),
            &crate::package_report_v2::PackageReportV2Options::default(),
        )
        .expect("package report must not recurse through formatter candidates");
        assert!(report.contains("\"schema\":\"semaprax.canonical-source.v1\""));
    }
}
