//! Parsing a pinned Lean toolchain's build output into one closed verdict.
//!
//! This module is a pure function from `(expected theorem names, raw build
//! output)` to a closed [`KernelVerdict`]. It never spawns a process, reads a
//! file, or consults the environment: running Lean is the caller's job,
//! expressed as the [`super::LeanKernel`] capability, so this crate gains no
//! ambient process authority from the existence of a parser.
//!
//! # What must never be accepted as proof
//!
//! Issue #186 lists, as explicitly out of scope, "accepting `sorry`,
//! admitted axioms, unchecked code, or timeouts as theorem proof". The
//! parser enforces exactly that, and is fail-closed by construction: it
//! starts from "rejected" and only reaches [`KernelVerdict::Checked`] when
//! *every* expected theorem produced its own `#print axioms` line and every
//! such line's axiom set is a subset of Lean's three standard axioms.
//! Output it does not understand is a rejection, never a pass.
//!
//! The axiom-set check is the authoritative one, and it is the same check
//! `scripts/kernel0-lean-gate.py` already applies to the Kernel-0 proof
//! (issue #188): `sorryAx` is how an admitted hole shows up in an
//! elaborated proof term, so a `sorry` that a source-text scan missed still
//! cannot pass here.

/// The Lean toolchain this export is pinned to, byte-identical to
/// `proofs/kernel0-lean/lean-toolchain` (issue #188's already-pinned
/// kernel — deliberately not a second toolchain). A kernel run reporting a
/// different toolchain is refused, because "toolchain version drift can
/// change accepted proofs" is one of the issue's named failure modes.
pub const PINNED_TOOLCHAIN: &str = "leanprover/lean4:v4.34.0";

/// The kernel identity recorded in certificates.
pub const KERNEL_IDENTITY: &str = "lean4";

/// Lean's three standard axioms, sorted. Anything outside this set —
/// `sorryAx` above all — invalidates a theorem.
pub const STANDARD_AXIOMS: [&str; 3] = ["Classical.choice", "Quot.sound", "propext"];

/// Exactly why a kernel run was not accepted. No variant is a catch-all
/// "something went wrong that we will treat leniently": every one of these
/// is a refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rejection {
    /// The build emitted an `error:` line.
    BuildError { excerpt: String },
    /// A declaration used `sorry` (or `admit`), reported by Lean as a
    /// warning rather than an error.
    AdmittedHole { excerpt: String },
    /// A deterministic timeout or recursion-depth cutoff. Explicitly not a
    /// proof.
    Timeout { excerpt: String },
    /// An expected theorem produced no `#print axioms` line at all, so the
    /// kernel never confirmed it exists with the statement we exported.
    MissingTheorem { theorem: String },
    /// An expected theorem produced more than one `#print axioms` line, so
    /// which one is authoritative is ambiguous.
    DuplicateTheorem { theorem: String },
    /// A theorem depends on an axiom outside [`STANDARD_AXIOMS`].
    ForbiddenAxiom { theorem: String, axiom_name: String },
    /// The caller's kernel reported a toolchain other than the pinned one.
    ToolchainDrift { reported: String },
    /// The output contained nothing this parser recognizes.
    Unrecognized,
}

impl Rejection {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BuildError { .. } => "build_error",
            Self::AdmittedHole { .. } => "admitted_hole",
            Self::Timeout { .. } => "timeout",
            Self::MissingTheorem { .. } => "missing_theorem",
            Self::DuplicateTheorem { .. } => "duplicate_theorem",
            Self::ForbiddenAxiom { .. } => "forbidden_axiom",
            Self::ToolchainDrift { .. } => "toolchain_drift",
            Self::Unrecognized => "unrecognized_output",
        }
    }

    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::BuildError { excerpt } => format!("the Lean build reported an error: {excerpt}"),
            Self::AdmittedHole { excerpt } => {
                format!("a declaration uses an admitted hole: {excerpt}")
            }
            Self::Timeout { excerpt } => {
                format!("the Lean run hit a deterministic cutoff, which is not a proof: {excerpt}")
            }
            Self::MissingTheorem { theorem } => {
                format!("no `#print axioms` line for expected theorem `{theorem}`")
            }
            Self::DuplicateTheorem { theorem } => {
                format!("more than one `#print axioms` line for theorem `{theorem}`")
            }
            Self::ForbiddenAxiom {
                theorem,
                axiom_name,
            } => format!("theorem `{theorem}` depends on non-standard axiom `{axiom_name}`"),
            Self::ToolchainDrift { reported } => format!(
                "kernel reported toolchain `{reported}`, not the pinned `{PINNED_TOOLCHAIN}`"
            ),
            Self::Unrecognized => {
                "the kernel output contained no recognizable `#print axioms` report".to_owned()
            }
        }
    }
}

/// The closed verdict. There is deliberately no "probably fine" state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelVerdict {
    /// Every expected theorem was confirmed, depending only on standard
    /// axioms. `axioms` lists, per theorem in the caller's expected order,
    /// the exact axiom set the kernel reported.
    Checked {
        axioms: Vec<(String, Vec<String>)>,
    },
    Rejected(Rejection),
}

fn excerpt(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.chars().count() <= 200 {
        trimmed.to_owned()
    } else {
        trimmed.chars().take(200).collect::<String>() + "…"
    }
}

/// Parse one `#print axioms` line. Lean prints either
/// `'Name' depends on axioms: [a, b]` or `'Name' does not depend on any axioms`.
fn parse_axiom_line(line: &str) -> Option<(String, Vec<String>)> {
    let trimmed = line.trim();
    let body = trimmed.strip_prefix("info: ").unwrap_or(trimmed);
    // Lean prefixes build output lines with a file/position banner; take
    // everything from the first quote.
    let start = body.find('\'')?;
    let rest = &body[start + 1..];
    let end = rest.find('\'')?;
    let name = rest[..end].to_owned();
    let tail = rest[end + 1..].trim_start();
    if let Some(list) = tail.strip_prefix("depends on axioms: [") {
        let list = list.strip_suffix(']').unwrap_or(list);
        let axioms = list
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect();
        Some((name, axioms))
    } else if tail.starts_with("does not depend on any axioms") {
        Some((name, Vec::new()))
    } else {
        None
    }
}

/// Decide whether `output` is an acceptance of exactly `expected` (in that
/// order). `toolchain` is what the caller's kernel reported running.
#[must_use]
pub fn parse(expected: &[String], toolchain: &str, output: &str) -> KernelVerdict {
    if toolchain != PINNED_TOOLCHAIN {
        return KernelVerdict::Rejected(Rejection::ToolchainDrift {
            reported: toolchain.to_owned(),
        });
    }
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("(deterministic) timeout")
            || lower.contains("maximum recursion depth has been reached")
            || lower.contains("deep recursion was detected")
        {
            return KernelVerdict::Rejected(Rejection::Timeout {
                excerpt: excerpt(line),
            });
        }
        if lower.contains("declaration uses 'sorry'")
            || lower.contains("uses sorry")
            || lower.contains("sorryax")
        {
            return KernelVerdict::Rejected(Rejection::AdmittedHole {
                excerpt: excerpt(line),
            });
        }
        if lower.contains("error:") {
            return KernelVerdict::Rejected(Rejection::BuildError {
                excerpt: excerpt(line),
            });
        }
    }

    let mut reported: Vec<(String, Vec<String>)> = Vec::new();
    for line in output.lines() {
        if let Some(entry) = parse_axiom_line(line) {
            reported.push(entry);
        }
    }
    if reported.is_empty() {
        return KernelVerdict::Rejected(Rejection::Unrecognized);
    }

    let mut axioms = Vec::with_capacity(expected.len());
    for theorem in expected {
        let mut matches = reported.iter().filter(|(name, _)| name == theorem);
        let Some((_, found)) = matches.next() else {
            return KernelVerdict::Rejected(Rejection::MissingTheorem {
                theorem: theorem.clone(),
            });
        };
        if matches.next().is_some() {
            return KernelVerdict::Rejected(Rejection::DuplicateTheorem {
                theorem: theorem.clone(),
            });
        }
        for axiom_name in found {
            if !STANDARD_AXIOMS.contains(&axiom_name.as_str()) {
                return KernelVerdict::Rejected(Rejection::ForbiddenAxiom {
                    theorem: theorem.clone(),
                    axiom_name: axiom_name.clone(),
                });
            }
        }
        let mut sorted = found.clone();
        sorted.sort();
        axioms.push((theorem.clone(), sorted));
    }
    KernelVerdict::Checked { axioms }
}
