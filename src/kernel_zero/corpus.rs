//! A small, deterministic Kernel-0 `.spx` program generator.
//!
//! Produces well-typed Kernel-0-shaped source text -- not `Term`s -- because
//! the differential test (`super::differential`) needs actual `.spx` bytes
//! to hand to the compiler's own `parse` -> `hir::resolve` -> `interpret`
//! pipeline anyway; generating text directly means the exact same bytes
//! feed both the reference interpreter's side (via `super::reify`, after an
//! independent `parse`/`resolve`) and the compiler's side, so nothing here
//! needs its own parallel `Term` builder.
//!
//! Determinism: every program in [`generated_corpus`] is produced by one
//! `Xorshift64` stream seeded from the fixed constant [`CORPUS_SEED`]. Same
//! seed, same Rust version, same output, every run -- a repository
//! invariant ("Source formatting, graph JSON, Wasm bytes, diagnostics,
//! semantic patches, and contracted generated artifacts are deterministic",
//! `AGENTS.md`) that a flaky generator would quietly violate for this test.

use super::value::Value;

/// Fixed generator seed. Recorded here, not only in the differential test's
/// report, so a future run reproduces today's exact corpus without needing
/// to consult this task's report.
pub(crate) const CORPUS_SEED: u64 = 0x4B65_726E_656C_3021; // ASCII "Kernel0!"

/// Number of generated programs. Kept modest: each program is exercised
/// against the real compiler through `interpreter::interpret`, which spawns
/// a dedicated OS thread per call, so this bounds the differential test's
/// wall-clock cost, not the interestingness of any one program.
pub(crate) const CORPUS_PROGRAM_COUNT: usize = 60;

/// Kernel-0's two scalar types, for this generator's own bookkeeping (which
/// declared name has which type, so a later reference stays well-typed).
/// Deliberately a local copy of the two-variant shape rather than importing
/// `super::term::KernelType`: the generator's job is only to know "which of
/// the two scalar types is this slot", the same fact the grammar's own `Ty`
/// production states, not to share code with the term/eval/reify pipeline
/// it is independently exercising.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GenType {
    I64,
    Bool,
}

impl GenType {
    fn source_name(self) -> &'static str {
        match self {
            Self::I64 => "i64",
            Self::Bool => "bool",
        }
    }
}

/// One generated Kernel-0 program: its full `.spx` source (including the
/// placeholder `main` every SEMAPRAX program needs), the `@id` of the
/// function under test, that function's parameter types, and a handful of
/// concrete argument tuples to run it with.
pub(crate) struct GeneratedProgram {
    pub(crate) source: String,
    pub(crate) entry_id: String,
    pub(crate) entry_params: Vec<GenType>,
    pub(crate) samples: Vec<Vec<Value>>,
}

/// A small, non-cryptographic xorshift64* PRNG. Not `rand`: a self-contained
/// generator keeps this corpus reproducible from source alone, with no
/// dependency-version sensitivity, and Kernel-0's own corpus has no need for
/// statistical rigor beyond "varied and deterministic".
struct Xorshift64(u64);

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        // xorshift64 is undefined at state zero; the seed's low bit is
        // forced on so a zero `CORPUS_SEED` could never silently stall.
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_below(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "kernel-0 corpus generator: next_below(0)");
        (self.next_u64() % bound as u64) as usize
    }

    fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }

    /// A signed 64-bit value biased toward the exact boundaries where `i64`
    /// arithmetic stops being total (zero, +/-1, `i64::MAX`, `i64::MIN`),
    /// plus an ordinary small or arbitrary value -- see the task's own
    /// emphasis on overflow and division/remainder by zero.
    fn next_hazardous_i64(&mut self) -> i64 {
        match self.next_below(9) {
            0 => 0,
            1 => 1,
            2 => -1,
            3 => 2,
            4 => -2,
            5 => i64::MAX,
            6 => i64::MIN,
            7 => (self.next_u64() as i64) / 1_000_000_000,
            _ => (self.next_u64() % 21) as i64 - 10,
        }
    }
}

/// One generated helper's callable signature: its declared *name* (what a
/// `Call` site writes, e.g. `helper0(...)`; distinct from its `@id`, which
/// is only the external stable-identity attribute) plus parameter/return
/// types.
struct FnSignature {
    name: String,
    params: Vec<GenType>,
    return_type: GenType,
}

/// In-scope `let`/parameter bindings while generating one function body.
type Scope = Vec<(String, GenType)>;

struct Generator {
    rng: Xorshift64,
    functions: Vec<FnSignature>,
    fresh_var: u64,
}

impl Generator {
    fn fresh_var_name(&mut self) -> String {
        self.fresh_var += 1;
        format!("gen_v{}", self.fresh_var)
    }

    fn gen_type(&mut self) -> GenType {
        if self.rng.next_bool() {
            GenType::I64
        } else {
            GenType::Bool
        }
    }

    fn gen_expr(&mut self, ty: GenType, scope: &Scope, depth: u32) -> String {
        match ty {
            GenType::I64 => self.gen_i64(scope, depth),
            GenType::Bool => self.gen_bool(scope, depth),
        }
    }

    fn gen_leaf(&mut self, ty: GenType, scope: &Scope) -> String {
        let vars: Vec<&str> = scope
            .iter()
            .filter(|(_, var_ty)| *var_ty == ty)
            .map(|(name, _)| name.as_str())
            .collect();
        if !vars.is_empty() && self.rng.next_bool() {
            return vars[self.rng.next_below(vars.len())].to_owned();
        }
        match ty {
            GenType::I64 => {
                let value = self.rng.next_hazardous_i64();
                if value < 0 {
                    format!("({value})")
                } else {
                    value.to_string()
                }
            }
            GenType::Bool => {
                if self.rng.next_bool() {
                    "true".to_owned()
                } else {
                    "false".to_owned()
                }
            }
        }
    }

    fn gen_i64(&mut self, scope: &Scope, depth: u32) -> String {
        if depth == 0 || self.rng.next_below(4) == 0 {
            return self.gen_leaf(GenType::I64, scope);
        }
        match self.rng.next_below(5) {
            0 => {
                let op = ["+", "-", "*", "/", "%"][self.rng.next_below(5)];
                let left = self.gen_i64(scope, depth - 1);
                let right = self.gen_i64(scope, depth - 1);
                format!("({left} {op} {right})")
            }
            1 => format!("(-{})", self.gen_i64(scope, depth - 1)),
            2 => {
                let condition = self.gen_bool(scope, depth - 1);
                let then_branch = self.gen_i64(scope, depth - 1);
                let else_branch = self.gen_i64(scope, depth - 1);
                format!("(if {condition} {{ {then_branch} }} else {{ {else_branch} }})")
            }
            3 => self.gen_let(GenType::I64, scope, depth),
            _ => self.gen_call(GenType::I64, scope, depth),
        }
    }

    fn gen_bool(&mut self, scope: &Scope, depth: u32) -> String {
        if depth == 0 || self.rng.next_below(4) == 0 {
            return self.gen_leaf(GenType::Bool, scope);
        }
        match self.rng.next_below(6) {
            0 => {
                let ops = ["==", "!=", "<", "<=", ">", ">="];
                let op = ops[self.rng.next_below(ops.len())];
                let left = self.gen_i64(scope, depth - 1);
                let right = self.gen_i64(scope, depth - 1);
                format!("({left} {op} {right})")
            }
            // A documented extension beyond Kernel-0's stated typing table:
            // the real admitted language (confirmed against the built CLI)
            // and `kernel_zero::reifies_into_kernel_zero` both also accept
            // `bool == bool` / `bool != bool`, which the document's typing
            // rules do not state -- see `docs/SEMANTIC-KERNEL-V1.md` and
            // this task's report.
            1 => {
                let op = if self.rng.next_bool() { "==" } else { "!=" };
                let left = self.gen_bool(scope, depth - 1);
                let right = self.gen_bool(scope, depth - 1);
                format!("({left} {op} {right})")
            }
            2 => format!("(!{})", self.gen_bool(scope, depth - 1)),
            3 => {
                let condition = self.gen_bool(scope, depth - 1);
                let then_branch = self.gen_bool(scope, depth - 1);
                let else_branch = self.gen_bool(scope, depth - 1);
                format!("(if {condition} {{ {then_branch} }} else {{ {else_branch} }})")
            }
            4 => self.gen_let(GenType::Bool, scope, depth),
            _ => self.gen_bool_connective(scope, depth),
        }
    }

    /// `&&`/`||`, biased so a literal, known-short-circuiting left operand
    /// (`false &&`, `true ||`) appears often: with the right operand drawn
    /// from the same hazard-biased generator as everywhere else, this
    /// deliberately manufactures many `false && <would-fault>` /
    /// `true || <would-fault>` cases across the corpus, not just the hand-
    /// written ones, to fuzz "lazy boolean operands execute only when
    /// required" (`AGENTS.md`) rather than merely assert it once.
    fn gen_bool_connective(&mut self, scope: &Scope, depth: u32) -> String {
        let is_and = self.rng.next_bool();
        let op = if is_and { "&&" } else { "||" };
        let left = if self.rng.next_below(2) == 0 {
            (if is_and { "false" } else { "true" }).to_owned()
        } else {
            self.gen_bool(scope, depth.saturating_sub(1))
        };
        let right = self.gen_bool(scope, depth.saturating_sub(1));
        format!("({left} {op} {right})")
    }

    fn gen_let(&mut self, ty: GenType, scope: &Scope, depth: u32) -> String {
        let bound_type = self.gen_type();
        let name = self.fresh_var_name();
        let value = self.gen_expr(bound_type, scope, depth.saturating_sub(1));
        let mut inner_scope = scope.clone();
        inner_scope.push((name.clone(), bound_type));
        let body = self.gen_expr(ty, &inner_scope, depth.saturating_sub(1));
        format!("{{ let {name} = {value}; {body} }}")
    }

    fn gen_call(&mut self, ty: GenType, scope: &Scope, depth: u32) -> String {
        let candidates: Vec<usize> = self
            .functions
            .iter()
            .enumerate()
            .filter(|(_, signature)| signature.return_type == ty)
            .map(|(index, _)| index)
            .collect();
        if candidates.is_empty() || depth == 0 {
            return self.gen_leaf(ty, scope);
        }
        let chosen = candidates[self.rng.next_below(candidates.len())];
        let name = self.functions[chosen].name.clone();
        let params = self.functions[chosen].params.clone();
        let args: Vec<String> = params
            .iter()
            .map(|param_type| self.gen_expr(*param_type, scope, depth.saturating_sub(1)))
            .collect();
        format!("{name}({})", args.join(", "))
    }

    /// A concrete argument value for `ty`, drawn from the same hazard-biased
    /// distribution `gen_leaf` uses, for sampling call arguments once a
    /// program's source is finished.
    fn sample_value(&mut self, ty: GenType) -> Value {
        match ty {
            GenType::I64 => Value::Int(self.rng.next_hazardous_i64()),
            GenType::Bool => Value::Bool(self.rng.next_bool()),
        }
    }
}

fn function_declaration(
    id: &str,
    name: &str,
    scope: &Scope,
    return_type: GenType,
    body: &str,
) -> String {
    let params_text = scope
        .iter()
        .map(|(name, ty)| format!("{name}: {}", ty.source_name()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "@id(\"{id}\")\nfn {name}({params_text}) -> {} {{\n    {body}\n}}\n\n",
        return_type.source_name()
    )
}

/// Generates one program: `helper_count` (1..=4) non-recursive helper
/// functions, each usable by every later one (guaranteeing an acyclic call
/// graph by construction, never checked after the fact), then one "entry"
/// function under test, then a handful of concrete argument samples for it.
fn generate_one(generator: &mut Generator) -> GeneratedProgram {
    generator.functions.clear();
    generator.fresh_var = 0;
    let mut source = String::from(
        "module test.kernel_zero_corpus;\n\n@id(\"app.main\")\nfn main() -> i64 { 0 }\n\n",
    );

    let helper_count = 1 + generator.rng.next_below(4);
    for index in 0..helper_count {
        let param_count = generator.rng.next_below(3);
        let name = format!("helper{index}");
        let scope: Scope = (0..param_count)
            .map(|slot| (format!("p{slot}"), generator.gen_type()))
            .collect();
        let return_type = generator.gen_type();
        let body = generator.gen_expr(return_type, &scope, 4);
        source.push_str(&function_declaration(
            &format!("test.{name}"),
            &name,
            &scope,
            return_type,
            &body,
        ));
        generator.functions.push(FnSignature {
            name,
            params: scope.iter().map(|(_, ty)| *ty).collect(),
            return_type,
        });
    }

    let entry_param_count = generator.rng.next_below(3);
    let entry_scope: Scope = (0..entry_param_count)
        .map(|slot| (format!("e{slot}"), generator.gen_type()))
        .collect();
    let entry_return = generator.gen_type();
    let entry_body = generator.gen_expr(entry_return, &entry_scope, 5);
    source.push_str(&function_declaration(
        "app.entry",
        "entry",
        &entry_scope,
        entry_return,
        &entry_body,
    ));

    let entry_params: Vec<GenType> = entry_scope.iter().map(|(_, ty)| *ty).collect();
    let sample_count = if entry_params.is_empty() { 1 } else { 4 };
    let samples: Vec<Vec<Value>> = (0..sample_count)
        .map(|_| {
            entry_params
                .iter()
                .map(|ty| generator.sample_value(*ty))
                .collect()
        })
        .collect();

    GeneratedProgram {
        source,
        entry_id: "app.entry".to_owned(),
        entry_params,
        samples,
    }
}

/// The whole deterministic corpus, in generation order, from
/// [`CORPUS_SEED`].
pub(crate) fn generated_corpus() -> Vec<GeneratedProgram> {
    let mut generator = Generator {
        rng: Xorshift64::new(CORPUS_SEED),
        functions: Vec::new(),
        fresh_var: 0,
    };
    (0..CORPUS_PROGRAM_COUNT)
        .map(|_| generate_one(&mut generator))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_generation_is_deterministic() {
        let first: Vec<String> = generated_corpus()
            .into_iter()
            .map(|program| program.source)
            .collect();
        let second: Vec<String> = generated_corpus()
            .into_iter()
            .map(|program| program.source)
            .collect();
        assert_eq!(
            first, second,
            "same seed must reproduce byte-identical source text"
        );
    }

    #[test]
    fn corpus_is_nonempty_and_bounded() {
        let corpus = generated_corpus();
        assert_eq!(corpus.len(), CORPUS_PROGRAM_COUNT);
        for program in &corpus {
            assert!(
                program.source.len() < 8192,
                "generated program is unexpectedly large"
            );
            assert!(!program.samples.is_empty());
        }
    }
}
