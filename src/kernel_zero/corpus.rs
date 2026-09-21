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

/// A compact, deterministic adversarial corpus for the part of Kernel-0
/// semantics a random expression generator is least likely to cover: which
/// *particular* checked-arithmetic fault becomes observable when more than
/// one subexpression could fault.  These are source programs, rather than
/// synthetic `Term`s, for the same reason as [`generated_corpus`]: the
/// reference evaluator and every compiler backend must receive identical
/// source bytes.
///
/// The selector's eight branches name the complete [`super::value::Fault`]
/// family in its public status-code order.  Each strict context is sampled
/// over its full ordered 8-by-8 product.  Thus, for example, changing a
/// backend to evaluate `fault(right)` before `fault(left)` cannot still pass
/// by merely producing some arithmetic failure: at least one sample exposes
/// the wrong named fault.  The corpus is deliberately finite evidence, not a
/// proof or a replacement for the mechanized Kernel-0 model.
pub(crate) fn adversarial_fault_corpus() -> Vec<GeneratedProgram> {
    const KINDS: i64 = 8;

    let pairs = (0..KINDS)
        .flat_map(|left| (0..KINDS).map(move |right| vec![Value::Int(left), Value::Int(right)]))
        .collect::<Vec<_>>();
    let kinds = (0..KINDS)
        .map(|kind| vec![Value::Int(kind)])
        .collect::<Vec<_>>();
    let branches = (0..KINDS)
        .flat_map(|selected| {
            (0..KINDS).flat_map(move |unselected| {
                [
                    vec![
                        Value::Bool(true),
                        Value::Int(selected),
                        Value::Int(unselected),
                    ],
                    vec![
                        Value::Bool(false),
                        Value::Int(unselected),
                        Value::Int(selected),
                    ],
                ]
            })
        })
        .chain((0..KINDS).flat_map(|inactive| {
            [
                vec![Value::Bool(true), Value::Int(KINDS), Value::Int(inactive)],
                vec![Value::Bool(false), Value::Int(inactive), Value::Int(KINDS)],
            ]
        }))
        .collect::<Vec<_>>();

    let module = |name: &str, helpers: &str, parameters: &str, return_type: &str, body: &str| {
        format!(
            "module test.kernel_zero_adversarial;\n\n@id(\"app.main\")\nfn main() -> i64 {{ 0 }}\n\n{helpers}@id(\"app.entry\")\nfn {name}({parameters}) -> {return_type}\n{{\n    {body}\n}}\n"
        )
    };
    let selector = "@id(\"test.fault\")\nfn fault(kind: i64) -> i64\n{\n    \
if kind == 0 { 9223372036854775807 + 1 } else {\n        \
if kind == 1 { (-9223372036854775807) - 2 } else {\n            \
if kind == 2 { 4611686018427387904 * 2 } else {\n                \
if kind == 3 { 1 / 0 } else {\n                    \
if kind == 4 { (-9223372036854775807 - 1) / -1 } else {\n                        \
if kind == 5 { 1 % 0 } else {\n                            \
if kind == 6 { (-9223372036854775807 - 1) % -1 } else {\n                            \
if kind == 7 { -(-9223372036854775807 - 1) } else { 7 }\n                        }\n                    }\n                }\n            }\n        }\n    }\n}\n}\n\n";
    let take_first =
        "@id(\"test.take_first\")\nfn take_first(first: i64, second: i64) -> i64 { first }\n\n";
    let strict = |name: &str, return_type: &str, body: &str, helpers: &str| GeneratedProgram {
        source: module(
            name,
            &format!("{selector}{helpers}"),
            "left: i64, right: i64",
            return_type,
            body,
        ),
        entry_id: "app.entry".to_owned(),
        entry_params: vec![GenType::I64, GenType::I64],
        samples: pairs.clone(),
    };

    vec![
        strict("entry", "i64", "fault(left) + fault(right)", ""),
        strict("entry", "bool", "fault(left) < fault(right)", ""),
        strict(
            "entry",
            "i64",
            "take_first(fault(left), fault(right))",
            take_first,
        ),
        strict(
            "entry",
            "i64",
            "let bound = fault(left);\n    fault(right)",
            "",
        ),
        strict(
            "entry",
            "bool",
            "(fault(left) == 0) && (fault(right) == 0)",
            "",
        ),
        strict(
            "entry",
            "bool",
            "(fault(left) == 0) || (fault(right) == 0)",
            "",
        ),
        GeneratedProgram {
            source: module(
                "entry",
                selector,
                "kind: i64",
                "bool",
                "false && (fault(kind) == 0)",
            ),
            entry_id: "app.entry".to_owned(),
            entry_params: vec![GenType::I64],
            samples: kinds.clone(),
        },
        GeneratedProgram {
            source: module(
                "entry",
                selector,
                "kind: i64",
                "bool",
                "true || (fault(kind) == 0)",
            ),
            entry_id: "app.entry".to_owned(),
            entry_params: vec![GenType::I64],
            samples: kinds,
        },
        GeneratedProgram {
            source: module(
                "entry",
                selector,
                "pick: bool, selected: i64, unselected: i64",
                "i64",
                "if pick { fault(selected) } else { fault(unselected) }",
            ),
            entry_id: "app.entry".to_owned(),
            entry_params: vec![GenType::Bool, GenType::I64, GenType::I64],
            samples: branches,
        },
    ]
}

/// Deterministic structural programs aimed at the coverage holes that a
/// hazard-biased expression generator and the fault-selection matrix leave
/// behind.  In particular, these cases keep arithmetic *in range* at the
/// signed boundaries, make several layers of control demonstrably lazy, and
/// raise the real reified call/lexical structure far above the generator's
/// ordinary depth.  They therefore exercise the bounded translation and its
/// weighted-call certificate as concrete input, rather than merely producing
/// another random mix of small expressions.
///
/// Like [`adversarial_fault_corpus`], this remains finite test evidence.  It
/// intentionally stays below the private certificate harness's 64-function
/// and 128-depth limits: testing the admitted side of those limits is useful
/// here; changing the proof-profile refusal boundary is not.
pub(crate) fn adversarial_structure_corpus() -> Vec<GeneratedProgram> {
    let module = |name: &str, helpers: &str, parameters: &str, return_type: &str, body: &str| {
        format!(
            "module test.kernel_zero_structure;\n\n@id(\"app.main\")\nfn main() -> i64 {{ 0 }}\n\n{helpers}@id(\"app.entry\")\nfn {name}({parameters}) -> {return_type}\n{{\n    {body}\n}}\n"
        )
    };

    // Forty non-recursive calls are long enough to make function inventory,
    // call-target identity, and weighted descent materially observable while
    // still leaving clear headroom under the proof harness's explicit 64/128
    // certificate ceilings.  Each edge contributes a fresh arithmetic node
    // too, so accidentally omitting a callee or charging only immediate calls
    // cannot be hidden by a constant-return chain.
    const CALL_DEPTH: usize = 40;
    let mut deep_call_helpers = String::new();
    deep_call_helpers.push_str("@id(\"test.call_0\")\nfn call_0(value: i64) -> i64 { value }\n\n");
    for index in 1..=CALL_DEPTH {
        deep_call_helpers.push_str(&format!(
            "@id(\"test.call_{index}\")\nfn call_{index}(value: i64) -> i64 {{ call_{}(value + 1) }}\n\n",
            index - 1
        ));
    }

    // A fresh name at each level is required: the real resolver deliberately
    // rejects same-scope shadowing.  This is a 48-deep lexical/de-Bruijn
    // stress shape, not a test of an unsupported shadowing feature.
    const LET_DEPTH: usize = 48;
    let mut deep_let_body = format!("value_{LET_DEPTH}");
    for index in (1..=LET_DEPTH).rev() {
        let previous = if index == 1 {
            "0".to_owned()
        } else {
            format!("value_{}", index - 1)
        };
        deep_let_body = format!("{{ let value_{index} = {previous} + 1; {deep_let_body} }}");
    }

    let safe_arithmetic = module(
        "entry",
        "",
        "case: i64",
        "i64",
        "if case == 0 { (-9223372036854775807 - 1) + 0 } else {\n        \
if case == 1 { 9223372036854775807 + 0 } else {\n            \
if case == 2 { (-9223372036854775807 - 1) - 0 } else {\n                \
if case == 3 { 9223372036854775807 - 0 } else {\n                    \
if case == 4 { (-9223372036854775807 - 1) * 1 } else {\n                        \
if case == 5 { 9223372036854775807 * 1 } else {\n                            \
if case == 6 { (-9223372036854775807 - 1) / 1 } else {\n                                \
if case == 7 { 9223372036854775807 / 1 } else {\n                                    \
if case == 8 { (-9223372036854775807 - 1) % 1 } else {\n                                        \
if case == 9 { 9223372036854775807 % -1 } else {\n                                            \
if case == 10 { -7 / 3 } else {\n                                                \
if case == 11 { -7 % 3 } else {\n                                                    \
if case == 12 { 7 / -3 } else {\n                                                        \
if case == 13 { 7 % -3 } else { -(-9223372036854775807) }\n                                                    }\n                                                }\n                                            }\n                                        }\n                                    }\n                                }\n                            }\n                        }\n                    }\n                }\n            }\n        }\n    }\n}",
    );

    let lazy_control = module(
        "entry",
        "@id(\"test.fault\")\nfn fault(kind: i64) -> i64\n{\n    if kind == 0 { 1 / 0 } else {\n        if kind == 1 { 5 % 0 } else {\n            if kind == 2 { 9223372036854775807 + 1 } else { 17 }\n        }\n    }\n}\n\n",
        "pick: bool, kind: i64",
        "i64",
        "if pick {\n        let first = if false { fault(kind) } else { 40 };\n        if true { first + (if false { fault(kind) } else { 2 }) } else { fault(kind) }\n    } else {\n        let first = if true { 40 } else { fault(kind) };\n        if false { fault(kind) } else { first + (if true { 2 } else { fault(kind) }) }\n    }",
    );

    let multi_argument = module(
        "entry",
        "@id(\"test.pick\")\nfn pick(flag: bool, when_true: i64, when_false: i64) -> i64\n{\n    if flag { when_true } else { when_false }\n}\n\n@id(\"test.combine\")\nfn combine(left: i64, middle: i64, right: i64) -> i64\n{\n    left + middle - right\n}\n\n",
        "flag: bool, value: i64",
        "i64",
        "combine(pick(flag, value, 10), pick(!flag, 20, value), pick(flag, 3, 4))",
    );

    vec![
        GeneratedProgram {
            source: safe_arithmetic,
            entry_id: "app.entry".to_owned(),
            entry_params: vec![GenType::I64],
            samples: (0..15).map(|case| vec![Value::Int(case)]).collect(),
        },
        GeneratedProgram {
            source: module(
                "entry",
                &deep_call_helpers,
                "value: i64",
                "i64",
                &format!("call_{CALL_DEPTH}(value)"),
            ),
            entry_id: "app.entry".to_owned(),
            entry_params: vec![GenType::I64],
            samples: vec![
                vec![Value::Int(-1)],
                vec![Value::Int(0)],
                vec![Value::Int(1)],
            ],
        },
        GeneratedProgram {
            source: module("entry", "", "", "i64", &deep_let_body),
            entry_id: "app.entry".to_owned(),
            entry_params: vec![],
            samples: vec![vec![]],
        },
        GeneratedProgram {
            source: lazy_control,
            entry_id: "app.entry".to_owned(),
            entry_params: vec![GenType::Bool, GenType::I64],
            samples: [true, false]
                .into_iter()
                .flat_map(|pick| (0..3).map(move |kind| vec![Value::Bool(pick), Value::Int(kind)]))
                .collect(),
        },
        GeneratedProgram {
            source: multi_argument,
            entry_id: "app.entry".to_owned(),
            entry_params: vec![GenType::Bool, GenType::I64],
            samples: vec![
                vec![Value::Bool(true), Value::Int(-10)],
                vec![Value::Bool(false), Value::Int(-10)],
                vec![Value::Bool(true), Value::Int(42)],
                vec![Value::Bool(false), Value::Int(42)],
            ],
        },
    ]
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

    #[test]
    fn adversarial_fault_corpus_is_deterministic_and_covers_every_ordered_pair() {
        let first = adversarial_fault_corpus();
        let second = adversarial_fault_corpus();
        assert_eq!(first.len(), 9);
        assert_eq!(
            first
                .iter()
                .map(|program| program.source.as_str())
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|program| program.source.as_str())
                .collect::<Vec<_>>(),
            "adversarial source must be byte-identical across runs"
        );
        assert_eq!(
            first
                .iter()
                .map(|program| program.samples.len())
                .sum::<usize>(),
            544,
            "six strict 8-by-8 contexts, two lazy-right contexts, and faulting plus successful conditional branches"
        );
        for program in &first {
            assert!(program.source.len() < 8192);
            assert!(!program.samples.is_empty());
            crate::parse(&program.source, "kernel-zero-adversarial-corpus.spx").unwrap_or_else(
                |error| {
                    panic!(
                        "adversarial corpus source must parse: {error:?}\nsource:\n{}",
                        program.source
                    )
                },
            );
        }
    }

    #[test]
    fn adversarial_structure_corpus_reifies_and_replays_weight_certificates() {
        use super::super::reify::BoundTranslation;
        use super::super::weights;

        let first = adversarial_structure_corpus();
        let second = adversarial_structure_corpus();
        assert_eq!(first.len(), 5);
        assert_eq!(
            first
                .iter()
                .map(|program| program.source.as_str())
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|program| program.source.as_str())
                .collect::<Vec<_>>(),
            "adversarial structural source must be byte-identical across runs"
        );
        assert_eq!(
            first.iter().map(|program| program.samples.len()).sum::<usize>(),
            29,
            "boundary arithmetic, deep call/let, lazy control, and multi-argument cases must retain their sample matrix"
        );
        for program in &first {
            assert!(program.source.len() < 8192);
            let parsed = crate::parse(&program.source, "kernel-zero-structure-corpus.spx")
                .unwrap_or_else(|error| panic!("structural corpus source must parse: {error:?}"));
            let resolved = crate::hir::resolve(&parsed).unwrap_or_else(|errors| {
                panic!("structural corpus source must resolve: {errors:?}")
            });
            let entry = crate::hir::DeclarationId::new(program.entry_id.clone());
            assert!(
                super::super::reifies_into_kernel_zero(&resolved, &entry),
                "structural corpus entry must remain inside Kernel-0"
            );
            let binding = BoundTranslation::derive(&program.source, &entry)
                .expect("structural corpus must admit a bounded translation");
            let kernel = binding
                .replay(&program.source, &entry)
                .expect("structural corpus translation must replay exact source");
            let certificate = weights::derive(&kernel)
                .expect("structural corpus must fit the weighted-call certificate profile");
            assert_eq!(weights::verify(&kernel, &certificate), Ok(()));
            assert!(
                weights::value_call_fuel(&kernel, &certificate, &entry).is_ok(),
                "every structural entry must have a checked numeric call-fuel witness"
            );
        }
    }
}
