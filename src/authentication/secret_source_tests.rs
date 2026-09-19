//! Issue #191: hostile compile-time proof for `std.auth.secret.Secret<T>`
//! (declared in `std/auth/src/auth.spx`), the `.spx`-visible opaque scalar
//! handle type. These are checked directly against `crate::check`, the same
//! parse/resolve/type-check/verify pipeline `semaprax check` drives, on
//! small self-contained fixtures that mirror `auth.spx`'s own `Secret<T>`
//! declaration — not against the real package, since a hostile case that
//! must fail to compile cannot live inside a package whose own test suite
//! must build cleanly (see `auth.spx`'s `Secret<T>` doc comment, point 1).
//!
//! The one property that matters most is proven here, not merely
//! documented: comparing two `Secret<T>` values with `==`/`!=` — the
//! "comparable in a way that leaks" failure mode issue #191 names
//! explicitly — is refused by the compiler before it ever reaches a
//! backend. Every hostile case below is paired with a positive control
//! proving the same fixture compiles once the leaking comparison is
//! replaced with the sanctioned unwrapped-scalar comparison, so a
//! regression that started accepting aggregate equality again would flip
//! the negative case from `Err` to `Ok`, not merely fail to reject.

fn secret_i64_fixture(body: &str) -> String {
    format!(
        r#"module test.secret_source;

@id("test.secret")
record Secret<T> {{
    @id("test.secret.value")
    value: T,
}}

@id("test.secret.compare")
fn secret_compare(left: Secret<i64>, right: Secret<i64>) -> bool
{{
    {body}
}}

@id("app.main")
fn main() -> i64
{{
    0
}}
"#
    )
}

fn secret_bool_fixture(body: &str) -> String {
    format!(
        r#"module test.secret_source;

@id("test.secret")
record Secret<T> {{
    @id("test.secret.value")
    value: T,
}}

@id("test.secret.compare")
fn secret_compare(left: Secret<bool>, right: Secret<bool>) -> bool
{{
    {body}
}}

@id("app.main")
fn main() -> i64
{{
    0
}}
"#
    )
}

/// A module that takes its `Secret<i64>` as a parameter, so no scalar the
/// secret could carry is ever written in source. The companion below writes a
/// literal instead, which is the control: it proves the graph really does
/// carry scalars, so the absence in the subject means something.
fn secret_parameter_module() -> String {
    r#"module test.secret_graph;

@id("test.secret")
record Secret<T> {
    @id("test.secret.value")
    value: T,
}

@id("test.secret.is_positive")
fn is_positive(held: Secret<i64>) -> bool
{
    held.value > 0
}

@id("app.main")
fn main() -> i64
{
    0
}
"#
    .to_owned()
}

fn literal_scalar_module() -> String {
    r#"module test.secret_graph;

@id("test.secret")
record Secret<T> {
    @id("test.secret.value")
    value: T,
}

@id("test.secret.is_positive")
fn is_positive(held: Secret<i64>) -> bool
{
    held.value > 987654321
}

@id("app.main")
fn main() -> i64
{
    0
}
"#
    .to_owned()
}

fn has_code(diagnostics: &[crate::diagnostic::Diagnostic], code: &str) -> bool {
    diagnostics.iter().any(|diagnostic| diagnostic.code == code)
}

/// Non-vacuity control: the leaking form really does reach the compiler and
/// really is what gets refused, not an unrelated parse failure upstream of
/// it. Every hostile test below pairs with this same shape.
#[test]
fn secret_i64_field_comparison_compiles() {
    let source = secret_i64_fixture("left.value == right.value");
    assert!(
        crate::check(&source, "secret-i64-field-comparison.spx").is_ok(),
        "unwrapped scalar-field comparison must compile"
    );
}

#[test]
fn secret_i64_whole_value_equality_is_rejected() {
    let source = secret_i64_fixture("left == right");
    let diagnostics = crate::check(&source, "secret-i64-eq.spx")
        .err()
        .expect("comparing two Secret<i64> values with `==` must fail to compile");
    assert!(
        has_code(&diagnostics, "SPX-T207"),
        "expected SPX-T207 (aggregate equality outside the executable comparison \
         profile), got {diagnostics:?}"
    );
}

#[test]
fn secret_i64_whole_value_inequality_is_rejected() {
    let source = secret_i64_fixture("left != right");
    let diagnostics = crate::check(&source, "secret-i64-ne.spx")
        .err()
        .expect("comparing two Secret<i64> values with `!=` must fail to compile");
    assert!(
        has_code(&diagnostics, "SPX-T207"),
        "expected SPX-T207 for `!=` exactly as for `==`, got {diagnostics:?}"
    );
}

/// `Secret<bool>` gets the same paired proof as `Secret<i64>`: the refusal
/// is a property of comparing any nominal aggregate, not specific to one
/// admitted type argument.
#[test]
fn secret_bool_field_comparison_compiles() {
    let source = secret_bool_fixture("left.value == right.value");
    assert!(
        crate::check(&source, "secret-bool-field-comparison.spx").is_ok(),
        "unwrapped scalar-field comparison must compile"
    );
}

#[test]
fn secret_bool_whole_value_equality_is_rejected() {
    let source = secret_bool_fixture("left == right");
    let diagnostics = crate::check(&source, "secret-bool-eq.spx")
        .err()
        .expect("comparing two Secret<bool> values with `==` must fail to compile");
    assert!(
        has_code(&diagnostics, "SPX-T207"),
        "expected SPX-T207, got {diagnostics:?}"
    );
}

/// `Secret<T>` cannot be widened past its two admitted scalar arguments: an
/// attempt to instantiate it over `usize` — the type this package's own
/// session/state code uses everywhere else — is refused by the compiler's
/// own generic copy-type admission, not by anything this package adds.
/// This is the capacity ceiling `auth.spx`'s `Secret<T>` doc comment (point 3)
/// reports rather than works around. (`Secret<Bytes>` was checked too and
/// is, perhaps surprisingly, statically admitted with an `own Bytes`
/// parameter — see that doc comment's note — but is unexplored beyond the
/// static check: this package does not build a byte-carrying `Secret<T>`
/// on that basis alone, since interpreter execution of it is unverified.)
#[test]
fn secret_over_usize_is_rejected_by_generic_copy_type_admission() {
    let source = r#"module test.secret_source_usize;

@id("test.secret")
record Secret<T> {
    @id("test.secret.value")
    value: T,
}

@id("test.secret.wrap_usize")
fn secret_wrap_usize(value: usize) -> Secret<usize>
{
    Secret<usize> { value: value }
}

@id("app.main")
fn main() -> i64
{
    0
}
"#;
    let diagnostics = crate::check(source, "secret-over-usize.spx")
        .err()
        .expect("`Secret<usize>` must fail to compile");
    assert!(
        has_code(&diagnostics, "SPX-T223"),
        "expected SPX-T223 (generic copy type accepts only direct i64/bool \
         arguments), got {diagnostics:?}"
    );
}

// The language has no format/print/interpolation facility for any value at
// all (`auth.spx`'s `Secret<T>` doc comment, point 2): `src/lexer.rs` recognizes ordinary string
// literals and their escapes and nothing else — no interpolation token, no
// template syntax, no `Display`/`Debug`-equivalent derive. That is a fact
// about the whole language, audited directly against the lexer rather than
// asserted, so there is no `.spx` construct a hostile fixture could even
// spell here to attempt leaking a `Secret<T>` into text; the absence is
// exercised by grep against `src/lexer.rs`, not restated as a vacuous test
// against a syntax that does not exist.

/// Issue #191's third non-leak property — "not serialisable into graph JSON" —
/// stated as what it actually is, because the audit recorded it as untested
/// and the reason it was untested matters more than a test would.
///
/// It is **structurally guaranteed, not test-guaranteed**. `graph::to_json`
/// takes `&Program` and nothing else: a parsed source tree, with no runtime,
/// no interpreter state and no evaluated value anywhere in its input. There is
/// no channel through which a held secret could reach it. A test asserting
/// "the graph contains no secret value" over a module that never wrote one
/// would be asserting the absence of something that was never present — which
/// is why the first version of this test was deleted rather than shipped.
///
/// What IS worth pinning is the boundary a reader will otherwise get wrong:
/// the graph **does** carry source literals, including one written into a
/// `Secret` construction. That is correct and unavoidable — the graph is a
/// projection of source, and a literal in source is source. The property is
/// therefore "no *runtime* value is serialisable", never "no scalar appears".
/// Anyone who writes a real secret as a literal in checked source has
/// published it in the source, and no projection can undo that.
#[test]
fn the_graph_projects_a_secret_construction_literal_because_a_source_literal_is_source() {
    let module = r#"module test.secret_graph;

@id("test.secret")
record Secret<T> {
    @id("test.secret.value")
    value: T,
}

@id("test.secret.hold")
fn hold() -> bool
{
    let held = Secret<i64> { value: 987654321 };
    held.value > 0
}

@id("app.main")
fn main() -> i64
{
    0
}
"#;
    let program =
        crate::parse(module, std::path::Path::new("secret-graph.spx")).expect("the fixture parses");
    let json = crate::graph::to_json(&program).expect("the fixture projects");

    for identity in ["test.secret", "test.secret.value", "test.secret.hold"] {
        assert!(
            json.contains(identity),
            "the graph must carry `{identity}`; it is not projecting this module"
        );
    }
    assert!(
        json.contains("987654321"),
        "the graph carries source literals, including inside a Secret construction. \
         If this ever stops being true the doc comment above is wrong and the \
         property needs restating, not the test relaxing."
    );
}

/// Issue #191's fourth non-leak property — "not serialisable into a
/// trace/audit record" — for the half of it that is a real channel rather
/// than an argument.
///
/// A runtime fault is the one place a held scalar could plausibly escape: a
/// diagnostic that quoted the operand it faulted on would publish the secret
/// into every log, journal and evidence capsule downstream, and nothing about
/// the type system would stop it. That is a genuine leak surface, unlike the
/// graph projection above, so it is worth executing rather than arguing.
///
/// This holds a distinctive value in a `Secret<i64>`, divides by a zero taken
/// from a second secret so the fault is unavoidable and not constant-folded,
/// and asserts the value appears nowhere in the failure — not in any
/// diagnostic message, help text, or code.
#[test]
fn a_runtime_fault_on_a_held_secret_never_quotes_the_held_value() {
    const HELD: &str = "987654321";
    let module = format!(
        r#"module test.secret_trace;

@id("test.secret")
record Secret<T> {{
    @id("test.secret.value")
    value: T,
}}

@id("test.secret.fault")
fn fault() -> i64
{{
    let held = Secret<i64> {{ value: {HELD} }};
    let divisor = Secret<i64> {{ value: 0 }};
    held.value / divisor.value
}}

@id("app.main")
fn main() -> i64
{{
    0
}}
"#
    );
    let program = crate::hir::resolve(
        &crate::parse(&module, std::path::Path::new("secret-trace.spx"))
            .expect("the fault fixture parses"),
    )
    .expect("the fault fixture resolves");
    let prepared =
        crate::interpreter::retained_call::prepare_retained_call(&program, "test.secret.fault")
            .expect("the faulting entry prepares");

    let outcome =
        crate::interpreter::retained_call::evaluate_retained_call(&program, &prepared, &[], 10_000);

    // Whether the division surfaces as an Err or as a failing outcome, the
    // held value must not be anywhere in what the caller can observe.
    let observed = match outcome {
        Ok(evaluation) => format!("{evaluation:?}"),
        Err(diagnostics) => diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "{} {} {}",
                    diagnostic.code,
                    diagnostic.message,
                    diagnostic.help.clone().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join(" | "),
    };
    // Non-vacuity, and the thing my first attempt at a Secret leak test
    // lacked: assert the fault ACTUALLY happened. Without this the whole test
    // passes the moment the division stops faulting for any reason, while
    // appearing to prove something about leaks.
    assert!(
        observed.contains("semaprax.arithmetic.v1"),
        "the fixture must really fault on division by zero, or the leak \
         assertion below proves nothing: {observed}"
    );
    assert!(
        !observed.contains(HELD),
        "a runtime fault published the held secret value: {observed}"
    );
}
