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
