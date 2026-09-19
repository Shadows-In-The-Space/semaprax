//! Issue #191: hostile compile-time proof that `std.auth.identity.Identity`
//! and `std.auth.authorization.Authorization` (declared in
//! `std/auth/src/auth.spx`) are distinct nominal types the compiler enforces,
//! not merely a convention two `bool`-returning functions happen to follow.
//! These are checked directly against `crate::check`, the same
//! parse/resolve/type-check/verify pipeline `semaprax check` drives, on small
//! self-contained fixtures that mirror `auth.spx`'s own declarations — not
//! against the real package, since a hostile case that must fail to compile
//! cannot live inside a package whose own test suite must build cleanly (see
//! `auth.spx`'s `Identity`/`Authorization` doc comment, point 5, and
//! `secret_source_tests.rs`'s identical rationale for `Secret<T>`).
//!
//! The property that matters most is proven here, not merely documented:
//! issue #191's acceptance mapping asks for "authentication and
//! authorization" as "separate typed concepts", graded "not met as a
//! distinct nominal type the compiler enforces one cannot smuggle past" —
//! i.e. a value proving *who you are* must not be usable where a value
//! proving *what you may do* is required, and vice versa. Every hostile case
//! below is paired with a positive control proving the same fixture compiles
//! when the argument's declared type actually matches the parameter, so a
//! regression that collapsed the two types back into interchangeable shapes
//! (or back into a bare `bool`) would flip the negative case from `Err` to
//! `Ok`, not merely fail to reject.

fn identity_authorization_fixture() -> &'static str {
    r#"module test.identity_authorization_source;

@id("test.identity")
record Identity {
    @id("test.identity.subject_id")
    subject_id: usize,
}

@id("test.authorization")
record Authorization {
    @id("test.authorization.permitted")
    permitted: bool,
}

@id("test.requires_identity")
fn requires_identity(who: Identity) -> usize
{
    who.subject_id
}

@id("test.requires_authorization")
fn requires_authorization(decision: Authorization) -> bool
{
    decision.permitted
}

"#
}

fn fixture_with_main(body: &str) -> String {
    format!(
        "{}@id(\"app.main\")\nfn main() -> i64\n{{\n{body}\n}}\n",
        identity_authorization_fixture()
    )
}

fn has_code(diagnostics: &[crate::diagnostic::Diagnostic], code: &str) -> bool {
    diagnostics.iter().any(|diagnostic| diagnostic.code == code)
}

/// Non-vacuity control: an `Identity` value really is accepted where an
/// `Identity` is required, so the negative case below is a real refusal of a
/// specific *wrong* type, not an unrelated failure that would reject any
/// argument at all.
#[test]
fn requires_identity_accepts_an_identity_value() {
    let source = fixture_with_main(
        r#"    let who = Identity { subject_id: 1usize };
    if requires_identity(who) == 1usize { 0 } else { 1 }"#,
    );
    assert!(
        crate::check(&source, "identity-accepts-identity.spx").is_ok(),
        "an Identity value must be accepted where Identity is required"
    );
}

/// The property that matters most, direction one: an `Authorization` value —
/// proof of *what you may do* — must not be usable where an `Identity` —
/// proof of *who you are* — is required. If this ever started compiling, the
/// nominal distinction would have collapsed back to interchangeable shapes.
#[test]
fn authorization_cannot_be_used_where_identity_is_required() {
    let source = fixture_with_main(
        r#"    let decision = Authorization { permitted: true };
    if requires_identity(decision) == 1usize { 0 } else { 1 }"#,
    );
    let diagnostics = crate::check(&source, "authorization-as-identity.spx")
        .err()
        .expect("passing an Authorization value where Identity is required must fail to compile");
    assert!(
        has_code(&diagnostics, "SPX-T205"),
        "expected SPX-T205 (argument type mismatch), got {diagnostics:?}"
    );
}

/// Non-vacuity control for the other direction.
#[test]
fn requires_authorization_accepts_an_authorization_value() {
    let source = fixture_with_main(
        r#"    let decision = Authorization { permitted: true };
    if requires_authorization(decision) { 0 } else { 1 }"#,
    );
    assert!(
        crate::check(&source, "authorization-accepts-authorization.spx").is_ok(),
        "an Authorization value must be accepted where Authorization is required"
    );
}

/// The property that matters most, direction two: an `Identity` value must
/// not be usable where an `Authorization` value is required — the exact
/// mirror image of the case above, since a one-directional check alone would
/// leave the types distinguishable in name only from one side.
#[test]
fn identity_cannot_be_used_where_authorization_is_required() {
    let source = fixture_with_main(
        r#"    let who = Identity { subject_id: 1usize };
    if requires_authorization(who) { 0 } else { 1 }"#,
    );
    let diagnostics = crate::check(&source, "identity-as-authorization.spx")
        .err()
        .expect("passing an Identity value where Authorization is required must fail to compile");
    assert!(
        has_code(&diagnostics, "SPX-T205"),
        "expected SPX-T205 (argument type mismatch), got {diagnostics:?}"
    );
}

/// `Identity`/`Authorization` inherit the same whole-value-equality refusal
/// `Secret<T>` proves in `secret_source_tests.rs` — a general `Type::Named`
/// invariant (`SPX-T207`), not a mechanism either type declares for itself.
/// Paired with the field-comparison positive control, exactly like the
/// `Secret<T>` proof, so a regression that started admitting aggregate
/// equality again would flip this from `Err` to `Ok`, not merely stop being
/// asserted.
#[test]
fn identity_field_comparison_compiles_but_whole_value_equality_is_rejected() {
    let field_source = fixture_with_main(
        r#"    let a = Identity { subject_id: 1usize };
    let b = Identity { subject_id: 1usize };
    if a.subject_id == b.subject_id { 0 } else { 1 }"#,
    );
    assert!(
        crate::check(&field_source, "identity-field-comparison.spx").is_ok(),
        "unwrapped scalar-field comparison must compile"
    );

    let whole_value_source = fixture_with_main(
        r#"    let a = Identity { subject_id: 1usize };
    let b = Identity { subject_id: 1usize };
    if a == b { 0 } else { 1 }"#,
    );
    let diagnostics = crate::check(&whole_value_source, "identity-whole-value-eq.spx")
        .err()
        .expect("comparing two Identity values with `==` must fail to compile");
    assert!(
        has_code(&diagnostics, "SPX-T207"),
        "expected SPX-T207 (aggregate equality outside the executable comparison \
         profile), got {diagnostics:?}"
    );
}

/// The interpreter-backend ceiling `auth.spx`'s `Identity`/`Authorization`
/// doc comment (point 4) reports: calling a function whose parameter or
/// return type mentions a plain (non-generic) user record fails with
/// `SPX-F102`, even though `semaprax check`'s static phase admits the
/// declaration and the call — the same ceiling `Secret<T>` hits, now shown
/// to be about the *shape* (no `Bytes` field anywhere in it), not about
/// being generic. `semaprax check` above already proved the call is
/// statically well-typed; this proves the interpreter specifically, and
/// separately, refuses to execute it.
#[test]
fn calling_a_function_typed_over_identity_is_rejected_by_the_interpreter() {
    let module = fixture_with_main(
        r#"    let who = Identity { subject_id: 1usize };
    if requires_identity(who) == 1usize { 0 } else { 1 }"#,
    );
    let program = crate::hir::resolve(
        &crate::parse(
            &module,
            std::path::Path::new("identity-interpreter-ceiling.spx"),
        )
        .expect("the fixture parses"),
    )
    .expect("the fixture resolves");
    let prepared = crate::interpreter::retained_call::prepare_retained_call(&program, "app.main")
        .expect("the entry point prepares");
    let outcome =
        crate::interpreter::retained_call::evaluate_retained_call(&program, &prepared, &[], 10_000);
    let diagnostics = outcome.err().expect(
        "calling a function typed over Identity must currently fail on the interpreter \
         (SPX-F102) — if this starts succeeding, auth.spx's doc comment (point 4) is \
         stale and the discovered ceiling has been lifted",
    );
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "SPX-F102"),
        "expected SPX-F102 (interpreter admission failed), got {diagnostics:?}"
    );
}
