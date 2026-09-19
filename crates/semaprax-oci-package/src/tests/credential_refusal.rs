//! Refusal without authority: this crate has no registry client and no
//! `--publish` path anywhere in its source (`grep -rn "registry\|push\|http"
//! src/` under this crate turns up nothing but this comment), but as a
//! defense-in-depth belt-and-suspenders measure it also refuses to run at
//! all near a live registry credential. Each test here would catch either
//! failure mode: a refusal that never fires (removed check) or one that
//! fires unconditionally (broken check that also blocks legitimate runs).

use super::{fixture_plan, fresh_output_dir, TEST_LOCK};
use crate::build_and_publish;

#[test]
fn each_credential_shaped_variable_blocks_the_whole_build() {
    let _guard = TEST_LOCK.lock().unwrap();
    for name in crate::validation::FORBIDDEN_CREDENTIAL_ENV_VARS {
        // Belt-and-suspenders precondition: nothing else in this process
        // should have left one of these set.
        assert!(
            std::env::var_os(name).is_none(),
            "test environment must not carry {name} before this check"
        );
        std::env::set_var(name, "shhh-do-not-use-me");

        let out = fresh_output_dir(&format!("credential-{name}"));
        let result = build_and_publish(fixture_plan(), &out);

        std::env::remove_var(name);

        let error = result.expect_err(&format!("{name} present must refuse the build"));
        assert_eq!(error.kind(), crate::OciErrorKind::Identity);
        assert!(
            !out.exists(),
            "{name}: refusal must happen before any file is created"
        );
    }
}

/// With none of those variables set, the exact same plan succeeds. This is
/// the negative control for the negative control: it would catch a check
/// that refuses unconditionally regardless of the environment.
#[test]
fn absent_credentials_allow_the_build_to_proceed() {
    let _guard = TEST_LOCK.lock().unwrap();
    for name in crate::validation::FORBIDDEN_CREDENTIAL_ENV_VARS {
        assert!(std::env::var_os(name).is_none());
    }
    let out = fresh_output_dir("credential-absent");
    let bundle = build_and_publish(fixture_plan(), &out).expect("no credential present");
    assert!(out.join("index.json").is_file());
    assert!(!bundle.manifest_digest().is_empty());
    std::fs::remove_dir_all(&out).ok();
}
