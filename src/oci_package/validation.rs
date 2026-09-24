//! Closed admission rules for OCI deployable-artifact identity and for the
//! ambient environment this crate is allowed to run in.
//!
//! Every check here refuses a hostile shape outright; none of them attempt to
//! sanitize, truncate, or otherwise repair an input into an accepted one.

use super::OciError;

/// Project identity component: the same closed charset the npm packaging
/// module uses for a package name (ASCII lowercase, digits, `-` not leading),
/// bounded to 64 bytes. This shape cannot contain `/`, `\`, `..`, a NUL byte,
/// or a control character, so it can never be mistaken for a path.
pub(crate) fn valid_identity_component(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// A dotted stable-identity component (an entry-module name). Slightly wider
/// than [`valid_identity_component`] to admit `module.name` shapes, but still
/// closed: no separators, no NUL byte, no control character, and no `..`
/// traversal-shaped substring even though this value is never used to form a
/// filesystem path in this crate.
pub(crate) fn valid_stable_component(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && !value.contains("..")
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

/// A `sha256:` digest fact: exactly the `"sha256:" + 64 lowercase hex`
/// shape produced everywhere else in this repository.
pub(crate) fn valid_digest_fact(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Container-registry-credential-shaped environment variable names. None of
/// these are ever read for a legitimate purpose by this crate -- it has no
/// registry client and no publish path -- so their mere presence in the
/// process environment is refused before any file is touched. This mirrors
/// `scripts/generated-package-release.py`'s `assert_no_credential_env`.
pub(crate) const FORBIDDEN_CREDENTIAL_ENV_VARS: &[&str] = &[
    "DOCKER_PASSWORD",
    "DOCKER_AUTH_CONFIG",
    "REGISTRY_PASSWORD",
    "REGISTRY_TOKEN",
    "REGISTRY_AUTH_TOKEN",
    "OCI_REGISTRY_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "ACR_PASSWORD",
    "ECR_PASSWORD",
    "QUAY_PASSWORD",
    "AWS_SECRET_ACCESS_KEY",
];

/// Refuse to run at all if a live registry-publish-credential-shaped
/// environment variable is set. This tool has no registry client and no
/// legitimate use for one; a credential in its environment can only be an
/// ambient-authority leak from the invoking process, so its presence alone
/// is refused before any file is created or read.
pub(crate) fn refuse_if_credential_environment_present() -> Result<(), OciError> {
    let present: Vec<&str> = FORBIDDEN_CREDENTIAL_ENV_VARS
        .iter()
        .copied()
        .filter(|name| std::env::var_os(name).is_some())
        .collect();
    if present.is_empty() {
        Ok(())
    } else {
        Err(OciError::credential_environment(present.join(", ")))
    }
}

/// Refuse an [`std::path::Path`] carrying an embedded NUL byte in any
/// component. `Path`/`OsStr` can represent one on Unix even though no real
/// filesystem accepts it; refusing it here keeps the failure a clean
/// diagnostic instead of an opaque OS error deeper in the publish path.
pub(crate) fn path_is_free_of_nul_bytes(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        !path.as_os_str().as_bytes().contains(&0)
    }
    #[cfg(not(unix))]
    {
        !path.to_string_lossy().contains('\0')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_component_rejects_hostile_shapes() {
        assert!(valid_identity_component("my-project"));
        assert!(!valid_identity_component(""));
        assert!(!valid_identity_component("../etc"));
        assert!(!valid_identity_component("a/b"));
        assert!(!valid_identity_component("a\\b"));
        assert!(!valid_identity_component("a\0b"));
        assert!(!valid_identity_component("-leading"));
        assert!(!valid_identity_component("Upper"));
        assert!(!valid_identity_component(&"a".repeat(65)));
    }

    #[test]
    fn stable_component_rejects_traversal_and_separators() {
        assert!(valid_stable_component("my_project.app"));
        assert!(!valid_stable_component(".."));
        assert!(!valid_stable_component("a/../b"));
        assert!(!valid_stable_component("a/b"));
        assert!(!valid_stable_component(".leading"));
        assert!(!valid_stable_component("trailing."));
        assert!(!valid_stable_component(&"a".repeat(129)));
    }

    #[test]
    fn digest_fact_shape_is_exact() {
        let hex = "0".repeat(64);
        assert!(valid_digest_fact(&format!("sha256:{hex}")));
        assert!(!valid_digest_fact(&hex));
        assert!(!valid_digest_fact("sha256:short"));
        assert!(!valid_digest_fact(&format!("sha256:{}", "F".repeat(64))));
    }
}
