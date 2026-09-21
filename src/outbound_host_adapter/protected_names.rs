//! Closed protected-name policy shared by typed operational exports.

const PROTECTED: [&str; 12] = [
    "password",
    "api_key",
    "bearer_token",
    "session_token",
    "webhook_signing_secret",
    "smtp_credential",
    "authorization",
    "cookie",
    "set_cookie",
    "proxy_authorization",
    "access_token",
    "refresh_token",
];

pub(super) fn is_protected(value: &str) -> bool {
    PROTECTED.iter().any(|expected| {
        value.len() == expected.len()
            && value.bytes().zip(expected.bytes()).all(|(actual, wanted)| {
                let normalized = match actual {
                    b'A'..=b'Z' => actual + (b'a' - b'A'),
                    b'-' => b'_',
                    _ => actual,
                };
                normalized == wanted
            })
    })
}
