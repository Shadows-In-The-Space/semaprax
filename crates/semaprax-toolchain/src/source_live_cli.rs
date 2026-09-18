//! Private, explicitly selected durable source Agent CLI.
//!
//! The compiler owns the checked driver and source journal. This module only
//! supplies host-selected files, an exclusive latest-store lease, a stable
//! clock, and the one fixed free OpenCode provider.

mod checkpoint;
mod offline_repair_cli;
mod options;
mod repair;
mod run;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliError {
    reason: String,
    code: u8,
}

impl CliError {
    fn usage(reason: &'static str) -> Self {
        Self {
            reason: reason.into(),
            code: 2,
        }
    }

    fn refused(reason: &'static str) -> Self {
        Self {
            reason: reason.into(),
            code: 1,
        }
    }

    fn detail(reason: String) -> Self {
        Self { reason, code: 1 }
    }
}

/// Executes durable source-live verbs or the fixed offline repair demonstration.
/// Neither route publishes source or selects a paid provider.
pub fn run(arguments: &[String]) -> Result<String, (String, u8)> {
    let result = match arguments.split_first() {
        Some((verb, rest)) if verb == "offline-repair" => offline_repair_cli::run(rest),
        Some((verb, rest)) if verb == "repair" => repair::run(rest),
        _ => options::Command::parse(arguments).and_then(run::execute),
    };
    result.map_err(|error| (error.reason, error.code))
}
