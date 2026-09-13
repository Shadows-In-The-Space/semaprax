//! Private, explicitly selected durable source Agent CLI.
//!
//! The compiler owns the checked driver and source journal. This module only
//! supplies host-selected files, an exclusive latest-store lease, a stable
//! clock, and the one fixed free OpenCode provider.

mod checkpoint;
mod options;
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

/// Executes `run`, `resume`, or one V2-to-V3 `migrate` handoff. No verb
/// publishes source, launches a shell, or chooses a paid model.
pub fn run(arguments: &[String]) -> Result<String, (String, u8)> {
    let result = options::Command::parse(arguments).and_then(run::execute);
    result.map_err(|error| (error.reason, error.code))
}
