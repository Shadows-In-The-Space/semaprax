use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::{checkpoint::bounded_read, CliError};

const MAX_CONFIG_BYTES: usize = 8192;
const MAX_TOKEN_BYTES: usize = 240;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SessionConfig {
    pub manifest: PathBuf,
    pub source_path: String,
    pub agent_id: String,
    pub step_id: String,
    pub task_path: PathBuf,
    pub task_budget: i64,
    pub read_path: PathBuf,
    pub deadline_millis: i64,
    pub ceiling: i64,
    pub reservation_units: i64,
    pub max_iterations: usize,
    pub max_stages: usize,
    pub max_steps_per_stage: usize,
    pub max_total_steps: usize,
    pub response_limit: usize,
}

impl SessionConfig {
    pub(super) fn load(path: &Path) -> Result<Self, CliError> {
        if !path.is_absolute() {
            return Err(CliError::usage("configuration path must be absolute"));
        }
        let bytes = bounded_read(path, MAX_CONFIG_BYTES)?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| CliError::refused("configuration JSON is malformed"))?;
        let canonical = serde_json::to_vec(&value)
            .map_err(|_| CliError::refused("configuration cannot be encoded"))?;
        if bytes.as_slice() != canonical.as_slice()
            && bytes.strip_suffix(b"\n") != Some(canonical.as_slice())
        {
            // Re-encoding collapses duplicate keys and alternate spellings.
            // Exact replay therefore rejects them before any host boundary.
            return Err(CliError::refused("configuration must be canonical JSON"));
        }
        let map = value
            .as_object()
            .ok_or(CliError::refused("configuration must be an object"))?;
        const KEYS: [&str; 16] = [
            "schema",
            "manifest",
            "source_path",
            "agent_id",
            "step_id",
            "task_path",
            "task_budget",
            "read_path",
            "deadline_millis",
            "ceiling",
            "reservation_units",
            "max_iterations",
            "max_stages",
            "max_steps_per_stage",
            "max_total_steps",
            "response_limit",
        ];
        if map.len() != KEYS.len() || !KEYS.iter().all(|key| map.contains_key(*key)) {
            return Err(CliError::refused(
                "configuration has missing or unknown keys",
            ));
        }
        if text(map, "schema")? != "semaprax.source-live-cli.config.v1" {
            return Err(CliError::refused("configuration schema is unsupported"));
        }
        let manifest = absolute(map, "manifest")?;
        let task_path = absolute(map, "task_path")?;
        let read_path = absolute(map, "read_path")?;
        let source_path = token(map, "source_path")?;
        if Path::new(&source_path).is_absolute()
            || Path::new(&source_path)
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || !source_path.ends_with(".spx")
        {
            return Err(CliError::refused(
                "source_path must be a relative Project .spx path",
            ));
        }
        let agent_id = token(map, "agent_id")?;
        let step_id = token(map, "step_id")?;
        let task_budget = nonnegative_i64(map, "task_budget")?;
        let deadline_millis = positive_i64(map, "deadline_millis")?;
        let ceiling = nonnegative_i64(map, "ceiling")?;
        let reservation_units = positive_i64(map, "reservation_units")?;
        let max_iterations = positive_usize(map, "max_iterations")?;
        let max_stages = positive_usize(map, "max_stages")?;
        let max_steps_per_stage = positive_usize(map, "max_steps_per_stage")?;
        let max_total_steps = positive_usize(map, "max_total_steps")?;
        let response_limit = positive_usize(map, "response_limit")?;
        if max_iterations > 4096
            || max_stages > 12_289
            || max_steps_per_stage > 1_000_000
            || max_total_steps > 1_000_000_000
            || response_limit > 65_536
        {
            return Err(CliError::refused(
                "configuration exceeds source journal limits",
            ));
        }
        Ok(Self {
            manifest,
            source_path,
            agent_id,
            step_id,
            task_path,
            task_budget,
            read_path,
            deadline_millis,
            ceiling,
            reservation_units,
            max_iterations,
            max_stages,
            max_steps_per_stage,
            max_total_steps,
            response_limit,
        })
    }
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, CliError> {
    map.get(key)
        .and_then(Value::as_str)
        .ok_or(CliError::refused("configuration field has the wrong type"))
}

fn token(map: &Map<String, Value>, key: &str) -> Result<String, CliError> {
    let value = text(map, key)?;
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(CliError::refused("configuration identifier is invalid"));
    }
    Ok(value.to_owned())
}

fn absolute(map: &Map<String, Value>, key: &str) -> Result<PathBuf, CliError> {
    let path = PathBuf::from(text(map, key)?);
    if !path.is_absolute() {
        return Err(CliError::refused("configuration path must be absolute"));
    }
    Ok(path)
}

fn positive_i64(map: &Map<String, Value>, key: &str) -> Result<i64, CliError> {
    let value = map
        .get(key)
        .and_then(Value::as_i64)
        .ok_or(CliError::refused("configuration integer is invalid"))?;
    (value > 0)
        .then_some(value)
        .ok_or(CliError::refused("configuration integer must be positive"))
}

fn nonnegative_i64(map: &Map<String, Value>, key: &str) -> Result<i64, CliError> {
    let value = map
        .get(key)
        .and_then(Value::as_i64)
        .ok_or(CliError::refused("configuration integer is invalid"))?;
    (value >= 0).then_some(value).ok_or(CliError::refused(
        "configuration integer must be nonnegative",
    ))
}

fn positive_usize(map: &Map<String, Value>, key: &str) -> Result<usize, CliError> {
    let value = map
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
        .ok_or(CliError::refused("configuration capacity is invalid"))?;
    (value > 0)
        .then_some(value)
        .ok_or(CliError::refused("configuration capacity must be positive"))
}

pub(super) enum Command {
    Run {
        config: PathBuf,
        checkpoint: PathBuf,
        executable: PathBuf,
        scratch: PathBuf,
    },
    Resume {
        config: PathBuf,
        checkpoint: PathBuf,
        executable: PathBuf,
        scratch: PathBuf,
    },
    Migrate {
        previous_config: PathBuf,
        previous_checkpoint: PathBuf,
        destination_config: PathBuf,
        destination_checkpoint: PathBuf,
        function: String,
        steps: usize,
        executable: PathBuf,
        scratch: PathBuf,
    },
}

impl Command {
    pub(super) fn parse(arguments: &[String]) -> Result<Self, CliError> {
        let Some((verb, rest)) = arguments.split_first() else {
            return Err(CliError::usage("expected run, resume, or migrate"));
        };
        let (positionals, flags) = match verb.as_str() {
            "run" | "resume" if rest.len() == 6 => (&rest[..2], &rest[2..]),
            "migrate" if rest.len() == 10 => (&rest[..6], &rest[6..]),
            _ => return Err(CliError::usage("source-live operand count is invalid")),
        };
        if flags[0] != "--opencode" || flags[2] != "--scratch" {
            return Err(CliError::usage(
                "expected --opencode ABS --scratch EMPTY_ABS",
            ));
        }
        let executable = absolute_operand(&flags[1])?;
        let scratch = absolute_operand(&flags[3])?;
        match verb.as_str() {
            "run" => Ok(Self::Run {
                config: absolute_operand(&positionals[0])?,
                checkpoint: absolute_operand(&positionals[1])?,
                executable,
                scratch,
            }),
            "resume" => Ok(Self::Resume {
                config: absolute_operand(&positionals[0])?,
                checkpoint: absolute_operand(&positionals[1])?,
                executable,
                scratch,
            }),
            "migrate" => {
                let steps = positionals[5]
                    .parse::<usize>()
                    .ok()
                    .filter(|steps| *steps > 0 && *steps <= 1_000_000)
                    .ok_or(CliError::usage("migration steps must be in 1..=1000000"))?;
                let function = positionals[4].clone();
                if function.is_empty()
                    || function.len() > MAX_TOKEN_BYTES
                    || function.bytes().any(|byte| byte.is_ascii_control())
                {
                    return Err(CliError::usage("migration function identity is invalid"));
                }
                Ok(Self::Migrate {
                    previous_config: absolute_operand(&positionals[0])?,
                    previous_checkpoint: absolute_operand(&positionals[1])?,
                    destination_config: absolute_operand(&positionals[2])?,
                    destination_checkpoint: absolute_operand(&positionals[3])?,
                    function,
                    steps,
                    executable,
                    scratch,
                })
            }
            _ => unreachable!(),
        }
    }
}

fn absolute_operand(value: &str) -> Result<PathBuf, CliError> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(CliError::usage(
            "source-live operands must be absolute paths",
        ));
    }
    Ok(path)
}
