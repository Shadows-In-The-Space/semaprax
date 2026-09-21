//! Independent replay for the generated service host-configuration fixture.
//!
//! The JSON Schema is guidance for external tooling. This decoder owns the
//! compiler-side closed shape, cross-field rules, finite bounds, and canonical
//! bytes. Decoding grants no database, network, telemetry, or secret authority.

use serde_json::{Map, Value};

pub(super) const MAX_SERVICE_CONFIG_BYTES: usize = 16 * 1024;
const SCHEMA: &str = "semaprax.service-config.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Fixture,
    Host,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ServiceConfigV1 {
    canonical: Vec<u8>,
}

impl ServiceConfigV1 {
    pub(super) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

pub(super) fn decode(bytes: &[u8]) -> Result<ServiceConfigV1, String> {
    if bytes.is_empty() || bytes.len() > MAX_SERVICE_CONFIG_BYTES {
        return Err("service configuration exceeds its exact byte bound".into());
    }
    let mut value: Value = serde_json::from_slice(bytes)
        .map_err(|_| "service configuration JSON is malformed".to_owned())?;
    let root = closed_object(
        &value,
        &["database", "http", "mode", "schema", "secrets", "telemetry"],
        "root",
    )?;
    if text(root, "schema")? != SCHEMA {
        return Err("service configuration schema is unknown".into());
    }
    let mode = match text(root, "mode")? {
        "fixture" => Mode::Fixture,
        "host" => Mode::Host,
        _ => return Err("service configuration mode is unknown".into()),
    };

    let database = closed_member(
        root,
        "database",
        &["adapter", "dsn_secret_ref", "migration_table"],
    )?;
    if text(database, "migration_table")? != "semaprax_migrations" {
        return Err("service migration table is not the fixed v1 identity".into());
    }
    let database_adapter = text(database, "adapter")?;
    let dsn = reference(database, "dsn_secret_ref")?;

    let http = closed_member(root, "http", &["adapter", "listen_origin", "tls_profile"])?;
    let http_adapter = text(http, "adapter")?;
    let listen_origin = origin(http, "listen_origin")?;
    let tls_profile = text(http, "tls_profile")?;

    let secrets = closed_member(
        root,
        "secrets",
        &[
            "password_pepper_ref",
            "session_signing_key_ref",
            "webhook_signing_key_ref",
        ],
    )?;
    let password = reference(secrets, "password_pepper_ref")?;
    let session = reference(secrets, "session_signing_key_ref")?;
    let webhook = reference(secrets, "webhook_signing_key_ref")?;

    let telemetry = closed_member(root, "telemetry", &["adapter", "endpoint_origin"])?;
    let telemetry_adapter = text(telemetry, "adapter")?;
    let telemetry_origin = origin(telemetry, "endpoint_origin")?;

    let fixture = database_adapter == "fixture"
        && dsn.is_none()
        && http_adapter == "fixture"
        && listen_origin.is_none()
        && tls_profile == "fixture"
        && password.is_none()
        && session.is_none()
        && webhook.is_none()
        && telemetry_adapter == "fixture"
        && telemetry_origin.is_none();
    let host = matches!(database_adapter, "sqlite" | "postgresql")
        && dsn.is_some()
        && http_adapter == "native"
        && listen_origin.is_some()
        && tls_profile == "modern"
        && password.is_some()
        && session.is_some()
        && webhook.is_some()
        && telemetry_adapter == "otlp"
        && telemetry_origin.is_some();
    if !matches!(
        (mode, fixture, host),
        (Mode::Fixture, true, false) | (Mode::Host, false, true)
    ) {
        return Err("service configuration mode and adapter selections disagree".into());
    }

    value.sort_all_objects();
    let mut canonical = serde_json::to_vec(&value)
        .map_err(|_| "service configuration cannot be rendered".to_owned())?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err("service configuration must use canonical JSON plus one line feed".into());
    }
    Ok(ServiceConfigV1 { canonical })
}

fn closed_object<'a>(
    value: &'a Value,
    keys: &[&str],
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("service configuration {label} must be an object"))?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(format!(
            "service configuration {label} fields are not closed"
        ));
    }
    Ok(object)
}

fn closed_member<'a>(
    root: &'a Map<String, Value>,
    key: &str,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, String> {
    closed_object(
        root.get(key)
            .ok_or_else(|| format!("service configuration lacks {key}"))?,
        keys,
        key,
    )
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("service configuration {key} must be text"))
}

fn reference<'a>(object: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, String> {
    let Some(value) = object.get(key) else {
        return Err(format!("service configuration lacks {key}"));
    };
    if value.is_null() {
        return Ok(None);
    }
    let value = value
        .as_str()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.as_bytes()[0].is_ascii_lowercase()
                && value.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
        .ok_or_else(|| format!("service configuration {key} reference is invalid"))?;
    Ok(Some(value))
}

fn origin<'a>(object: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, String> {
    let Some(value) = object.get(key) else {
        return Err(format!("service configuration lacks {key}"));
    };
    if value.is_null() {
        return Ok(None);
    }
    let value = value
        .as_str()
        .filter(|value| valid_https_origin(value))
        .ok_or_else(|| format!("service configuration {key} origin is invalid"))?;
    Ok(Some(value))
}

fn valid_https_origin(value: &str) -> bool {
    if value.len() > 2048 || !value.starts_with("https://") {
        return false;
    }
    let authority = &value[8..];
    let mut parts = authority.split(':');
    let host = parts.next().unwrap_or_default();
    let port = parts.next();
    if parts.next().is_some()
        || host.len() < 2
        || !host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        || !host.as_bytes()[0].is_ascii_alphanumeric()
        || !host.as_bytes()[host.len() - 1].is_ascii_alphanumeric()
    {
        return false;
    }
    port.is_none_or(|port| {
        !port.is_empty()
            && port.len() <= 5
            && (port.len() == 1 || !port.starts_with('0'))
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port > 0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        include_bytes!("../../../examples/task-service-project/service.config.json").to_vec()
    }

    #[test]
    fn fixture_replays_exactly_and_host_shape_is_distinct() {
        let decoded = decode(&fixture()).unwrap();
        assert_eq!(decoded.canonical_bytes(), fixture());

        let host = serde_json::json!({
            "schema": SCHEMA,
            "mode": "host",
            "database": {"adapter":"postgresql","dsn_secret_ref":"db.primary","migration_table":"semaprax_migrations"},
            "http": {"adapter":"native","listen_origin":"https://service.example","tls_profile":"modern"},
            "secrets": {"password_pepper_ref":"auth.pepper","session_signing_key_ref":"auth.session","webhook_signing_key_ref":"webhook.signing"},
            "telemetry": {"adapter":"otlp","endpoint_origin":"https://telemetry.example"},
        });
        let mut host = serde_json::to_vec(&host).unwrap();
        host.push(b'\n');
        assert_eq!(decode(&host).unwrap().canonical_bytes(), host);
    }

    #[test]
    fn hostile_shape_mode_and_canonical_drift_refuse() {
        let valid: Value = serde_json::from_slice(&fixture()).unwrap();
        let mutations: [fn(&mut Value); 5] = [
            |value: &mut Value| value["unknown"] = Value::Bool(true),
            |value: &mut Value| value["mode"] = Value::String("host".into()),
            |value: &mut Value| value["database"]["adapter"] = Value::String("postgresql".into()),
            |value: &mut Value| {
                value["database"]["dsn_secret_ref"] = Value::String("postgres://credential".into())
            },
            |value: &mut Value| {
                value["http"]["listen_origin"] = Value::String("http://insecure.example".into())
            },
        ];
        for mutation in mutations {
            let mut changed = valid.clone();
            mutation(&mut changed);
            changed.sort_all_objects();
            let mut bytes = serde_json::to_vec(&changed).unwrap();
            bytes.push(b'\n');
            assert!(decode(&bytes).is_err());
        }
        let mut noncanonical = fixture();
        noncanonical.insert(0, b' ');
        assert!(decode(&noncanonical).is_err());
        assert!(decode(&vec![b' '; MAX_SERVICE_CONFIG_BYTES + 1]).is_err());
    }

    #[test]
    fn explicit_https_ports_match_the_published_schema_boundary() {
        let valid: Value = serde_json::from_slice(&fixture()).unwrap();
        for (port, accepted) in [
            ("1", true),
            ("65535", true),
            ("0", false),
            ("00001", false),
            ("65536", false),
            ("99999", false),
        ] {
            let mut host = valid.clone();
            host["mode"] = Value::String("host".into());
            host["database"]["adapter"] = Value::String("sqlite".into());
            host["database"]["dsn_secret_ref"] = Value::String("db.primary".into());
            host["http"]["adapter"] = Value::String("native".into());
            host["http"]["listen_origin"] =
                Value::String(format!("https://service.example:{port}"));
            host["http"]["tls_profile"] = Value::String("modern".into());
            host["secrets"]["password_pepper_ref"] = Value::String("auth.pepper".into());
            host["secrets"]["session_signing_key_ref"] = Value::String("auth.session".into());
            host["secrets"]["webhook_signing_key_ref"] = Value::String("webhook.signing".into());
            host["telemetry"]["adapter"] = Value::String("otlp".into());
            host["telemetry"]["endpoint_origin"] =
                Value::String(format!("https://telemetry.example:{port}"));
            host.sort_all_objects();
            let mut bytes = serde_json::to_vec(&host).unwrap();
            bytes.push(b'\n');
            assert_eq!(decode(&bytes).is_ok(), accepted, "port {port}");
        }
    }
}
