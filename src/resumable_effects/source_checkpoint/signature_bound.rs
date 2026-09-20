//! Version 2 binds the compiler-derived effect signature into the authenticated
//! envelope. Version 1 remains a separate, unchanged compatibility wire.

use super::{
    checkpoint, keys, map_inner_error, required_str, scope_json, validate_scope,
    validate_scope_field, ArgumentValue, Hmac, KeyInit, Mac, ResolvedProgram,
    ResumableContinuation, Sha256, SourceCheckpointError, SourceCheckpointKey,
    SourceCheckpointScope, MAX_CHECKPOINT_BYTES,
};
use crate::resumable_effects::source_signature::{
    derive_source_effect_signature, SourceEffectSignature,
};
use serde_json::{json, Value};

/// Explicit opt-in schema binding checked source effect shapes and lowering.
pub const SOURCE_RESUMABLE_CHECKPOINT_SCHEMA_V2: &str = "semaprax.source-resumable-checkpoint.v2";
const AUTHENTICATION_DOMAIN_V2: &[u8] = b"semaprax.source-resumable-checkpoint-authentication.v2\0";

/// Authenticate a structurally valid continuation and its compiler-derived
/// signature under the caller's exact scope. Unlike the v1 encoder, this API
/// requires the checked program and original arguments so that a continuation
/// from different source, lowering, or argument bits cannot be signed as
/// current. The caller-owned scope establishes the invocation being signed;
/// the opaque continuation does not carry an invocation identity of its own.
///
/// No source is executed. A signed checkpoint remains inert proof data;
/// ordinary resume must replay every request before accepting a new answer.
pub fn encode_source_checkpoint_v2(
    program: &ResolvedProgram,
    key: &SourceCheckpointKey,
    scope: &SourceCheckpointScope,
    function_id: &str,
    arguments: &[ArgumentValue],
    continuation: &ResumableContinuation,
) -> Result<Vec<u8>, SourceCheckpointError> {
    validate_scope(scope)?;
    validate_scope_field(function_id)?;
    let signature = derive_signature(program, function_id)?;
    let inner = checkpoint::encode(function_id, continuation).map_err(map_inner_error)?;
    checkpoint::decode(program, function_id, arguments, &inner).map_err(map_inner_error)?;
    let continuation =
        serde_json::from_slice(&inner).map_err(|_| SourceCheckpointError::Malformed)?;
    render(
        key,
        payload(scope, function_id, signature_json(&signature), continuation),
    )
}

/// Recover only when authenticated scope, selected function, checked effect
/// signature, lowering plan, and the structural continuation all match the
/// independently supplied current program and arguments. V1 envelopes are
/// deliberately rejected; callers must select that compatibility API explicitly.
/// Signature drift is reported as [`SourceCheckpointError::ProgramMismatch`].
pub fn decode_source_checkpoint_v2(
    program: &ResolvedProgram,
    key: &SourceCheckpointKey,
    expected_scope: &SourceCheckpointScope,
    function_id: &str,
    arguments: &[ArgumentValue],
    bytes: &[u8],
) -> Result<ResumableContinuation, SourceCheckpointError> {
    validate_scope(expected_scope)?;
    validate_scope_field(function_id)?;
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(SourceCheckpointError::TooLarge);
    }
    let document: Value =
        serde_json::from_slice(bytes).map_err(|_| SourceCheckpointError::Malformed)?;
    // Check the version before the exact field set to make downgrade refusal
    // stable even though the old wire has no signature field.
    if required_str(&document, "schema")? != SOURCE_RESUMABLE_CHECKPOINT_SCHEMA_V2 {
        return Err(SourceCheckpointError::SchemaMismatch);
    }
    keys(
        &document,
        &[
            "schema",
            "scope",
            "function",
            "signature",
            "continuation",
            "authentication",
        ],
    )?;
    let encoded_scope = &document["scope"];
    keys(
        encoded_scope,
        &["program_root", "invocation_id", "policy_epoch"],
    )?;
    let observed_scope = SourceCheckpointScope::new(
        required_str(encoded_scope, "program_root")?,
        required_str(encoded_scope, "invocation_id")?,
        encoded_scope["policy_epoch"]
            .as_u64()
            .ok_or(SourceCheckpointError::Malformed)?,
    )?;
    let encoded_function = required_str(&document, "function")?;
    validate_scope_field(encoded_function)?;
    keys(
        &document["signature"],
        &[
            "request_shape",
            "answer_shape",
            "plan_identity",
            "yield_count",
        ],
    )?;
    let unsigned = payload(
        &observed_scope,
        encoded_function,
        document["signature"].clone(),
        document["continuation"].clone(),
    );
    verify_authentication(key, &unsigned, required_str(&document, "authentication")?)?;
    if render(key, unsigned)?.as_slice() != bytes {
        return Err(SourceCheckpointError::NonCanonical);
    }
    if observed_scope != *expected_scope {
        return Err(SourceCheckpointError::ScopeMismatch);
    }
    if encoded_function != function_id {
        return Err(SourceCheckpointError::FunctionMismatch);
    }
    let expected_signature = derive_signature(program, function_id)?;
    if document["signature"] != signature_json(&expected_signature) {
        return Err(SourceCheckpointError::ProgramMismatch);
    }
    let inner = format!("{}\n", document["continuation"]).into_bytes();
    checkpoint::decode(program, function_id, arguments, &inner).map_err(map_inner_error)
}

fn derive_signature(
    program: &ResolvedProgram,
    function_id: &str,
) -> Result<SourceEffectSignature, SourceCheckpointError> {
    derive_source_effect_signature(program, function_id)
        .map_err(|_| SourceCheckpointError::ProgramMismatch)
}

fn signature_json(signature: &SourceEffectSignature) -> Value {
    json!({
        "request_shape": signature.request_shape(),
        "answer_shape": signature.answer_shape(),
        "plan_identity": format!("sha256:{:x}", crate::digest_hex::LowerHex(signature.plan_identity())),
        "yield_count": signature.yield_count(),
    })
}

fn payload(
    scope: &SourceCheckpointScope,
    function_id: &str,
    signature: Value,
    continuation: Value,
) -> Value {
    json!({
        "schema": SOURCE_RESUMABLE_CHECKPOINT_SCHEMA_V2,
        "scope": scope_json(scope),
        "function": function_id,
        "signature": signature,
        "continuation": continuation,
    })
}

fn mac(key: &SourceCheckpointKey, payload: &Value) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key.0).expect("HMAC accepts a 32-byte key");
    mac.update(AUTHENTICATION_DOMAIN_V2);
    mac.update(payload.to_string().as_bytes());
    mac
}

fn render(key: &SourceCheckpointKey, mut payload: Value) -> Result<Vec<u8>, SourceCheckpointError> {
    let authentication = format!(
        "hmac-sha256:{:x}",
        crate::digest_hex::LowerHex(mac(key, &payload).finalize().into_bytes())
    );
    payload["authentication"] = Value::String(authentication);
    let bytes = format!("{payload}\n").into_bytes();
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(SourceCheckpointError::TooLarge);
    }
    Ok(bytes)
}

fn verify_authentication(
    key: &SourceCheckpointKey,
    payload: &Value,
    claimed: &str,
) -> Result<(), SourceCheckpointError> {
    let hex = claimed
        .strip_prefix("hmac-sha256:")
        .ok_or(SourceCheckpointError::AuthenticationMismatch)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SourceCheckpointError::AuthenticationMismatch);
    }
    let mut tag = [0; 32];
    for (index, byte) in tag.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| SourceCheckpointError::AuthenticationMismatch)?;
    }
    mac(key, payload)
        .verify_slice(&tag)
        .map_err(|_| SourceCheckpointError::AuthenticationMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interpreter::resumable::{
        resume_sequential_resumable_effect, run_sequential_resumable_effect,
        SequentialResumableStep,
    };
    use std::path::Path;

    const SOURCE: &str = r#"
module test.signature_checkpoint;
@id("app.ask")
fn ask(seed: i64) -> i64
    yields i64 -> i64
{
    let first = yield seed + 1;
    yield first + 2
}
@id("app.main")
fn main() -> i64 { 0 }
"#;

    fn program(source: &str) -> ResolvedProgram {
        let ast = crate::parse(source, Path::new("signature-checkpoint.spx")).unwrap();
        crate::hir::resolve(&ast).unwrap()
    }

    fn scope() -> SourceCheckpointScope {
        SourceCheckpointScope::new("sha256:program", "invocation-7", 11).unwrap()
    }

    fn key() -> SourceCheckpointKey {
        SourceCheckpointKey::new([0x5a; 32])
    }

    fn first(program: &ResolvedProgram) -> ResumableContinuation {
        let evaluation =
            run_sequential_resumable_effect(program, "app.ask", &[ArgumentValue::Int(4)], 10_000)
                .unwrap();
        let SequentialResumableStep::Suspended { continuation } = evaluation.step else {
            panic!("fixture did not suspend")
        };
        continuation
    }

    fn encode(program: &ResolvedProgram, continuation: &ResumableContinuation) -> Vec<u8> {
        encode_source_checkpoint_v2(
            program,
            &key(),
            &scope(),
            "app.ask",
            &[ArgumentValue::Int(4)],
            continuation,
        )
        .unwrap()
    }

    fn decode(
        program: &ResolvedProgram,
        bytes: &[u8],
    ) -> Result<ResumableContinuation, SourceCheckpointError> {
        decode_source_checkpoint_v2(
            program,
            &key(),
            &scope(),
            "app.ask",
            &[ArgumentValue::Int(4)],
            bytes,
        )
    }

    // Simulate a buggy authorized writer, stronger than store-side corruption:
    // a fresh valid tag still cannot substitute compiler-derived facts.
    fn resign(mut document: Value) -> Vec<u8> {
        document.as_object_mut().unwrap().remove("authentication");
        render(&key(), document).unwrap()
    }

    #[test]
    fn signature_bound_checkpoint_is_deterministic_and_recovers_each_site() {
        let program = program(SOURCE);
        let continuation = first(&program);
        let bytes = encode(&program, &continuation);
        assert_eq!(bytes, encode(&program, &continuation));
        let document: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document["schema"], SOURCE_RESUMABLE_CHECKPOINT_SCHEMA_V2);
        assert_eq!(
            document["signature"],
            signature_json(&derive_signature(&program, "app.ask").unwrap())
        );
        let recovered = decode(&program, &bytes).unwrap();
        assert_eq!(recovered, continuation);
        let resumed = resume_sequential_resumable_effect(
            &program,
            "app.ask",
            &[ArgumentValue::Int(4)],
            &recovered,
            &ArgumentValue::Int(10),
            10_000,
        )
        .unwrap();
        let SequentialResumableStep::Suspended { continuation } = resumed.step else {
            panic!("second site was not reached")
        };
        let recovered = decode(&program, &encode(&program, &continuation)).unwrap();
        assert_eq!(recovered.request(), &ArgumentValue::Int(12));
        let finished = resume_sequential_resumable_effect(
            &program,
            "app.ask",
            &[ArgumentValue::Int(4)],
            &recovered,
            &ArgumentValue::Int(20),
            10_000,
        )
        .unwrap();
        assert!(matches!(
            finished.step,
            SequentialResumableStep::Completed {
                result: ArgumentValue::Int(20),
                ..
            }
        ));
    }

    #[test]
    fn authenticated_signature_fields_cannot_override_checked_source() {
        let program = program(SOURCE);
        let document: Value = serde_json::from_slice(&encode(&program, &first(&program))).unwrap();
        for (field, value) in [
            ("request_shape", json!("semaprax.resolved-type.v1:bool")),
            ("answer_shape", json!("semaprax.resolved-type.v1:bool")),
            ("plan_identity", json!(format!("sha256:{}", "0".repeat(64)))),
            ("yield_count", json!(3)),
            ("yield_count", json!(2.0)),
            ("yield_count", json!("2")),
        ] {
            let mut changed = document.clone();
            changed["signature"][field] = value;
            assert_eq!(
                decode(&program, &resign(changed)),
                Err(SourceCheckpointError::ProgramMismatch),
                "{field}"
            );
        }
        let mut extra = document.clone();
        extra["signature"]["unknown"] = json!(0);
        assert_eq!(
            decode(&program, &resign(extra)),
            Err(SourceCheckpointError::Malformed)
        );
        let mut absent = document;
        absent["signature"]
            .as_object_mut()
            .unwrap()
            .remove("request_shape");
        assert_eq!(
            decode(&program, &resign(absent)),
            Err(SourceCheckpointError::Malformed)
        );
    }

    #[test]
    fn changed_program_types_plan_and_arguments_refuse_recovery_and_encoding() {
        let original = program(SOURCE);
        let continuation = first(&original);
        let bytes = encode(&original, &continuation);
        let answer_drift = SOURCE
            .replace(
                "-> i64\n    yields i64 -> i64",
                "-> bool\n    yields i64 -> bool",
            )
            .replace("yield first + 2", "yield 2");
        let request_drift = SOURCE
            .replace("yields i64 -> i64", "yields bool -> i64")
            .replace("yield seed + 1", "yield true")
            .replace("yield first + 2", "yield false");
        for source in [
            SOURCE.replace("seed + 1", "seed + 9"),
            SOURCE.replace("yield first + 2", "first + 2"),
            answer_drift,
            request_drift,
        ] {
            let drifted = program(&source);
            assert_eq!(
                decode(&drifted, &bytes),
                Err(SourceCheckpointError::ProgramMismatch)
            );
            assert!(encode_source_checkpoint_v2(
                &drifted,
                &key(),
                &scope(),
                "app.ask",
                &[ArgumentValue::Int(4)],
                &continuation
            )
            .is_err());
        }
        assert!(encode_source_checkpoint_v2(
            &original,
            &key(),
            &scope(),
            "app.ask",
            &[ArgumentValue::Int(5)],
            &continuation
        )
        .is_err());
        assert!(decode_source_checkpoint_v2(
            &original,
            &key(),
            &scope(),
            "app.ask",
            &[ArgumentValue::Int(5)],
            &bytes
        )
        .is_err());
    }

    #[test]
    fn signature_checkpoint_rejects_corruption_noncanonical_bytes_and_downgrade() {
        let program = program(SOURCE);
        let continuation = first(&program);
        let bytes = encode(&program, &continuation);
        let document: Value = serde_json::from_slice(&bytes).unwrap();
        let mut corrupt = document.clone();
        corrupt["signature"]["yield_count"] = json!(3);
        assert_eq!(
            decode(&program, format!("{corrupt}\n").as_bytes()),
            Err(SourceCheckpointError::AuthenticationMismatch)
        );
        assert_eq!(
            decode(&program, &[b" ".as_slice(), bytes.as_slice()].concat()),
            Err(SourceCheckpointError::NonCanonical)
        );
        // Equal duplicate values preserve parsed meaning and MAC but not the wire.
        let duplicate = String::from_utf8(bytes.clone()).unwrap().replacen(
            "\"yield_count\":2",
            "\"yield_count\":2,\"yield_count\":2",
            1,
        );
        assert_eq!(
            decode(&program, duplicate.as_bytes()),
            Err(SourceCheckpointError::NonCanonical)
        );
        assert!(decode(&program, &bytes[..bytes.len() - 2]).is_err());
        assert_eq!(
            decode(&program, &vec![b' '; MAX_CHECKPOINT_BYTES + 1]),
            Err(SourceCheckpointError::TooLarge)
        );
        let v1 = super::super::encode_source_checkpoint(&key(), &scope(), "app.ask", &continuation)
            .unwrap();
        assert_eq!(
            decode(&program, &v1),
            Err(SourceCheckpointError::SchemaMismatch)
        );
        assert!(super::super::decode_source_checkpoint(
            &program,
            &key(),
            &scope(),
            "app.ask",
            &[ArgumentValue::Int(4)],
            &bytes
        )
        .is_err());
        assert_eq!(
            super::super::decode_source_checkpoint(
                &program,
                &key(),
                &scope(),
                "app.ask",
                &[ArgumentValue::Int(4)],
                &v1
            )
            .unwrap(),
            continuation
        );
    }

    #[test]
    fn signature_checkpoint_preserves_scope_key_and_function_refusals() {
        let program = program(SOURCE);
        let bytes = encode(&program, &first(&program));
        for expected in [
            SourceCheckpointScope::new("sha256:other", "invocation-7", 11).unwrap(),
            SourceCheckpointScope::new("sha256:program", "invocation-8", 11).unwrap(),
            SourceCheckpointScope::new("sha256:program", "invocation-7", 12).unwrap(),
        ] {
            assert_eq!(
                decode_source_checkpoint_v2(
                    &program,
                    &key(),
                    &expected,
                    "app.ask",
                    &[ArgumentValue::Int(4)],
                    &bytes
                ),
                Err(SourceCheckpointError::ScopeMismatch)
            );
        }
        assert_eq!(
            decode_source_checkpoint_v2(
                &program,
                &SourceCheckpointKey::new([0; 32]),
                &scope(),
                "app.ask",
                &[ArgumentValue::Int(4)],
                &bytes
            ),
            Err(SourceCheckpointError::AuthenticationMismatch)
        );
        assert_eq!(
            decode_source_checkpoint_v2(
                &program,
                &key(),
                &scope(),
                "app.other",
                &[ArgumentValue::Int(4)],
                &bytes
            ),
            Err(SourceCheckpointError::FunctionMismatch)
        );
    }
}
