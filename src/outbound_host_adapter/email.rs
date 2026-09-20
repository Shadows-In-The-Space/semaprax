//! Bounded provider-neutral email delivery and authority-free envelope replay.

use std::collections::BTreeSet;
use std::fmt;

use super::*;

pub const MAX_EMAIL_RECIPIENTS: usize = 64;
pub const MAX_EMAIL_SUBJECT_BYTES: usize = 256;
pub const MAX_EMAIL_BODY_BYTES: usize = 8_192;
pub const MAX_EMAIL_ATTACHMENTS: usize = 4;
pub const MAX_EMAIL_ATTACHMENT_NAME_BYTES: usize = 128;
pub const MAX_EMAIL_ATTACHMENT_BYTES: usize = 2_048;

/// One opaque attachment supplied to the provider-neutral email envelope.
/// Attachment bytes do not appear in debug output or delivery evidence.
pub struct EmailAttachment {
    pub name: String,
    pub media_type: String,
    pub body: Vec<u8>,
}

impl fmt::Debug for EmailAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailAttachment")
            .field("name", &"[REDACTED]")
            .field("media_type", &self.media_type)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Caller-selected email data for one deployment-selected provider adapter.
/// This is not SMTP and grants no DNS, socket, or credential authority.
pub struct EmailRequest {
    pub endpoint: String,
    pub delivery_id: String,
    pub idempotency_key: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub reply_to: Option<String>,
    pub subject: String,
    pub body: Vec<u8>,
    pub attachments: Vec<EmailAttachment>,
    pub deadline_ms: u64,
}

impl fmt::Debug for EmailRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailRequest")
            .field("endpoint_origin", &canonical_origin(&self.endpoint))
            .field("delivery_id", &"[REDACTED]")
            .field("idempotency_key", &"[REDACTED]")
            .field("sender", &"[REDACTED]")
            .field("recipient_count", &self.recipients.len())
            .field("has_reply_to", &self.reply_to.is_some())
            .field("subject", &"[REDACTED]")
            .field("body_bytes", &self.body.len())
            .field("attachment_count", &self.attachments.len())
            .field("deadline_ms", &self.deadline_ms)
            .finish()
    }
}

impl EmailRequest {
    fn encode(&self, limit: usize) -> Result<Vec<u8>, Refusal> {
        let attachments = self
            .attachments
            .iter()
            .map(|attachment| {
                serde_json::json!({
                    "body_hex": lower_hex(&attachment.body),
                    "media_type": attachment.media_type,
                    "name": attachment.name,
                })
            })
            .collect::<Vec<_>>();
        let value = serde_json::json!({
            "attachments": attachments,
            "body_hex": lower_hex(&self.body),
            "recipients": self.recipients,
            "reply_to": self.reply_to,
            "schema": "semaprax.outbound.email-request.v1",
            "sender": self.sender,
            "subject": self.subject,
        });
        let mut output = CappedJsonWriter::new(limit);
        serde_json::to_writer(&mut output, &value).map_err(|_| Refusal::RequestTooLarge)?;
        Ok(output.finish())
    }
}

/// Refusal while independently decoding a provider-neutral email envelope.
/// This diagnostic result cannot create delivery authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmailEnvelopeMismatch {
    Malformed,
    NonCanonical,
    Schema,
    Bound,
    PreparedRequest,
}

/// Validate and attempt one provider-neutral email delivery.
pub fn deliver_email(
    capability: OutboundCapability,
    request: EmailRequest,
    adapter: &mut impl OutboundAdapter,
) -> Result<DeliveryResult, Refusal> {
    let origin = validate_email(&capability.policy, &request)?;
    let body = request.encode(capability.policy.max_request_bytes)?;
    let prepared = PreparedRequest {
        endpoint: request.endpoint,
        headers: vec![
            (
                "content-type".into(),
                "application/vnd.semaprax.email.v1+json".into(),
            ),
            ("idempotency-key".into(), request.idempotency_key.clone()),
            ("x-semaprax-delivery-id".into(), request.delivery_id.clone()),
        ],
        body,
        deadline_ms: request.deadline_ms,
        max_redirects: 0,
        max_response_bytes: capability.policy.max_response_bytes,
    };
    let observation = adapter.send(&prepared);
    Ok(settle(
        capability,
        origin,
        request.delivery_id,
        request.idempotency_key,
        prepared,
        observation,
    ))
}

/// Strictly decode a canonical email envelope and bind it to one prepared
/// request. This replay observes no capability, credentials, or adapter.
pub fn verify_email_envelope(
    bytes: &[u8],
    expected_request: &PreparedRequest,
) -> Result<(), EmailEnvelopeMismatch> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BODY_BYTES {
        return Err(EmailEnvelopeMismatch::Bound);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| EmailEnvelopeMismatch::Malformed)?;
    decode_email_envelope(&value)?;
    let canonical = serde_json::to_vec(&value).map_err(|_| EmailEnvelopeMismatch::Malformed)?;
    if canonical != bytes {
        return Err(EmailEnvelopeMismatch::NonCanonical);
    }
    if expected_request.body != bytes
        || expected_request.headers.len() != 3
        || expected_request.headers[0]
            != (
                "content-type".into(),
                "application/vnd.semaprax.email.v1+json".into(),
            )
        || expected_request.headers[1].0 != "idempotency-key"
        || expected_request.headers[2].0 != "x-semaprax-delivery-id"
        || !valid_identity(&expected_request.headers[1].1)
        || !valid_identity(&expected_request.headers[2].1)
    {
        return Err(EmailEnvelopeMismatch::PreparedRequest);
    }
    Ok(())
}

fn decode_email_envelope(value: &serde_json::Value) -> Result<(), EmailEnvelopeMismatch> {
    const KEYS: [&str; 7] = [
        "attachments",
        "body_hex",
        "recipients",
        "reply_to",
        "schema",
        "sender",
        "subject",
    ];
    let object = value.as_object().ok_or(EmailEnvelopeMismatch::Malformed)?;
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(EmailEnvelopeMismatch::Malformed);
    }
    let text = |key: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or(EmailEnvelopeMismatch::Malformed)
    };
    if text("schema")? != "semaprax.outbound.email-request.v1" {
        return Err(EmailEnvelopeMismatch::Schema);
    }
    let recipients = object
        .get("recipients")
        .and_then(serde_json::Value::as_array)
        .ok_or(EmailEnvelopeMismatch::Malformed)?;
    if recipients.is_empty() || recipients.len() > MAX_EMAIL_RECIPIENTS {
        return Err(EmailEnvelopeMismatch::Bound);
    }
    let recipients = recipients
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(EmailEnvelopeMismatch::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let reply_to = match object
        .get("reply_to")
        .ok_or(EmailEnvelopeMismatch::Malformed)?
    {
        serde_json::Value::Null => None,
        value => Some(
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(EmailEnvelopeMismatch::Malformed)?,
        ),
    };
    let attachments = object
        .get("attachments")
        .and_then(serde_json::Value::as_array)
        .ok_or(EmailEnvelopeMismatch::Malformed)?;
    if attachments.len() > MAX_EMAIL_ATTACHMENTS {
        return Err(EmailEnvelopeMismatch::Bound);
    }
    let attachments = attachments
        .iter()
        .map(decode_email_attachment)
        .collect::<Result<Vec<_>, _>>()?;
    let request = EmailRequest {
        endpoint: "https://email-envelope.invalid/".into(),
        delivery_id: "email-envelope".into(),
        idempotency_key: "email-envelope".into(),
        sender: text("sender")?.to_owned(),
        recipients,
        reply_to,
        subject: text("subject")?.to_owned(),
        body: decode_lower_hex(text("body_hex")?, MAX_EMAIL_BODY_BYTES)?,
        attachments,
        deadline_ms: 1,
    };
    validate_email_members(&request).map_err(|refusal| match refusal {
        Refusal::RequestTooLarge | Refusal::CardinalityExceeded => EmailEnvelopeMismatch::Bound,
        _ => EmailEnvelopeMismatch::Malformed,
    })
}

fn decode_email_attachment(
    value: &serde_json::Value,
) -> Result<EmailAttachment, EmailEnvelopeMismatch> {
    const KEYS: [&str; 3] = ["body_hex", "media_type", "name"];
    let object = value.as_object().ok_or(EmailEnvelopeMismatch::Malformed)?;
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(EmailEnvelopeMismatch::Malformed);
    }
    let text = |key: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or(EmailEnvelopeMismatch::Malformed)
    };
    Ok(EmailAttachment {
        name: text("name")?.to_owned(),
        media_type: text("media_type")?.to_owned(),
        body: decode_lower_hex(text("body_hex")?, MAX_EMAIL_ATTACHMENT_BYTES)?,
    })
}

fn decode_lower_hex(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, EmailEnvelopeMismatch> {
    if value.len() % 2 != 0 || value.len() / 2 > maximum_bytes {
        return Err(EmailEnvelopeMismatch::Bound);
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = lower_hex_digit(pair[0]).ok_or(EmailEnvelopeMismatch::Malformed)?;
        let low = lower_hex_digit(pair[1]).ok_or(EmailEnvelopeMismatch::Malformed)?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn lower_hex_digit(byte: u8) -> Option<u8> {
    if byte.is_ascii_digit() {
        Some(byte - b'0')
    } else if (b'a'..=b'f').contains(&byte) {
        Some(byte - b'a' + 10)
    } else {
        None
    }
}

fn validate_email(policy: &OutboundPolicy, request: &EmailRequest) -> Result<String, Refusal> {
    let origin = validate_common(policy, &request.endpoint, request.deadline_ms)?;
    if !valid_identity(&request.delivery_id) || !valid_identity(&request.idempotency_key) {
        return Err(Refusal::InvalidIdentity);
    }
    validate_email_members(request)?;
    Ok(origin)
}

fn validate_email_members(request: &EmailRequest) -> Result<(), Refusal> {
    if request.recipients.is_empty() || request.recipients.len() > MAX_EMAIL_RECIPIENTS {
        return Err(Refusal::InvalidEmail);
    }
    if request.body.len() > MAX_EMAIL_BODY_BYTES
        || request.attachments.len() > MAX_EMAIL_ATTACHMENTS
    {
        return Err(Refusal::RequestTooLarge);
    }
    if !email_address_admitted(&request.sender)
        || request
            .reply_to
            .as_deref()
            .is_some_and(|value| !email_address_admitted(value))
        || request
            .recipients
            .iter()
            .any(|value| !email_address_admitted(value))
    {
        return Err(Refusal::InvalidEmail);
    }
    if request.recipients.iter().collect::<BTreeSet<_>>().len() != request.recipients.len() {
        return Err(Refusal::CardinalityExceeded);
    }
    if request.subject.is_empty()
        || request.subject.len() > MAX_EMAIL_SUBJECT_BYTES
        || contains_control(&request.subject)
    {
        return Err(Refusal::InvalidEmail);
    }
    if request.attachments.iter().any(|attachment| {
        !valid_attachment_name(&attachment.name) || !valid_media_type(&attachment.media_type)
    }) {
        return Err(Refusal::InvalidEmail);
    }
    if request
        .attachments
        .iter()
        .any(|attachment| attachment.body.len() > MAX_EMAIL_ATTACHMENT_BYTES)
    {
        return Err(Refusal::RequestTooLarge);
    }
    if request
        .attachments
        .iter()
        .map(|attachment| &attachment.name)
        .collect::<BTreeSet<_>>()
        .len()
        != request.attachments.len()
    {
        return Err(Refusal::CardinalityExceeded);
    }
    Ok(())
}

fn email_address_admitted(address: &str) -> bool {
    let bytes = address.as_bytes();
    if !(3..=254).contains(&bytes.len()) || !address.is_ascii() {
        return false;
    }
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    address.matches('@').count() == 1
        && (1..=64).contains(&local.len())
        && local.split('.').all(valid_local_atom)
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && (1..=255).contains(&domain.len())
        && domain.contains('.')
        && domain.split('.').all(valid_domain_label)
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
}

fn valid_local_atom(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                )
        })
}

fn valid_domain_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_attachment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EMAIL_ATTACHMENT_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_media_type(value: &str) -> bool {
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    !kind.is_empty()
        && !subtype.is_empty()
        && value.matches('/').count() == 1
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'/' | b'!'
                        | b'#'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
