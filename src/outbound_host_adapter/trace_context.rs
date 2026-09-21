//! Bounded W3C Trace Context parsing and propagation.
//!
//! Identifier generation is capability-injected. This module never reads an
//! ambient random source and never treats an inbound header as authority.

const TRACEPARENT_BYTES: usize = 55;
const SAMPLED_FLAG: u8 = 0x01;
const RANDOM_TRACE_ID_FLAG: u8 = 0x02;
const KNOWN_FLAGS: u8 = SAMPLED_FLAG | RANDOM_TRACE_ID_FLAG;

/// Deployment-owned cryptographic entropy authority. Returning success
/// certifies that every requested byte was selected uniformly from a secure
/// random or pseudorandom source. In particular, this guarantees at least the
/// rightmost 56 trace-ID bits required before setting W3C's random-ID flag.
/// Implementations that cannot make that guarantee must return an error.
pub trait TraceEntropyCapability {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), TraceContextError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceContextError {
    Malformed,
    UnsupportedVersion,
    ReservedFlags,
    EntropyUnavailable,
    ZeroIdentifier,
    IdentifierCollision,
}

/// One current span plus the remote or local parent from which it was derived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceContext {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    flags: u8,
}

impl TraceContext {
    pub fn fresh(
        entropy: &mut dyn TraceEntropyCapability,
        sampled: bool,
    ) -> Result<Self, TraceContextError> {
        let mut identifiers = [0; 24];
        entropy
            .fill_bytes(&mut identifiers)
            .map_err(|_| TraceContextError::EntropyUnavailable)?;
        let mut trace_id = [0; 16];
        trace_id.copy_from_slice(&identifiers[..16]);
        let mut span_id = [0; 8];
        span_id.copy_from_slice(&identifiers[16..]);
        validate_identifiers(&trace_id, &span_id)?;
        Ok(Self {
            trace_id,
            span_id,
            parent_span_id: None,
            flags: RANDOM_TRACE_ID_FLAG | u8::from(sampled),
        })
    }

    pub fn from_traceparent(
        header: &str,
        entropy: &mut dyn TraceEntropyCapability,
    ) -> Result<Self, TraceContextError> {
        let bytes = header.as_bytes();
        if bytes.len() < 2 || !bytes[..2].iter().all(|byte| lower_hex(*byte)) {
            return Err(TraceContextError::Malformed);
        }
        if &bytes[..2] != b"00" {
            return Err(TraceContextError::UnsupportedVersion);
        }
        if bytes.len() != TRACEPARENT_BYTES
            || bytes[2] != b'-'
            || bytes[35] != b'-'
            || bytes[52] != b'-'
        {
            return Err(TraceContextError::Malformed);
        }
        let trace_id = decode_hex::<16>(&bytes[3..35])?;
        let remote_parent = decode_hex::<8>(&bytes[36..52])?;
        let flags = decode_hex::<1>(&bytes[53..55])?[0];
        validate_identifiers(&trace_id, &remote_parent)?;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(TraceContextError::ReservedFlags);
        }
        let span_id = next_span_id(entropy)?;
        if span_id == remote_parent {
            return Err(TraceContextError::IdentifierCollision);
        }
        Ok(Self {
            trace_id,
            span_id,
            parent_span_id: Some(remote_parent),
            flags,
        })
    }

    pub fn child(
        &self,
        entropy: &mut dyn TraceEntropyCapability,
    ) -> Result<Self, TraceContextError> {
        let span_id = next_span_id(entropy)?;
        if span_id == self.span_id {
            return Err(TraceContextError::IdentifierCollision);
        }
        Ok(Self {
            trace_id: self.trace_id,
            span_id,
            parent_span_id: Some(self.span_id),
            flags: self.flags,
        })
    }

    pub fn traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            hex(&self.trace_id),
            hex(&self.span_id),
            self.flags
        )
    }

    pub fn trace_id(&self) -> String {
        hex(&self.trace_id)
    }

    pub fn span_id(&self) -> String {
        hex(&self.span_id)
    }

    pub fn parent_span_id(&self) -> Option<String> {
        self.parent_span_id
            .as_ref()
            .map(|identifier| hex(identifier))
    }

    pub fn sampled(&self) -> bool {
        self.flags & SAMPLED_FLAG != 0
    }

    pub fn random_trace_id(&self) -> bool {
        self.flags & RANDOM_TRACE_ID_FLAG != 0
    }
}

fn next_span_id(entropy: &mut dyn TraceEntropyCapability) -> Result<[u8; 8], TraceContextError> {
    let mut identifier = [0; 8];
    entropy
        .fill_bytes(&mut identifier)
        .map_err(|_| TraceContextError::EntropyUnavailable)?;
    if identifier == [0; 8] {
        return Err(TraceContextError::ZeroIdentifier);
    }
    Ok(identifier)
}

fn validate_identifiers(trace_id: &[u8; 16], span_id: &[u8; 8]) -> Result<(), TraceContextError> {
    if *trace_id == [0; 16] || *span_id == [0; 8] {
        return Err(TraceContextError::ZeroIdentifier);
    }
    Ok(())
}

fn decode_hex<const N: usize>(input: &[u8]) -> Result<[u8; N], TraceContextError> {
    if input.len() != N * 2 || !input.iter().all(|byte| lower_hex(*byte)) {
        return Err(TraceContextError::Malformed);
    }
    let mut output = [0; N];
    for (index, pair) in input.chunks_exact(2).enumerate() {
        output[index] = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(output)
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("validated lowercase hexadecimal"),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing into String cannot fail");
    }
    output
}

#[cfg(test)]
#[path = "trace_context_tests.rs"]
mod tests;
