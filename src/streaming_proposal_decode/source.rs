//! Incremental framing for the authoritative flat source Proposal grammar.

use crate::agent_proposal::{CompiledAgentProposalSchema, DecodedProposal};

use super::{
    schema_prefix::SchemaPrefix, Scanner, StreamRefusal, MAX_STREAM_BYTES, STREAM_BYTES,
    STREAM_SEMANTIC, STREAM_TRUNCATED,
};

/// Source-proposal streaming outcome. It deliberately has its own typed
/// acceptance value; source Proposal documents are not interaction documents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourcePushOutcome {
    Incomplete,
    Accepted(DecodedProposal),
    Refused(StreamRefusal),
}

fn outcome(terminal: &SourceTerminal) -> SourcePushOutcome {
    match terminal {
        SourceTerminal::Accepted(value) => SourcePushOutcome::Accepted(value.clone()),
        SourceTerminal::Refused(refusal) => SourcePushOutcome::Refused(refusal.clone()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SourceTerminal {
    Accepted(DecodedProposal),
    Refused(StreamRefusal),
}

/// Shares the bounded UTF-8 and canonical JSON/LF scanner with the interaction
/// route, then delegates final admission to `CompiledAgentProposalSchema`.
pub struct SourceProposalStreamDecoder<'a> {
    schema: &'a CompiledAgentProposalSchema,
    buffer: Vec<u8>,
    confirmed_len: usize,
    scan: Scanner,
    prefix: SchemaPrefix,
    terminal: Option<SourceTerminal>,
}

#[cfg(test)]
pub(crate) mod tests;

impl<'a> SourceProposalStreamDecoder<'a> {
    #[must_use]
    pub fn new(schema: &'a CompiledAgentProposalSchema) -> Self {
        Self {
            schema,
            buffer: Vec::new(),
            confirmed_len: 0,
            scan: Scanner::default(),
            prefix: SchemaPrefix::new(schema.stream_envelope_prefix()),
            terminal: None,
        }
    }
    #[must_use]
    pub fn schema_digest(&self) -> &str {
        self.schema.schema().digest()
    }
    pub fn push(&mut self, chunk: &[u8]) -> SourcePushOutcome {
        if let Some(terminal) = &self.terminal {
            return outcome(terminal);
        }
        if self.buffer.len().saturating_add(chunk.len()) > MAX_STREAM_BYTES {
            return self.finalize(SourceTerminal::Refused(StreamRefusal::new(
                STREAM_BYTES,
                "source proposal exceeded stream byte bound",
                self.buffer.len(),
            )));
        }
        self.buffer.extend_from_slice(chunk);
        let tail = &self.buffer[self.confirmed_len..];
        let (text, invalid) = match std::str::from_utf8(tail) {
            Ok(text) => (text, false),
            Err(error) => {
                let valid = error.valid_up_to();
                (
                    std::str::from_utf8(&tail[..valid]).expect("valid prefix"),
                    error.error_len().is_some(),
                )
            }
        };
        let base = self.confirmed_len;
        for (offset, byte) in text.bytes().enumerate() {
            if let Err(refusal) = self.scan.step(byte, base + offset) {
                return self.finalize(SourceTerminal::Refused(refusal));
            }
            if let Err(refusal) = self.prefix.step(byte, base + offset) {
                return self.finalize(SourceTerminal::Refused(refusal));
            }
        }
        self.confirmed_len = base + text.len();
        if invalid {
            return self.finalize(SourceTerminal::Refused(StreamRefusal::new(
                super::STREAM_UTF8,
                "invalid UTF-8 byte sequence",
                self.confirmed_len,
            )));
        }
        SourcePushOutcome::Incomplete
    }
    pub fn cancel(&mut self, reason: impl Into<String>) -> SourcePushOutcome {
        if let Some(terminal) = &self.terminal {
            return outcome(terminal);
        }
        self.finalize(SourceTerminal::Refused(StreamRefusal::new(
            super::STREAM_CANCELLED,
            reason,
            self.buffer.len(),
        )))
    }
    pub fn finish(&mut self) -> SourcePushOutcome {
        if let Some(terminal) = &self.terminal {
            return outcome(terminal);
        }
        if !self.scan.terminated {
            return self.finalize(SourceTerminal::Refused(StreamRefusal::new(
                STREAM_TRUNCATED,
                "source proposal stream ended before terminal newline",
                self.buffer.len(),
            )));
        }
        let text = match std::str::from_utf8(&self.buffer) {
            Ok(text) => text,
            // A terminal LF may have been scanned before a later chunk
            // supplied an incomplete UTF-8 sequence. `push` deliberately
            // leaves such a suffix unconfirmed, so `finish` must refuse it
            // stably rather than relying on the scanner invariant and
            // panicking at this embedding boundary.
            Err(_) => {
                return self.finalize(SourceTerminal::Refused(StreamRefusal::new(
                    super::STREAM_UTF8,
                    "incomplete UTF-8 sequence at end of source proposal stream",
                    self.confirmed_len,
                )))
            }
        };
        match self.schema.decode(text) {
            Ok(value) => self.finalize(SourceTerminal::Accepted(value)),
            Err(diagnostics) => self.finalize(SourceTerminal::Refused(StreamRefusal::new(
                STREAM_SEMANTIC,
                diagnostics
                    .first()
                    .map(|d| format!("{}: {}", d.code, d.message))
                    .unwrap_or_else(|| "source proposal decode failed".into()),
                self.buffer.len(),
            ))),
        }
    }
    fn finalize(&mut self, terminal: SourceTerminal) -> SourcePushOutcome {
        let value = outcome(&terminal);
        self.terminal = Some(terminal);
        value
    }
}
