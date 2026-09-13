//! Exact outer-envelope prefix admission derived from compiled schemas.

use super::{StreamRefusal, STREAM_SCHEMA_PREFIX};

/// Incrementally checks the canonical envelope bytes through the start of the
/// `value` member. The compiled schema produces these bytes; this validator
/// only rejects a divergent prefix and never accepts or decodes a value.
pub(crate) struct SchemaPrefix {
    expected: Vec<u8>,
    seen: usize,
}

impl SchemaPrefix {
    pub(crate) fn new(expected: String) -> Self {
        Self {
            expected: expected.into_bytes(),
            seen: 0,
        }
    }

    pub(crate) fn step(&mut self, byte: u8, at: usize) -> Result<(), StreamRefusal> {
        if self.seen < self.expected.len() {
            let expected = self.expected[self.seen];
            if byte != expected {
                return Err(StreamRefusal::new(
                    STREAM_SCHEMA_PREFIX,
                    "streamed document diverged from the compiled schema envelope order or identity",
                    at,
                ));
            }
            self.seen += 1;
        }
        Ok(())
    }
}
