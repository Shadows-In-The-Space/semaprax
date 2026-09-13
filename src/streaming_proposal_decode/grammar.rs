//! One bounded incremental machine over schema-owned type tables.
use super::{StreamRefusal, MAX_STREAM_BYTES, MAX_STREAM_DEPTH, STREAM_SCHEMA_PREFIX};
use crate::diagnostic::quote_json;
use std::collections::BTreeMap;

pub const STREAM_GRAMMAR: &str = "STREAM-GRAMMAR";
pub const MAX_GRAMMAR_WORK: usize = MAX_STREAM_BYTES * 64;
#[derive(Clone, Debug)]
pub(crate) struct Grammar {
    pub(crate) envelope: String,
    pub(crate) root: String,
    pub(crate) types: BTreeMap<String, Type>,
}
#[derive(Clone, Debug)]
pub(crate) enum Type {
    Record(Vec<Field>),
    Variant(Vec<Case>),
}
#[derive(Clone, Debug)]
pub(crate) struct Case {
    pub(crate) id: String,
    pub(crate) fields: Vec<Field>,
}
#[derive(Clone, Debug)]
pub(crate) struct Field {
    pub(crate) id: String,
    pub(crate) value: Value,
}
#[derive(Clone, Debug)]
pub(crate) enum Value {
    Scalar(Scalar),
    Type(String),
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum Scalar {
    Bool,
    I32,
    I64,
    U8,
    U64,
    Text(usize),
    Bytes(usize),
}
/// Read-only grammar position. It never represents a decoded or authorized value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpectedNext {
    Envelope,
    ObjectKey,
    CaseIdentity,
    FieldIdentity,
    Scalar,
    Complete,
}

#[derive(Debug)]
enum Op {
    Literal {
        bytes: Vec<u8>,
        next: usize,
        kind: ExpectedNext,
        location: String,
    },
    Value(Value, String),
    Fields {
        id: String,
        case: Option<usize>,
        next: usize,
    },
    Case {
        id: String,
        low: usize,
        high: usize,
        next: usize,
    },
    String {
        scalar: Scalar,
        token: Vec<u8>,
        escape: Escape,
        decoded_bytes: usize,
        location: String,
    },
    Bytes {
        limit: usize,
        count: usize,
        token: Vec<u8>,
        allow_end: bool,
        location: String,
    },
}
#[derive(Clone, Copy, Debug)]
enum Escape {
    None,
    Slash,
    Unicode(u8, u16),
}
#[derive(Debug)]
pub(crate) struct GrammarState {
    grammar: Grammar,
    cases: BTreeMap<String, Vec<(Vec<u8>, usize)>>,
    stack: Vec<Op>,
    expected: Vec<ExpectedNext>,
    work: usize,
}

impl GrammarState {
    pub(crate) fn new(grammar: Grammar) -> Self {
        let root = grammar.root.clone();
        let envelope = grammar.envelope.as_bytes().to_vec();
        // Sort one auxiliary lookup table; original declaration order and
        // field tables remain untouched. Each later byte uses binary bounds.
        let cases = grammar
            .types
            .iter()
            .filter_map(|(id, ty)| {
                let Type::Variant(cases) = ty else {
                    return None;
                };
                let mut values: Vec<_> = cases
                    .iter()
                    .enumerate()
                    .map(|(i, c)| (quote_json(&c.id).into_bytes(), i))
                    .collect();
                values.sort_by(|a, b| a.0.cmp(&b.0));
                Some((id.clone(), values))
            })
            .collect();
        let mut state = Self {
            grammar,
            cases,
            stack: Vec::new(),
            expected: vec![ExpectedNext::Envelope],
            work: 0,
        };
        state.literal(b"}\n".to_vec(), ExpectedNext::ObjectKey, "document");
        state.stack.push(Op::Value(Value::Type(root.clone()), root));
        state.literal(envelope, ExpectedNext::Envelope, "envelope");
        state
    }
    pub(crate) fn expected_next(&self) -> &[ExpectedNext] {
        &self.expected
    }
    pub(crate) fn work(&self) -> usize {
        self.work
    }
    fn literal(&mut self, bytes: Vec<u8>, kind: ExpectedNext, location: &str) {
        if !bytes.is_empty() {
            self.stack.push(Op::Literal {
                bytes,
                next: 0,
                kind,
                location: location.into(),
            });
        }
    }
    fn fail(location: &str, at: usize, reason: &str) -> StreamRefusal {
        StreamRefusal::new(STREAM_GRAMMAR, format!("{location}: {reason}"), at)
    }
    fn charge(&mut self, amount: usize, at: usize) -> Result<(), StreamRefusal> {
        self.work = self.work.saturating_add(amount);
        if self.work > MAX_GRAMMAR_WORK {
            return Err(Self::fail("grammar", at, "incremental work limit exceeded"));
        }
        if self.stack.len() > MAX_STREAM_DEPTH * 4 {
            return Err(Self::fail("grammar", at, "parser stack limit exceeded"));
        }
        Ok(())
    }
    fn refresh(&mut self) {
        self.expected.clear();
        self.expected.push(match self.stack.last() {
            None => ExpectedNext::Complete,
            Some(Op::Literal { kind, .. }) => kind.clone(),
            Some(Op::Case { .. }) => ExpectedNext::CaseIdentity,
            Some(Op::Fields { .. }) => ExpectedNext::FieldIdentity,
            Some(Op::Value(Value::Type(_), _)) => ExpectedNext::ObjectKey,
            _ => ExpectedNext::Scalar,
        });
    }
    pub(crate) fn step(&mut self, byte: u8, at: usize) -> Result<(), StreamRefusal> {
        // Epsilon transitions expand only the current field/type, never its
        // descendants or alternate variant cases recursively.
        loop {
            self.charge(1, at)?;
            let op = self
                .stack
                .pop()
                .ok_or_else(|| Self::fail("document", at, "trailing byte"))?;
            match op {
                Op::Literal {
                    bytes,
                    mut next,
                    kind,
                    location,
                } => {
                    if bytes[next] != byte {
                        let code = if kind == ExpectedNext::Envelope {
                            STREAM_SCHEMA_PREFIX
                        } else {
                            STREAM_GRAMMAR
                        };
                        return Err(StreamRefusal::new(
                            code,
                            format!(
                                "{location}: expected canonical identity, order or punctuation"
                            ),
                            at,
                        ));
                    }
                    next += 1;
                    if next < bytes.len() {
                        self.stack.push(Op::Literal {
                            bytes,
                            next,
                            kind,
                            location,
                        });
                    }
                }
                Op::Value(Value::Type(id), _) => {
                    let ty = self
                        .grammar
                        .types
                        .get(&id)
                        .ok_or_else(|| Self::fail(&id, at, "missing compiled type"))?;
                    match ty {
                        Type::Record(_) => {
                            self.literal(b"}".to_vec(), ExpectedNext::ObjectKey, &id);
                            self.stack.push(Op::Fields {
                                id: id.clone(),
                                case: None,
                                next: 0,
                            });
                            self.literal(b"{\"fields\":{".to_vec(), ExpectedNext::ObjectKey, &id);
                        }
                        Type::Variant(cases) => {
                            self.stack.push(Op::Case {
                                id: id.clone(),
                                low: 0,
                                high: cases.len(),
                                next: 0,
                            });
                            self.literal(b"{\"case\":".to_vec(), ExpectedNext::CaseIdentity, &id);
                        }
                    }
                    continue;
                }
                Op::Fields { id, case, next } => {
                    let fields = match self.grammar.types.get(&id) {
                        Some(Type::Record(fields)) if case.is_none() => fields,
                        Some(Type::Variant(cases)) => {
                            &cases[case.expect("compiled variant case")].fields
                        }
                        _ => return Err(Self::fail(&id, at, "invalid compiled field table")),
                    };
                    if let Some(field) = fields.get(next).cloned() {
                        self.stack.push(Op::Fields {
                            id,
                            case,
                            next: next + 1,
                        });
                        self.stack.push(Op::Value(field.value, field.id.clone()));
                        let prefix = format!(
                            "{}{}:",
                            if next == 0 { "" } else { "," },
                            quote_json(&field.id)
                        );
                        self.literal(prefix.into_bytes(), ExpectedNext::FieldIdentity, &field.id);
                    } else {
                        self.literal(b"}".to_vec(), ExpectedNext::ObjectKey, &id);
                    }
                    continue;
                }
                Op::Case {
                    id,
                    low,
                    high,
                    mut next,
                } => {
                    let table = &self.cases[&id];
                    let mut comparisons = 0;
                    let lower = table[low..high].partition_point(|(value, _)| {
                        comparisons += 1;
                        value.get(next).copied() < Some(byte)
                    });
                    let upper = table[low..high].partition_point(|(value, _)| {
                        comparisons += 1;
                        value.get(next).copied() <= Some(byte)
                    });
                    let low = low + lower;
                    let high = low + upper - lower;
                    if low == high {
                        return Err(Self::fail(&id, at, "unknown or noncanonical variant case"));
                    }
                    next += 1;
                    let selected = (table[low].0.len() == next).then_some(table[low].1);
                    self.charge(comparisons, at)?;
                    if let Some(case) = selected {
                        self.literal(b"}".to_vec(), ExpectedNext::ObjectKey, &id);
                        self.stack.push(Op::Fields {
                            id: id.clone(),
                            case: Some(case),
                            next: 0,
                        });
                        self.literal(b",\"fields\":{".to_vec(), ExpectedNext::ObjectKey, &id);
                    } else {
                        self.stack.push(Op::Case {
                            id,
                            low,
                            high,
                            next,
                        });
                    }
                }
                Op::Value(Value::Scalar(Scalar::Bool), location) => {
                    let rest: &[u8] = match byte {
                        b't' => b"rue",
                        b'f' => b"alse",
                        _ => return Err(Self::fail(&location, at, "expected boolean")),
                    };
                    self.literal(rest.to_vec(), ExpectedNext::Scalar, &location);
                }
                Op::Value(Value::Scalar(Scalar::Bytes(limit)), location) => {
                    if byte != b'[' {
                        return Err(Self::fail(&location, at, "expected byte array"));
                    }
                    self.stack.push(Op::Bytes {
                        limit,
                        count: 0,
                        token: Vec::new(),
                        allow_end: true,
                        location,
                    });
                }
                Op::Value(Value::Scalar(scalar), location) => {
                    if byte != b'"' {
                        return Err(Self::fail(&location, at, "expected quoted scalar"));
                    }
                    self.stack.push(Op::String {
                        scalar,
                        token: vec![byte],
                        escape: Escape::None,
                        decoded_bytes: 0,
                        location,
                    });
                }
                Op::String {
                    scalar,
                    mut token,
                    mut escape,
                    mut decoded_bytes,
                    location,
                } => {
                    let limit = match scalar {
                        Scalar::Text(limit) => limit.saturating_mul(6).saturating_add(2),
                        _ => 22,
                    };
                    if token.len() >= limit {
                        return Err(Self::fail(&location, at, "scalar token limit exceeded"));
                    }
                    token.push(byte);
                    if byte == b'"' && matches!(escape, Escape::None) {
                        Self::validate_scalar(scalar, &token, &location, at)?;
                    } else {
                        match escape {
                            Escape::None if byte == b'\\' => escape = Escape::Slash,
                            Escape::None => decoded_bytes += 1,
                            Escape::Slash if byte == b'u' => escape = Escape::Unicode(0, 0),
                            Escape::Slash => {
                                decoded_bytes += 1;
                                escape = Escape::None;
                            }
                            Escape::Unicode(n, value) => {
                                let digit = (byte as char).to_digit(16).ok_or_else(|| {
                                    Self::fail(&location, at, "invalid Unicode escape")
                                })? as u16;
                                let value = value * 16 + digit;
                                if n == 3 {
                                    // Canonical quote_json emits non-control Unicode literally.
                                    if value > 31 {
                                        return Err(Self::fail(
                                            &location,
                                            at,
                                            "noncanonical Unicode escape",
                                        ));
                                    }
                                    decoded_bytes += 1;
                                    escape = Escape::None;
                                } else {
                                    escape = Escape::Unicode(n + 1, value);
                                }
                            }
                        }
                        if let Scalar::Text(limit) = scalar {
                            if decoded_bytes > limit {
                                return Err(Self::fail(
                                    &location,
                                    at,
                                    "string byte limit exceeded",
                                ));
                            }
                        }
                        self.stack.push(Op::String {
                            scalar,
                            token,
                            escape,
                            decoded_bytes,
                            location,
                        });
                    }
                }
                Op::Bytes {
                    limit,
                    mut count,
                    mut token,
                    mut allow_end,
                    location,
                } => {
                    if byte.is_ascii_digit() {
                        if token.is_empty() && count >= limit {
                            return Err(Self::fail(
                                &location,
                                at,
                                "byte array element limit exceeded",
                            ));
                        }
                        if token.len() >= 3 || token.first() == Some(&b'0') {
                            return Err(Self::fail(&location, at, "noncanonical byte element"));
                        }
                        token.push(byte);
                        let value = token
                            .iter()
                            .fold(0u16, |v, b| v * 10 + u16::from(*b - b'0'));
                        if value > 255 {
                            return Err(Self::fail(&location, at, "byte element exceeds u8"));
                        }
                        allow_end = true;
                        self.stack.push(Op::Bytes {
                            limit,
                            count,
                            token,
                            allow_end,
                            location,
                        });
                    } else if byte == b']' && allow_end {
                        // An empty initial array or one completed final element.
                    } else if byte == b',' && !token.is_empty() {
                        count += 1;
                        self.stack.push(Op::Bytes {
                            limit,
                            count,
                            token: Vec::new(),
                            allow_end: false,
                            location,
                        });
                    } else {
                        return Err(Self::fail(
                            &location,
                            at,
                            "expected canonical byte element or delimiter",
                        ));
                    }
                }
            }
            self.refresh();
            return Ok(());
        }
    }
    fn validate_scalar(
        scalar: Scalar,
        token: &[u8],
        location: &str,
        at: usize,
    ) -> Result<(), StreamRefusal> {
        let text: String = serde_json::from_slice(token)
            .map_err(|_| Self::fail(location, at, "invalid scalar JSON string"))?;
        if quote_json(&text).as_bytes() != token {
            return Err(Self::fail(location, at, "noncanonical scalar string"));
        }
        let valid = match scalar {
            Scalar::Text(limit) => text.len() <= limit,
            Scalar::I32 => text
                .parse::<i32>()
                .ok()
                .is_some_and(|v| v.to_string() == text),
            Scalar::I64 => text
                .parse::<i64>()
                .ok()
                .is_some_and(|v| v.to_string() == text),
            Scalar::U8 => text
                .parse::<u8>()
                .ok()
                .is_some_and(|v| v.to_string() == text),
            Scalar::U64 => text
                .parse::<u64>()
                .ok()
                .is_some_and(|v| v.to_string() == text),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(Self::fail(
                location,
                at,
                "scalar range or canonical decimal mismatch",
            ))
        }
    }
}
