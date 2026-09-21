use super::*;

// Deterministic capability fixture only; never a production entropy provider.
struct FixedEntropy {
    bytes: Vec<u8>,
    offset: usize,
    fail: bool,
}

impl FixedEntropy {
    fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            offset: 0,
            fail: false,
        }
    }
}

impl TraceEntropyCapability for FixedEntropy {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), TraceContextError> {
        if self.fail || self.offset + destination.len() > self.bytes.len() {
            return Err(TraceContextError::EntropyUnavailable);
        }
        destination.copy_from_slice(&self.bytes[self.offset..self.offset + destination.len()]);
        self.offset += destination.len();
        Ok(())
    }
}

#[test]
fn fresh_context_consumes_exact_entropy_and_sets_random_flag() {
    let mut entropy = FixedEntropy::new((1..=24).collect::<Vec<_>>());
    let context = TraceContext::fresh(&mut entropy, true).unwrap();
    assert_eq!(entropy.offset, 24);
    assert_eq!(
        context.traceparent(),
        "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-03"
    );
    assert!(context.sampled());
    assert!(context.random_trace_id());
    assert_eq!(context.parent_span_id(), None);
}

#[test]
fn inbound_context_preserves_trace_flags_and_replaces_parent() {
    let mut entropy = FixedEntropy::new([0x33; 8]);
    let context = TraceContext::from_traceparent(
        "00-11111111111111111111111111111111-2222222222222222-01",
        &mut entropy,
    )
    .unwrap();
    assert_eq!(context.trace_id(), "11111111111111111111111111111111");
    assert_eq!(context.span_id(), "3333333333333333");
    assert_eq!(
        context.parent_span_id().as_deref(),
        Some("2222222222222222")
    );
    assert_eq!(
        context.traceparent(),
        "00-11111111111111111111111111111111-3333333333333333-01"
    );
    assert!(context.sampled());
    assert!(!context.random_trace_id());
}

#[test]
fn child_preserves_trace_and_uses_current_span_as_parent() {
    let mut root_entropy = FixedEntropy::new([0x44; 24]);
    let root = TraceContext::fresh(&mut root_entropy, false).unwrap();
    let mut child_entropy = FixedEntropy::new([0x55; 8]);
    let child = root.child(&mut child_entropy).unwrap();
    assert_eq!(child.trace_id(), root.trace_id());
    assert_eq!(child.parent_span_id(), Some(root.span_id()));
    assert_eq!(child.span_id(), "5555555555555555");
    assert!(!child.sampled());
    assert!(child.random_trace_id());
}

#[test]
fn completed_span_is_bound_to_the_typed_context() {
    let mut entropy = FixedEntropy::new([0x66; 24]);
    let context = TraceContext::fresh(&mut entropy, false).unwrap();
    let span = super::super::SpanExport::from_trace_context(
        &context,
        "checkout".into(),
        17,
        super::super::SpanStatus::Ok,
        Vec::new(),
    );
    assert_eq!(span.trace_id, context.trace_id());
    assert_eq!(span.span_id, context.span_id());
    assert_eq!(span.parent_span_id, None);
    assert_eq!(span.name, "checkout");
    assert_eq!(span.duration_micros, 17);
}

#[test]
fn hostile_traceparents_fail_closed() {
    let cases = [
        "00-11111111111111111111111111111111-2222222222222222-05",
        "00-00000000000000000000000000000000-2222222222222222-01",
        "00-11111111111111111111111111111111-0000000000000000-01",
        "00-11111111111111111111111111111111-2222222222222222-0A",
        "00_11111111111111111111111111111111-2222222222222222-01",
        "00-11111111111111111111111111111111-2222222222222222-01-extra",
    ];
    for header in cases {
        let mut entropy = FixedEntropy::new([0x33; 8]);
        assert!(TraceContext::from_traceparent(header, &mut entropy).is_err());
        assert_eq!(entropy.offset, 0);
    }
    let mut entropy = FixedEntropy::new([0x33; 8]);
    assert_eq!(
        TraceContext::from_traceparent(
            "01-11111111111111111111111111111111-2222222222222222-01",
            &mut entropy
        ),
        Err(TraceContextError::UnsupportedVersion)
    );
}

#[test]
fn entropy_failure_zero_and_collision_refuse() {
    let mut failed = FixedEntropy {
        bytes: Vec::new(),
        offset: 0,
        fail: true,
    };
    assert_eq!(
        TraceContext::fresh(&mut failed, false),
        Err(TraceContextError::EntropyUnavailable)
    );
    let mut zero = FixedEntropy::new([0; 24]);
    assert_eq!(
        TraceContext::fresh(&mut zero, false),
        Err(TraceContextError::ZeroIdentifier)
    );
    let mut collision = FixedEntropy::new([0x22; 8]);
    assert_eq!(
        TraceContext::from_traceparent(
            "00-11111111111111111111111111111111-2222222222222222-01",
            &mut collision
        ),
        Err(TraceContextError::IdentifierCollision)
    );
}

#[test]
fn tracestate_admission_preserves_opaque_values_and_canonicalizes_member_ows() {
    let state = TraceState::parse("  rojo=active  ,\tcongo= opaque value\t").unwrap();
    assert_eq!(state.member_count(), 2);
    assert_eq!(state.as_header_value(), "rojo=active,congo= opaque value");

    let mut entropy = FixedEntropy::new([0x77; 8]);
    let (context, admitted) = TraceContext::from_headers(
        "00-11111111111111111111111111111111-2222222222222222-01",
        Some("rojo=active,congo= opaque value"),
        &mut entropy,
    )
    .unwrap();
    assert_eq!(
        context.parent_span_id().as_deref(),
        Some("2222222222222222")
    );
    assert_eq!(
        admitted.unwrap().as_header_value(),
        "rojo=active,congo= opaque value"
    );
}

#[test]
fn tracestate_hostile_inputs_are_bounded_and_unpaired_parent_fails_closed() {
    let too_many = (0..=MAX_TRACESTATE_MEMBERS)
        .map(|index| format!("v{index}=x"))
        .collect::<Vec<_>>()
        .join(",");
    let too_long = format!("v={}", "x".repeat(MAX_TRACESTATE_BYTES));
    let overlong_key = format!("a{}=x", "a".repeat(MAX_TRACESTATE_MEMBER_BYTES));
    let overlong_value = format!("v={}", "x".repeat(MAX_TRACESTATE_MEMBER_BYTES + 1));
    let cases = [
        ("Vendor=x", TraceStateError::InvalidKey),
        ("v=x=y", TraceStateError::InvalidValue),
        ("v=x,v=y", TraceStateError::DuplicateKey),
        ("v=x\n", TraceStateError::InvalidValue),
        (&too_many, TraceStateError::TooManyMembers),
        (&too_long, TraceStateError::TooLong),
        (&overlong_key, TraceStateError::InvalidKey),
        (&overlong_value, TraceStateError::InvalidValue),
    ];
    for (input, expected) in cases {
        assert_eq!(TraceState::parse(input), Err(expected), "{input:?}");
    }

    assert_eq!(TraceState::parse("").unwrap().member_count(), 0);
    assert_eq!(
        TraceState::parse("rojo=x, ,\t,congo=y")
            .unwrap()
            .as_header_value(),
        "rojo=x,congo=y"
    );

    let mut entropy = FixedEntropy::new([0x88; 8]);
    let (context, state) = TraceContext::from_headers(
        "00-11111111111111111111111111111111-2222222222222222-01",
        Some("v=x,v=y"),
        &mut entropy,
    )
    .unwrap();
    assert_eq!(
        context.parent_span_id().as_deref(),
        Some("2222222222222222")
    );
    assert!(state.is_none(), "invalid vendor state must be discarded");
    assert_eq!(entropy.offset, 8);

    let mut invalid_parent_entropy = FixedEntropy::new([0x99; 8]);
    assert_eq!(
        TraceContext::from_headers(
            "not-a-traceparent",
            Some("v=x,v=y"),
            &mut invalid_parent_entropy
        ),
        Err(TraceContextError::Malformed)
    );
    assert_eq!(invalid_parent_entropy.offset, 0);
}
