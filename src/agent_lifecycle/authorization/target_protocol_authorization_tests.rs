use super::*;

fn operation() -> TargetOperation {
    TargetOperation::new(
        "fixture.agent.effect.read",
        "read",
        "fixture.Argument",
        "fixture.Result",
    )
    .unwrap()
}

fn carrier(type_id: &str, payload: &[u8]) -> TypedCarrier {
    TypedCarrier::new(type_id, payload.to_vec()).unwrap()
}

fn limits() -> TargetLimits {
    TargetLimits {
        max_calls: 1,
        max_request_bytes: 4096,
        max_result_bytes: 1024,
        max_total_bytes: 5120,
        max_fuel: 20,
    }
}

fn grant() -> TargetGrant {
    TargetGrant::bind_request(
        AuthorizedRequest {
            binding: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            budget: 10,
            seal: b"seal".to_vec(),
        },
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        None,
        3,
        operation(),
        &carrier("fixture.Argument", b"request"),
    )
}

fn prior_v1_wire(request: &TargetHostRequest) -> Vec<u8> {
    let argument = request.argument.encode();
    let mut bytes = Vec::new();
    frame(&mut bytes, b"semaprax.agent-target-host-request.v1");
    frame(&mut bytes, request.grant_id.as_bytes());
    request.operation.canonical(&mut bytes);
    frame(&mut bytes, &request.turn.to_be_bytes());
    frame(&mut bytes, &request.fuel.to_be_bytes());
    frame(&mut bytes, &argument);
    bytes
}

struct Handler {
    calls: usize,
}

impl TargetHostHandler for Handler {
    fn dispatch(
        &mut self,
        _: &TargetHostRequest,
        sink: &mut TargetResponseSink,
    ) -> Result<(), TargetHostError> {
        self.calls += 1;
        sink.write(&carrier("fixture.Result", b"ok").encode())
            .map_err(|_| TargetHostError::Failed)
    }
}

#[test]
fn serialized_replay_refuses_an_authorization_binding_spliced_from_another_grant() {
    let mut handler = Handler { calls: 0 };
    let mut accounting = TargetAccounting::default();
    let run = dispatch(
        grant(),
        carrier("fixture.Argument", b"request"),
        4,
        limits(),
        &mut accounting,
        &AgentCancellation::new(),
        &mut handler,
    );
    let request = TargetHostRequest {
        grant_id: run.evidence().grant_id.clone(),
        authorization_binding: run.evidence().authorization_binding.clone(),
        operation: operation(),
        turn: 3,
        argument: carrier("fixture.Argument", b"request"),
        fuel: 4,
    };
    let request_wire = request.canonical_wire();
    let evidence = TargetEvidence::decode(&run.evidence().canonical_wire()).unwrap();
    evidence.replay_wire(&request_wire).unwrap();

    // Request v1 did not carry the authorization-binding frame. Its complete
    // legacy wire must fail closed rather than shift fields into a v2 decode.
    let prior_v1_wire = prior_v1_wire(&request);
    assert_eq!(
        evidence.replay_wire(&prior_v1_wire),
        Err(ProtocolError::MalformedRequest),
        "a prior request schema must fail closed rather than shift v2 fields"
    );

    let spliced_request = TargetHostRequest {
        grant_id: request.grant_id.clone(),
        authorization_binding:
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
        operation: operation(),
        turn: 3,
        argument: carrier("fixture.Argument", b"request"),
        fuel: 4,
    };
    assert_eq!(
        evidence.replay_wire(&spliced_request.canonical_wire()),
        Err(ProtocolError::ReplayMismatch),
        "a request cannot substitute the authorization behind an unchanged grant id"
    );

    let mut spliced_evidence = evidence.clone();
    spliced_evidence.authorization_binding = spliced_request.authorization_binding;
    let spliced_evidence = TargetEvidence::decode(&spliced_evidence.canonical_wire()).unwrap();
    assert_eq!(
        spliced_evidence.replay_wire(&request_wire),
        Err(ProtocolError::ReplayMismatch),
        "an observation cannot splice an authorization binding from another grant"
    );
    assert_eq!(
        handler.calls, 1,
        "serialized replay has no host-dispatch authority"
    );
}
