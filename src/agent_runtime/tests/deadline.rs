use super::*;

#[test]
fn dispatches_only_positive_remaining_deadlines() {
    struct DeadlineHost {
        probe: FakeProbe,
        attempt: usize,
        provider_deadlines: Rc<std::cell::RefCell<Vec<u64>>>,
        tool_deadlines: Rc<std::cell::RefCell<Vec<u64>>>,
    }

    impl AgentHost for DeadlineHost {
        fn policy_epoch(&self) -> u64 {
            self.probe.policy_epoch()
        }

        fn elapsed_ms(&self) -> u64 {
            self.probe.elapsed_ms()
        }

        fn boundary_probe(&self) -> Box<dyn AgentBoundaryProbe> {
            Box::new(self.probe.clone())
        }

        fn tokenize(&mut self, _: &str, request: &str) -> Option<u64> {
            Some(request.len() as u64)
        }

        fn attempt_provider(
            &mut self,
            _: &str,
            _: &str,
            request: &str,
            remaining_deadline_ms: u64,
            sink: &mut ProviderSink,
        ) -> ProviderAttempt {
            self.provider_deadlines
                .borrow_mut()
                .push(remaining_deadline_ms);
            let response = if self.attempt == 0 {
                tool_action("fixture.read", "{\"query\":\"alpha\"}")
            } else {
                final_action("done")
            };
            self.attempt += 1;
            assert!(sink.push(&response));
            if self.attempt == 1 {
                self.probe.elapsed.set(750);
            }
            ProviderAttempt {
                disposition: ProviderDisposition::Succeeded,
                usage: ProviderUsage::new(request.len() as u64, response.len() as u64, 0),
            }
        }

        fn invoke_tool(&mut self, _: &str, _: &str, _: &str, sink: &mut ToolResultSink) -> bool {
            assert!(sink.push(b"{\"value\":\"alpha\"}"));
            true
        }

        fn invoke_tool_with_deadline(
            &mut self,
            call_id: &str,
            tool_id: &str,
            arguments_json: &str,
            remaining_deadline_ms: u64,
            sink: &mut ToolResultSink,
        ) -> bool {
            self.tool_deadlines.borrow_mut().push(remaining_deadline_ms);
            self.invoke_tool(call_id, tool_id, arguments_json, sink)
        }
    }

    let provider_deadlines = Rc::new(std::cell::RefCell::new(Vec::new()));
    let tool_deadlines = Rc::new(std::cell::RefCell::new(Vec::new()));
    let probe = FakeHost::fixture().probe;
    probe.elapsed.set(400);
    let host = DeadlineHost {
        probe: probe.clone(),
        attempt: 0,
        provider_deadlines: Rc::clone(&provider_deadlines),
        tool_deadlines: Rc::clone(&tool_deadlines),
    };
    let artifact = new_agent(&fixture_profile(), host)
        .run(&fixture_task())
        .unwrap();
    assert_eq!(artifact.status, RunStatus::Completed);
    assert_eq!(&*provider_deadlines.borrow(), &[600, 250]);
    assert_eq!(&*tool_deadlines.borrow(), &[250]);

    let provider_deadlines = Rc::new(std::cell::RefCell::new(Vec::new()));
    let probe = FakeHost::fixture().probe;
    probe.elapsed.set(1000);
    let host = DeadlineHost {
        probe,
        attempt: 0,
        provider_deadlines: Rc::clone(&provider_deadlines),
        tool_deadlines: Rc::new(std::cell::RefCell::new(Vec::new())),
    };
    let artifact = new_agent(&fixture_profile(), host)
        .run(&fixture_task())
        .unwrap();
    assert_eq!(artifact.status, RunStatus::DeadlineExceeded);
    assert!(provider_deadlines.borrow().is_empty());
}

#[test]
fn cancellation_deadline_and_policy_revocation_close_provider_and_tool_sinks() {
    for (fault, status, code) in [
        (BoundaryFault::Cancel, RunStatus::Cancelled, "SPX-I220"),
        (
            BoundaryFault::Deadline,
            RunStatus::DeadlineExceeded,
            "SPX-I221",
        ),
        (BoundaryFault::Revoke, RunStatus::PolicyRejected, "SPX-G207"),
    ] {
        let mut host = ScriptHost::final_only("unreachable");
        host.revoke_after_admission = matches!(fault, BoundaryFault::Revoke);
        let probe = host.probe.clone();
        let cancellation = AgentCancellation::new();
        let provider_calls = Rc::clone(&host.provider_calls);
        let tool_calls = Rc::clone(&host.tool_calls);
        let profile_source = fixture_profile();
        let mut agent = Agent::new(&profile_source, host, cancellation.clone()).unwrap();
        match fault {
            BoundaryFault::Cancel => cancellation.cancel(),
            BoundaryFault::Deadline => probe.elapsed.set(1_000),
            BoundaryFault::Revoke => {}
            BoundaryFault::None => unreachable!(),
        }
        if matches!(fault, BoundaryFault::Cancel) {
            let diagnostics = match agent.run(&fixture_task()) {
                Ok(_) => panic!("pre-effect cancellation produced an artifact"),
                Err(diagnostics) => diagnostics,
            };
            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].code, code);
            assert_eq!(diagnostics[0].message, "Agent Runtime run was cancelled");
        } else {
            let artifact = agent.run(&fixture_task()).unwrap();
            assert!(artifact.status == status);
            assert!(artifact.evidence.contains(code));
        }
        assert_eq!(provider_calls.get(), 0);
        assert_eq!(tool_calls.get(), 0);

        let mut host = ScriptHost::final_only("unreachable");
        host.provider_fault = fault;
        let cancellation = AgentCancellation::new();
        if matches!(fault, BoundaryFault::Cancel) {
            host.provider_fault = BoundaryFault::None;
        }
        let mut agent = Agent::new(&fixture_profile(), host, cancellation.clone()).unwrap();
        if matches!(fault, BoundaryFault::Cancel) {
            cancellation.cancel();
        }
        if matches!(fault, BoundaryFault::Cancel) {
            let diagnostics = match agent.run(&fixture_task()) {
                Ok(_) => panic!("pre-effect cancellation produced an artifact"),
                Err(diagnostics) => diagnostics,
            };
            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].code, code);
        } else {
            let artifact = agent.run(&fixture_task()).unwrap();
            assert!(artifact.status == status);
            assert!(artifact.evidence.contains(code));
            assert!(!artifact.trace.contains("unreachable"));
        }

        let mut host = ScriptHost::final_only("done");
        host.attempts = vec![
            (
                ProviderDisposition::Succeeded,
                vec![tool_action("fixture.read", "{\"query\":\"alpha\"}")],
                ProviderUsage::default(),
            ),
            (
                ProviderDisposition::Succeeded,
                vec![final_action("done")],
                ProviderUsage::default(),
            ),
        ];
        host.tool_fault = fault;
        let cancellation = AgentCancellation::new();
        if matches!(fault, BoundaryFault::Cancel) {
            host.tool_fault = BoundaryFault::None;
        }
        let mut agent = Agent::new(&fixture_profile(), host, cancellation.clone()).unwrap();
        let artifact = if matches!(fault, BoundaryFault::Cancel) {
            // Existing private fault injection cannot access the runtime-owned bit;
            // the public integration corpus exercises cancellation during tool push.
            cancellation.cancel();
            let diagnostics = match agent.run(&fixture_task()) {
                Ok(_) => panic!("pre-effect cancellation produced an artifact"),
                Err(diagnostics) => diagnostics,
            };
            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].code, code);
            continue;
        } else {
            agent.run(&fixture_task()).unwrap()
        };
        assert!(artifact.status == status);
        assert!(artifact.evidence.contains(code));
        assert!(!artifact.trace.contains("\"status\":\"succeeded\",\"usage\":{\"provider_input_bytes\":0,\"provider_output_bytes\":0,\"reported_model_input_tokens\":0,\"reported_model_output_tokens\":0,\"usd_microunits\":0,\"tool_argument_bytes\":0,\"tool_result_bytes\":"));
    }
}
