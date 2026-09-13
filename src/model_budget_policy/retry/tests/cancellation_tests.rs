use super::*;
use crate::provider_adapter_sdk::{AdapterCapabilities, AdapterRefusal};

struct CancellingSafeFailure {
    capabilities: AdapterCapabilities,
    cancellation: AgentCancellation,
}

impl ProviderAdapter for CancellingSafeFailure {
    fn capabilities(&self) -> &AdapterCapabilities {
        &self.capabilities
    }

    fn start(
        &mut self,
        _: &AdapterInvocationCapability,
        _: &AdapterRequest,
    ) -> Result<(), AdapterRefusal> {
        Ok(())
    }

    fn poll(&mut self) -> AdapterPoll {
        self.cancellation.cancel();
        AdapterPoll::Failed {
            failure: ModelFailure::CapacityExceeded,
            attempted_bytes: 0,
        }
    }

    fn cancel(&mut self, _: &str) {}
}

#[test]
fn cancellation_after_poll_prevents_a_zero_byte_safe_failure_retry() {
    let calls = Rc::new(RefCell::new(0usize));
    let count = calls.clone();
    let cancellation = AgentCancellation::new();
    let poll_cancellation = cancellation.clone();
    let mut factory = move |provider: &str| {
        *count.borrow_mut() += 1;
        let mut capabilities = base_capabilities(provider, true);
        capabilities.provider_profile = provider.to_owned();
        capabilities
            .retryable_failure_classes
            .push(AttemptOutcomeClass::ProviderReportedRetryable);
        Ok(Box::new(CancellingSafeFailure {
            capabilities,
            cancellation: poll_cancellation.clone(),
        }) as Box<dyn ProviderAdapter>)
    };
    let clock = StepClock::new(0);
    let mut scheduler = RetryFailoverScheduler::new(
        limits(2, 1, 1),
        ProviderPolicy::new(vec![
            ProviderSlot::authorized("primary"),
            ProviderSlot::authorized("fallback"),
        ]),
        None,
        &clock,
        &cancellation,
        AdapterInvocationCapability::grant("post-poll cancellation regression"),
        &mut factory,
    )
    .unwrap();
    let mut classifier = CapacityIsSafe;
    let mut backoff = NoDelayBackoff;
    let run = scheduler.run_projected(
        &invocation(),
        &request(),
        &plan(),
        &mut classifier,
        &mut backoff,
        None,
        None,
        RetryCursor::FRESH,
        None,
    );
    assert_eq!(
        *calls.borrow(),
        1,
        "cancellation forbids retry and failover"
    );
    assert_eq!(
        run.attempts.len(),
        1,
        "the pre-dispatch reservation remains charged"
    );
    assert!(matches!(
        run.outcome,
        RetryFailoverOutcome::Failed {
            result: AdapterAttemptResult::Failed {
                classification: AttemptOutcomeClass::Uncertain,
                failure: Some(ModelFailure::Cancelled),
                attempted_bytes: 0,
                ..
            },
            ..
        }
    ));
}
