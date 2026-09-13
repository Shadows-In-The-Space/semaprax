use super::*;
use std::cell::Cell;
use std::rc::Rc;

struct Clock(Rc<Cell<i64>>);
impl InvocationClock for Clock {
    fn now_millis(&self) -> i64 {
        self.0.get()
    }
}
struct BoundaryProbe {
    inner: Probe,
    cancellation: AgentCancellation,
    now: Rc<Cell<i64>>,
    cancel: bool,
}
impl ProviderAdapter for BoundaryProbe {
    fn capabilities(&self) -> &AdapterCapabilities {
        self.inner.capabilities()
    }
    fn start(
        &mut self,
        cap: &AdapterInvocationCapability,
        request: &AdapterRequest,
    ) -> Result<(), AdapterRefusal> {
        self.inner.start(cap, request)
    }
    fn poll(&mut self) -> AdapterPoll {
        let result = self.inner.poll();
        if matches!(result, AdapterPoll::Settled(_)) {
            if self.cancel {
                self.cancellation.cancel();
            } else {
                self.now.set(10);
            }
        }
        result
    }
    fn cancel(&mut self, reason: &str) {
        self.inner.cancel(reason);
    }
}
#[test]
fn cancellation_and_deadline_during_settlement_prevent_publication() {
    let schema = schema();
    let bytes = document(&schema);
    for cancel in [true, false] {
        let cancellation = AgentCancellation::new();
        let now = Rc::new(Cell::new(0));
        let clock = Clock(now.clone());
        let mut adapter = BoundaryProbe {
            inner: Probe::new(vec![
                AdapterPoll::Event(AdapterEvent::Delta(bytes.clone())),
                AdapterPoll::Event(AdapterEvent::Completed),
                AdapterPoll::Settled(AdapterSettlement {
                    response_bytes: bytes.clone(),
                    usage: AdapterUsage {
                        tokens_in: None,
                        tokens_out: None,
                        cost_micros: None,
                    },
                }),
            ]),
            cancellation: cancellation.clone(),
            now,
            cancel,
        };
        let result = StreamingModelHandler::new(
            &mut adapter,
            AdapterInvocationCapability::grant("local boundary test"),
            &schema,
        )
        .with_cancellation_and_deadline(&cancellation, &clock, 10)
        .invoke(
            &ModelInvokeCapability::grant("local boundary test"),
            &request(&schema),
        );
        assert_eq!(
            result,
            ModelInvocationOutcome::Failed {
                failure: if cancel {
                    ModelFailure::Cancelled
                } else {
                    ModelFailure::Timeout
                },
                attempted_bytes: bytes.len(),
            }
        );
        assert_eq!(adapter.inner.starts, 1);
        assert_eq!(adapter.inner.polls, 3);
        assert_eq!(adapter.inner.cancels, 1);
    }
}
