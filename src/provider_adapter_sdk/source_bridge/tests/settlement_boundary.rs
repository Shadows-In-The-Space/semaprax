use super::*;
use std::cell::Cell;
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
fn source_cancellation_and_deadline_during_settlement_prevent_publication() {
    let schema = fixture_schema();
    let bytes = fixture_document(&schema, "ok");
    for cancel in [true, false] {
        let cancellation = AgentCancellation::new();
        let now = Rc::new(Cell::new(0));
        let clock = Clock(now.clone());
        let counts = Rc::new(RefCell::new(Counts::default()));
        let mut caps = base_capabilities("source-test", true);
        caps.max_request_bytes = MAX_STREAM_BYTES;
        let mut factory = || -> Box<dyn ProviderAdapter> {
            Box::new(BoundaryProbe {
                inner: Probe {
                    counts: counts.clone(),
                    caps: caps.clone(),
                    script: vec![
                        AdapterPoll::Event(AdapterEvent::Delta(bytes.clone())),
                        AdapterPoll::Event(AdapterEvent::Completed),
                        AdapterPoll::Settled(AdapterSettlement {
                            response_bytes: bytes.clone(),
                            usage: usage(1, 1, 1),
                        }),
                    ]
                    .into(),
                },
                cancellation: cancellation.clone(),
                now: now.clone(),
                cancel,
            })
        };
        let task = task();
        let mut source = StreamingSourceProposalAdapter::new(&mut factory, capability(), &schema)
            .with_cancellation_and_deadline(&cancellation, &clock, 10);
        let result = source.propose(request(&task, &schema)).unwrap_err();
        assert_eq!(
            result[0].code,
            if cancel {
                "source.adapter_cancelled"
            } else {
                "source.adapter_timeout"
            }
        );
        assert_eq!(counts.borrow().requests.len(), 1);
        assert_eq!(counts.borrow().polls, 3);
        assert_eq!(counts.borrow().cancels, 1);
    }
}
