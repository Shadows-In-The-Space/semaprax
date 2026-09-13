use super::*;
use crate::provider_adapter_sdk::{AdapterInvocationCapability, AdapterRequest, ProviderAdapter};
struct NoTransport;
impl HostHttpStreamTransport for NoTransport {
    fn start(
        &mut self,
        _: ProviderHttpRequest,
    ) -> Result<Box<dyn HostHttpStream>, TransportFailure> {
        panic!("invalid configuration reached host transport");
    }
}
#[test]
fn invalid_model_and_token_bounds_refuse_before_host_access() {
    for (model, tokens) in [
        (String::new(), 1),
        ("x".repeat(257), 1),
        ("model".into(), 0),
        ("model".into(), 1_048_577),
    ] {
        let request = AdapterRequest {
            request_bytes: b"prompt".to_vec(),
            max_response_bytes: 128,
        };
        let cap = AdapterInvocationCapability::grant("local no-dispatch test");
        assert!(
            OpenAiResponsesAdapter::new(model.clone(), tokens, Box::new(NoTransport))
                .start(&cap, &request)
                .is_err()
        );
        assert!(
            AnthropicMessagesAdapter::new(model, tokens, Box::new(NoTransport))
                .start(&cap, &request)
                .is_err()
        );
    }
}
