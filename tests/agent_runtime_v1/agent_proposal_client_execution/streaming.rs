//! Conformance of physically executed generated-client bytes with streaming admission.
use semaprax::agent_proposal::CompiledAgentProposalSchema;
use semaprax::streaming_proposal_decode::{SourceProposalStreamDecoder, SourcePushOutcome};

pub(super) fn check(schema: &CompiledAgentProposalSchema, bytes: &[u8]) {
    let expected = schema.decode(std::str::from_utf8(bytes).unwrap()).unwrap();
    // One-byte delivery splits every UTF-8 sequence, escape, integer and identity.
    // Larger chunks also cross those boundaries at unrelated positions.
    for size in [1, 3, 17, 1024] {
        let mut decoder = SourceProposalStreamDecoder::new(schema);
        for chunk in bytes.chunks(size) {
            assert_eq!(decoder.push(chunk), SourcePushOutcome::Incomplete);
        }
        assert_eq!(
            decoder.finish(),
            SourcePushOutcome::Accepted(expected.clone())
        );
    }
    let text = std::str::from_utf8(bytes).unwrap();
    let key = if text.contains("\"case\":") {
        "\"case\":"
    } else {
        "\"fields\":"
    };
    let hostile = text.replacen(key, "\"unexpected\":", 1);
    assert!(schema.decode(&hostile).is_err());
    for size in [1, 7, 1024] {
        let mut decoder = SourceProposalStreamDecoder::new(schema);
        let mut terminal = None;
        for chunk in hostile.as_bytes().chunks(size) {
            let outcome = decoder.push(chunk);
            if matches!(outcome, SourcePushOutcome::Refused(_)) {
                terminal = Some(outcome);
                break;
            }
            assert_eq!(outcome, SourcePushOutcome::Incomplete);
        }
        let terminal =
            terminal.expect("unknown generated-client value key must refuse during push");
        assert_eq!(decoder.finish(), terminal);
        assert_eq!(decoder.push(bytes), terminal);
    }
}
