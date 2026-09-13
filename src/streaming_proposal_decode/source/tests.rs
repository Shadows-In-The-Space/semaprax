use super::*;
use crate::agent_proposal::compile_agent_proposal_schema;
use crate::streaming_proposal_decode::{STREAM_TRAILING, STREAM_UTF8};

const MODULE: &str = "module fixture.source_proposal;\n\n@id(\"fixture.agent.type.proposal\")\nrecord Proposal {\n    @id(\"fixture.agent.type.proposal.note\")\n    note: string,\n}\n\n@id(\"app.main\")\nfn main() -> i64 { 0 }\n";
const RICH_MODULE: &str = "module fixture.source_proposal;\n\n@id(\"fixture.agent.type.proposal\")\nrecord Proposal {\n    @id(\"fixture.agent.type.proposal.note\")\n    note: string,\n    @id(\"fixture.agent.type.proposal.count\")\n    count: i64,\n    @id(\"fixture.agent.type.proposal.ready\")\n    ready: bool,\n    @id(\"fixture.agent.type.proposal.small\")\n    small: u8,\n    @id(\"fixture.agent.type.proposal.size\")\n    size: usize,\n}\n\n@id(\"app.main\")\nfn main() -> i64 { 0 }\n";
const VARIANT_MODULE: &str = "module fixture.source_proposal;\n\n@id(\"fixture.agent.type.proposal\")\nvariant Proposal {\n    @id(\"fixture.agent.type.proposal.accept\")\n    Accept {\n        @id(\"fixture.agent.type.proposal.accept.note\")\n        note: i64,\n    },\n    @id(\"fixture.agent.type.proposal.reject\")\n    Reject {\n        @id(\"fixture.agent.type.proposal.reject.reason\")\n        reason: i64,\n    },\n}\n\n@id(\"app.main\")\nfn main() -> i64 { 0 }\n";
pub(crate) const DEFINITION: &str = "{\"schema\":\"semaprax.agent-definition.v1\",\"agent_id\":\"fixture.agent\",\"types\":[{\"role\":\"task\",\"stable_id\":\"fixture.agent.type.task\"},{\"role\":\"state\",\"stable_id\":\"fixture.agent.type.state\"},{\"role\":\"observation\",\"stable_id\":\"fixture.agent.type.observation\"},{\"role\":\"proposal\",\"stable_id\":\"fixture.agent.type.proposal\"},{\"role\":\"outcome\",\"stable_id\":\"fixture.agent.type.outcome\"},{\"role\":\"result\",\"stable_id\":\"fixture.agent.type.result\"}],\"operations\":[{\"role\":\"initialize\",\"stable_id\":\"fixture.agent.fn.initialize\",\"kind\":\"deterministic\"},{\"role\":\"observe\",\"stable_id\":\"fixture.agent.fn.observe\",\"kind\":\"deterministic\"},{\"role\":\"propose\",\"stable_id\":\"fixture.agent.fn.propose\",\"kind\":\"model\"},{\"role\":\"authorize\",\"stable_id\":\"fixture.agent.fn.authorize\",\"kind\":\"deterministic\"},{\"role\":\"execute\",\"stable_id\":\"fixture.agent.fn.execute\",\"kind\":\"effect\"},{\"role\":\"reduce\",\"stable_id\":\"fixture.agent.fn.reduce\",\"kind\":\"deterministic\"}],\"runtime_v1\":{\"models\":[{\"provider_id\":\"fake.local\",\"model_id\":\"fake-basic\",\"locality\":\"local\",\"quality_tier\":\"basic\",\"tokenizer_id\":\"fake\",\"max_context_tokens\":4096,\"input_usd_microunits_per_million_tokens\":0,\"output_usd_microunits_per_million_tokens\":0,\"capabilities\":[\"text\"]}],\"tools\":[],\"policy\":{\"allowed_provider_ids\":[\"fake.local\"],\"allowed_model_ids\":[\"fake-basic\"],\"required_locality\":\"local_only\",\"minimum_quality_tier\":\"basic\",\"required_model_capabilities\":[\"text\"],\"granted_capabilities\":[],\"allowed_tool_ids\":[]},\"limits\":{\"max_turns\":1,\"max_provider_attempts\":1,\"max_retries_per_turn\":0,\"max_concurrency\":1,\"max_elapsed_ms\":1000,\"max_provider_request_bytes\":65536,\"max_provider_response_bytes\":4096,\"max_stream_chunks\":64,\"max_total_provider_input_bytes\":131072,\"max_total_provider_output_bytes\":8192,\"max_reported_model_input_tokens\":131072,\"max_reported_model_output_tokens\":8192,\"max_usd_microunits\":0,\"max_tool_calls\":0,\"max_tool_arguments_bytes\":4096,\"max_tool_result_bytes\":4096,\"max_total_tool_bytes\":8192,\"max_retained_state_bytes\":131072,\"max_trace_events\":64,\"max_trace_bytes\":131072,\"max_evidence_bytes\":262144,\"max_builder_bytes\":1048576}}}\n";

fn schema() -> CompiledAgentProposalSchema {
    compile_agent_proposal_schema(MODULE, "fixture.source.spx", DEFINITION).unwrap()
}
fn document(schema: &CompiledAgentProposalSchema, note: &str) -> Vec<u8> {
    format!("{{\"schema\":\"semaprax.agent-proposal.v1\",\"agent_id\":\"fixture.agent\",\"proposal_schema_digest\":{},\"value\":{{\"fields\":{{\"fixture.agent.type.proposal.note\":{}}}}}}}\n", crate::diagnostic::quote_json(schema.schema().digest()), crate::diagnostic::quote_json(note)).into_bytes()
}

fn rich_schema() -> CompiledAgentProposalSchema {
    compile_agent_proposal_schema(RICH_MODULE, "fixture.rich_source.spx", DEFINITION).unwrap()
}

fn rich_document(schema: &CompiledAgentProposalSchema, note: &str) -> Vec<u8> {
    format!(
        "{{\"schema\":\"semaprax.agent-proposal.v1\",\"agent_id\":\"fixture.agent\",\"proposal_schema_digest\":{},\"value\":{{\"fields\":{{\"fixture.agent.type.proposal.note\":{},\"fixture.agent.type.proposal.count\":\"7\",\"fixture.agent.type.proposal.ready\":true,\"fixture.agent.type.proposal.small\":\"8\",\"fixture.agent.type.proposal.size\":\"9\"}}}}}}\n",
        crate::diagnostic::quote_json(schema.schema().digest()),
        crate::diagnostic::quote_json(note),
    )
    .into_bytes()
}

fn variant_schema() -> CompiledAgentProposalSchema {
    compile_agent_proposal_schema(VARIANT_MODULE, "fixture.variant_source.spx", DEFINITION).unwrap()
}

fn variant_document(schema: &CompiledAgentProposalSchema) -> Vec<u8> {
    format!(
        "{{\"schema\":\"semaprax.agent-proposal.v1\",\"agent_id\":\"fixture.agent\",\"proposal_schema_digest\":{},\"value\":{{\"case\":\"fixture.agent.type.proposal.accept\",\"fields\":{{\"fixture.agent.type.proposal.accept.note\":\"7\"}}}}}}\n",
        crate::diagnostic::quote_json(schema.schema().digest()),
    )
    .into_bytes()
}

pub(crate) fn fixture_schema() -> CompiledAgentProposalSchema {
    schema()
}
pub(crate) fn fixture_document(schema: &CompiledAgentProposalSchema, note: &str) -> Vec<u8> {
    document(schema, note)
}

#[test]
fn chunked_source_decoder_matches_compiled_schema() {
    let schema = schema();
    let bytes = document(&schema, "café");
    let mut decoder = SourceProposalStreamDecoder::new(&schema);
    for chunk in bytes.chunks(3) {
        assert_eq!(decoder.push(chunk), SourcePushOutcome::Incomplete);
    }
    assert_eq!(
        decoder.finish(),
        SourcePushOutcome::Accepted(schema.decode(std::str::from_utf8(&bytes).unwrap()).unwrap())
    );
}

#[test]
fn source_grammar_agrees_with_the_compiled_record_across_chunks() {
    let schema = rich_schema();
    let bytes = rich_document(&schema, "café");
    let expected = schema.decode(std::str::from_utf8(&bytes).unwrap()).unwrap();
    for width in [1, 2, 7, 31] {
        let mut decoder = SourceProposalStreamDecoder::new(&schema);
        for chunk in bytes.chunks(width) {
            assert_eq!(decoder.push(chunk), SourcePushOutcome::Incomplete);
        }
        assert_eq!(
            decoder.finish(),
            SourcePushOutcome::Accepted(expected.clone())
        );
    }
}

#[test]
fn trailing_data_and_cancellation_are_sticky() {
    let schema = schema();
    let mut decoder = SourceProposalStreamDecoder::new(&schema);
    let mut bytes = document(&schema, "ok");
    bytes.push(b' ');
    assert!(
        matches!(decoder.push(&bytes), SourcePushOutcome::Refused(refusal) if refusal.code == STREAM_TRAILING)
    );
    assert_eq!(decoder.cancel("late"), decoder.finish());
}

#[test]
fn source_grammar_refuses_unknown_duplicate_missing_and_reordered_fields_early() {
    let schema = rich_schema();
    let valid = String::from_utf8(rich_document(&schema, "ok")).unwrap();
    let unknown = valid.replacen("proposal.note", "proposal.unknown", 1);
    let duplicate = valid.replacen(
        "\"fixture.agent.type.proposal.count\":\"7\",",
        "\"fixture.agent.type.proposal.note\":\"again\",\"fixture.agent.type.proposal.count\":\"7\",",
        1,
    );
    let missing = valid.replacen(",\"fixture.agent.type.proposal.size\":\"9\"", "", 1);
    let reordered = valid.replacen(
        "\"fixture.agent.type.proposal.note\":\"ok\",\"fixture.agent.type.proposal.count\":\"7\"",
        "\"fixture.agent.type.proposal.count\":\"7\",\"fixture.agent.type.proposal.note\":\"ok\"",
        1,
    );
    for source in [unknown, duplicate, missing, reordered] {
        let mut decoder = SourceProposalStreamDecoder::new(&schema);
        assert!(
            matches!(decoder.push(source.as_bytes()), SourcePushOutcome::Refused(refusal) if refusal.code == super::super::grammar::STREAM_GRAMMAR),
            "{source} must refuse before finish"
        );
    }
}

#[test]
fn source_grammar_refuses_wrong_case_scalar_and_scalar_bounds_early() {
    let variant = variant_schema();
    let bad_case = String::from_utf8(variant_document(&variant))
        .unwrap()
        .replace("proposal.accept", "proposal.unknown");
    let schema = rich_schema();
    let valid = String::from_utf8(rich_document(&schema, "ok")).unwrap();
    let wrong_type = valid.replacen("\"7\"", "7", 1);
    let noncanonical_integer = valid.replacen("\"8\"", "\"256\"", 1);
    let too_long_text = String::from_utf8(rich_document(&schema, &"a".repeat(4097))).unwrap();
    for (schema, source) in [
        (&variant, bad_case),
        (&schema, wrong_type),
        (&schema, noncanonical_integer),
        (&schema, too_long_text),
    ] {
        let mut decoder = SourceProposalStreamDecoder::new(schema);
        assert!(
            matches!(decoder.push(source.as_bytes()), SourcePushOutcome::Refused(refusal) if refusal.code == super::super::grammar::STREAM_GRAMMAR),
            "{source:?} must refuse before finish"
        );
    }
}

#[test]
fn cancellation_is_sticky_while_the_source_is_incomplete() {
    let schema = schema();
    let mut decoder = SourceProposalStreamDecoder::new(&schema);
    assert_eq!(decoder.push(b"{\"schema\":"), SourcePushOutcome::Incomplete);
    let cancelled = decoder.cancel("caller stopped");
    assert!(
        matches!(cancelled, SourcePushOutcome::Refused(ref refusal) if refusal.code == super::super::STREAM_CANCELLED)
    );
    assert_eq!(decoder.push(b"late"), cancelled);
}

#[test]
fn terminal_lf_then_incomplete_utf8_refuses_without_panicking() {
    let schema = schema();
    let mut decoder = SourceProposalStreamDecoder::new(&schema);
    let bytes = document(&schema, "ok");
    assert_eq!(decoder.push(&bytes), SourcePushOutcome::Incomplete);
    assert_eq!(decoder.push(&[0xc3]), SourcePushOutcome::Incomplete);
    assert!(
        matches!(decoder.finish(), SourcePushOutcome::Refused(refusal) if refusal.code == STREAM_UTF8)
    );
}

#[test]
fn top_level_schema_prefix_refuses_wrong_identity_duplicate_or_reordered_keys_without_finish() {
    let schema = schema();
    let valid = String::from_utf8(document(&schema, "ok")).unwrap();
    let wrong_digest = valid.replacen(schema.schema().digest(), &"0".repeat(64), 1);
    let duplicate = valid.replacen("\"agent_id\"", "\"schema\"", 1);
    for prefix in [
        b"{\"unknown\"".as_slice(),
        b"{\"agent_id\"".as_slice(),
        wrong_digest.as_bytes(),
        duplicate.as_bytes(),
    ] {
        let mut decoder = SourceProposalStreamDecoder::new(&schema);
        assert!(
            matches!(decoder.push(prefix), SourcePushOutcome::Refused(refusal) if refusal.code == super::super::STREAM_SCHEMA_PREFIX),
            "prefix {prefix:?} must refuse before finish"
        );
    }
}
