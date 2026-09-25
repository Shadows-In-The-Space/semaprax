# Language-native Agent syntax v1

Status: implemented bounded profile; **HOSTED GREEN** under the
[v0.4.0 release baseline](RELEASE-0.4.0-STATUS.md). Historical local,
authoring-time, ignored, device/simulator, or separately provisioned evidence
below retains its narrower scope; public promotion, registry publication and
broader product completion remain separately gated.

Audience: language users, compiler contributors, and Agent-system reviewers.

An admitted declaration has this closed shape:

```semaprax
@id("example.agent")
agent Example {
    types {
        @id("example.agent.type.task")
        type task;
        @id("example.agent.type.state")
        type state;
        @id("example.agent.type.observation")
        type observation;
        @id("example.agent.type.proposal")
        type proposal;
        @id("example.agent.type.outcome")
        type outcome;
        @id("example.agent.type.result")
        type result;
    }
    operations {
        @id("example.agent.fn.initialize")
        fn initialize;
        @id("example.agent.fn.observe")
        fn observe;
        @id("example.agent.fn.propose")
        model fn propose;
        @id("example.agent.fn.authorize")
        fn authorize;
        @id("example.agent.fn.execute")
        effect fn execute;
        @id("example.agent.fn.reduce")
        fn reduce;
    }
    runtime_v1 {
        canonical_json "<exact AgentDefinition v1 runtime_v1 object JSON>";
    }
}
```

All thirteen IDs are explicit and locally unique. Roles occur once in this
order. Plain `fn` is `deterministic`; only `propose` is `model fn` and only
`execute` is `effect fn`. Decoded `canonical_json` is capped at 1,310,720
bytes; formatting escapes the source string without changing decoded bytes.

The parser diagnostic `SPX-P124` owns missing identities, duplicate local
identities, wrong role order/names, a non-string compatibility value, and an
over-bound compatibility value. Ordinary missing-token diagnostics remain
`SPX-P104`/`SPX-P106`.

The AST retains exact IDs, closed role/kind enums, decoded runtime JSON, and
spans. Later semantics must check project-wide ID collisions, build canonical
AgentDefinition v1 JSON, and re-admit it. This syntax slice claims no runtime
JSON validation, HIR/graph integration, execution, authority, or backend support.
