# Source live CLI v1

Audience: private host operators and reviewers of the checked source execution route.

Status: **private host implementation with local recorded-transport integration
tests.** This CLI is a host adapter for the existing checked
[source driver and journal](SOURCE-LIVE-JOURNAL-V2.md). It does not add a second
replay engine, provider fallback, candidate publication path, or model-created
authority.

## Exact operator route

Only the unpublished `semaprax-full` binary admits:

```
semaprax-full source-live run CONFIG CHECKPOINT --opencode ABS --scratch EMPTY_ABS
semaprax-full source-live resume CONFIG CHECKPOINT --opencode ABS --scratch EMPTY_ABS
semaprax-full source-live migrate OLD_CONFIG OLD_CHECKPOINT NEW_CONFIG NEW_CHECKPOINT FUNCTION STEPS --opencode ABS --scratch EMPTY_ABS
semaprax-full source-live offline-repair
```

All operands are absolute except the stable migration function identity and
positive checked-evaluator step limit. `run` requires a new, private checkpoint
directory. `resume` requires its existing latest journal. `migrate` accepts a
committed unpriced v2 Suspend or a committed priced v4 Suspend from the
predecessor directory, and writes a fresh or same-claim destination journal.
The private CLI performs one predecessor-to-destination handoff; it does not
offer a general migration-chain command. A v3 predecessor is explicitly
refused by this CLI version; the checked embedding migration API has a separate
A→B→C gate. The executable is the one explicitly chosen OpenCode binary, and
every process attempt uses the fixed
`opencode/muse-spark-1.3-contributor-free` profile without a paid fallback.
Scratch must be a new empty absolute directory for each CLI invocation.

`offline-repair` is a separate fixed, credential-free private demonstration.
It accepts no operands and authenticates only the bundled
`examples/offline-repair-project` Project. It uses the checked Direct Runtime
v2 source loop with two scripted streaming attempts: the first creates a
malformed ephemeral candidate and the second must carry the checked diagnostic
feedback before it can create the bounded `fixture.repair.value` replacement preview. Its
single JSON report contains the candidate digest, source review, semantic
delta, impact summary, model/effect counters and the in-memory source journal.
The command neither writes source nor persists a checkpoint, publishes a
candidate, selects a network provider, accepts a target/path/model operand, or
claims physical recovery. It is local demonstration evidence for the checked
repair path, not a general offline repair interface.

Priced migration requires both predecessor and destination config v2 pricing
with exactly matching work unit, currency, minor-unit exponent and integer
rate. The destination money ceiling may narrow but cannot fall below carried
reservations. The migrated v4 journal retains unknown exposure, observed
charges, overage and the global money ordinal; it never reconstructs them from
the CLI receipt. Unpriced-to-priced and priced-to-unpriced conversion are
refused rather than silently shedding exposure or treating it as zero-priced.

A crash after fresh directory creation but before its first journal ACK can
leave an empty directory. Both `run` (existing directory) and `resume` (no
latest journal) refuse it. An operator may use a different new directory
only after independently establishing that no journal or provider work began;
the CLI does not infer that fact from an empty directory.

`CONFIG` is one canonical JSON object, at most 8192 bytes. Version 1 has exactly these
keys: `schema` (`semaprax.source-live-cli.config.v1`), `manifest`,
`source_path`, `agent_id`, `step_id`, `task_path`, `task_budget`, `read_path`,
`deadline_millis`, `ceiling`, `reservation_units`, `max_iterations`,
`max_stages`, `max_steps_per_stage`, `max_total_steps`, and `response_limit`.
Unknown, duplicate, alternate-encoding, and negative or over-capacity fields
are rejected before journal or provider work. JSON must use exact compact
sorted-key serialization; a single final line feed is accepted. `manifest`,
`task_path`, and `read_path` are absolute host selections; `source_path` is a
relative Project `.spx` selector without `..`. The task and observation files
are bounded to 65,536 bytes each. The observation file is an explicit fixed
read snapshot, returned by the one injected `AgentReadOperation`; it is not a
shell, test runner, candidate editor, or semantic validation tool.

Version 2 is an additive priced route. It uses schema
`semaprax.source-live-cli.config.v2`, retains every v1 key, and requires one
additional exact `pricing` object with `currency` (three uppercase ASCII
letters), `minor_unit_exponent` (`0..=9`), positive integer
`price_per_work_unit_minor`, and nonnegative integer `money_ceiling_minor`.
These are an operator quote in bound integer minor units for the fixed source
work unit, never a provider price lookup, currency conversion, float-cost
parser, or invoice. A v1 document with `pricing`, or a v2 document with a
missing, extra, malformed, zero-price, negative, or noncanonical pricing
field, is refused before checkpoint or provider activity; it cannot downgrade
to the unpriced route.

Version 3 is an additive priced-I/O route. It uses schema
`semaprax.source-live-cli.config.v3`, retains every v2 key and requires one
additional exact `io_limits` object with nonnegative integer
`max_request_bytes`, `max_total_request_bytes`, and
`max_total_response_bytes`. The per-attempt request field is capped at 65,536
bytes and may be zero; the cumulative fields are `u64` ceilings. V3 does not
widen v1/v2 keys, and a missing, extra, malformed, negative or noncanonical
I/O field is refused before a checkpoint or provider call. Its exact
reservation, recovery and migration semantics are in
[Source Live I/O v5](SOURCE-LIVE-IO-V5.md).

The host authenticates the retained Project, selects and checks its Agent
role closure, derives its actual `ProgramRoot`, and derives the proposal
grammar from the compiled source. The read snapshot bytes and fixed model are
hashed into the deployment binding; changing the snapshot on resume changes
the invocation identity and fails journal recovery. The task bytes, budget,
source revision, ProgramRoot, schema, fixed charge, bounds, clock and deadline
are bound by the existing `SourceInvocationBinding`. Neither submitted model
text nor the checkpoint document supplies those host facts. The unit is
`fixed_model_attempt_units.v1`, charged once per acknowledged attempt intent;
provider-reported counters remain optional observations, never billing proof.
For v2, the paired price reservation is also acknowledged before dispatch.
Current OpenCode cost JSON has no bound currency/minor-unit representation, so
the host records explicit `Unknown` charge evidence instead of converting a
float or manufacturing zero cost.

## Latest store, clock and migration claim

The Unix host holds the checkpoint directory by file descriptor and a
nonblocking exclusive advisory lock. It refuses symlinked/nonphysical path
components and non-private directories. A read preflights regular-file type
and byte limit on the opened descriptor; a FIFO or replaced symlink cannot
turn the bounded read into an unbounded wait. Each canonical journal
generation is written to a new file, synced, renamed over the latest document
through the held directory, then the directory is synced before the store
ACK. A failed or ambiguous commit poisons the writer. Recovery loads the
latest authoritative document under the same exclusive lock, validates the
exact independently derived source binding, and restores the existing
cumulative ledger. A store replacement by its owner or a valid rollback of
the latest document cannot be authenticated by hashes alone.

The CLI uses Unix epoch milliseconds as one restart-stable clock domain,
with origin zero for a fresh v2 run and an absolute `deadline_millis` supplied
in CONFIG. A v3 migration's origin is the authenticated predecessor latest
checkpoint's last checked clock floor; repeating the same handoff derives the
same origin from that predecessor terminal. Recovery does not reset that
deadline. A regressed or expired continuation
refuses; an already committed terminal is a read-only receipt and can be
retrieved after expiry with zero model/effect dispatches. The OpenCode
process timeout is no greater than 30 seconds or the invocation time
remaining when this CLI traversal begins. The source clock is checked again
before each attempt and after each settlement; a later child may cross the
absolute deadline, in which case its result is withheld and its committed
reservation remains charged.

Before a v2→v3 migration can evaluate or run the destination, the predecessor
store persists a single handoff claim under its held lock. The claim binds the
checked handoff digest, destination directory and new invocation. The same
destination/handoff may reopen its latest journal; another destination is
refused. A crash after the claim but before destination settlement can leave
the handoff unavailable pending explicit operator reconciliation. This is a
cooperating-CLI single-destination rule, not a distributed transaction or
proof against hostile owner rollback. The destination uses
`prepare_source_live_migration` and the same source journal/driver; checked
migration fuel is acknowledged before the pure evaluator, and the migrated
State is schema-checked before first Observe. No Initialize is repeated.

## Output and scope

A completed unpriced run returns the v1 bounded JSON receipt with terminal status,
invocation, generation, chain, acknowledged model units and stage fuel, and
this traversal's model/effect dispatch counts. Every receipt version also
carries `iterative_evidence`: the compiled reducer's own
`semaprax.agent-iterative-evidence.v2` document (policy, invocation digest,
status, iteration/effect counts, per-stage role/function/outcome/step rows,
authorization bindings, and a terminal-value digest) when this traversal
dispatched fresh work, or `null` on a pure terminal-checkpoint replay that
redispatched nothing. It does not include raw model text, credentials,
provider stderr, or a publication grant. A failure reports its selected
status and last acknowledged counters; the journal remains the reviewable
causal artifact. The CLI never rewrites authoritative `.spx` source or Git
state. Real failed-check observation, semantic candidate preview (source
diff, semantic impact, blind spots), repair feedback, and approval-bound
publication remain issue #116's separate vertical-slice work; the general
`run`/`resume`/`migrate` route is a domain-agnostic Agent-lifecycle host
adapter; it is not itself wired to the candidate-preview machinery that
`offline-repair` demonstrates for its one fixed project. No live provider,
hosted CI, durable power-loss, or exactly-once physical delivery claim
follows from local injected tests.

A completed priced run returns
`semaprax.source-live-cli.receipt.v2` with the same top-level status,
invocation, generation, chain, `committed_model_units`,
`committed_stage_fuel`, `model_dispatches`, and `effect_dispatches`, plus a
`money` object containing exactly `currency`, `minor_unit_exponent`,
`reserved_minor`, `observed_charge_minor`,
`unknown_charge_reservation_minor`, `observed_over_reservation_minor`, and
`remaining_admission_minor`. These values are replay-derived bound
reservations and provider observations. They are neither a reconciled invoice
nor a refund or payment authorization. A priced failure reports the same
acknowledged monetary counters in its error detail. Terminal recovery returns
the bound receipt without another provider call.

The focused `source_live_cli` tests exercise local recorded execution. The
retained-Project fixture sends a recorded OpenCode run/export through the
actual source adapter, then checks terminal resume and changed read, task,
or policy refusal with zero further calls. A second fixture executes checked
Suspend, pure StateB migration, destination completion, terminal recovery,
and competing-destination claim refusal. Store tests cover exclusive locks,
held-directory rename, poisoned writes, symlink/FIFO input refusal, and an
empty fresh directory that neither mode silently resumes. These are local
fixture results, not a live provider or power-loss test.
