# Persistent Semantic Cache v1

Status: implemented bounded profile; **HOSTED GREEN** under the
[v0.4.0 release baseline](RELEASE-0.4.0-STATUS.md). Historical local,
authoring-time, ignored, or separately provisioned observations below retain
their narrower scope; public promotion and broader product completion remain
separately gated.

Audience: compiler contributors and hosts managing trusted compiler installations.

This opt-in host store preserves compiler-created checked-module HIR across
processes. A fresh process authenticates the complete private cache, parses its
canonical source again, and rebuilds the linked Project and graph while reusing
checked module HIR. This is actual resolver reuse, with bounded private decoding;
it is not a portable source archive or a general incremental compiler.

## Host surface

`semantic_cache_store::initialize(root)` initializes an existing, empty, dedicated
host directory with an operating-system-generated secret key. `persist(root,
&ProjectFrontendCache)` accepts only opaque compiler-created semantic caches;
there is no public arbitrary-byte signer or raw checked-HIR constructor.
`load(root, expected_entry_digest)` returns a fully replayed semantic cache.
Its `restored_work()` describes the successful warm Project replay.

The explicit CLI adapters are:

```
semaprax semantic-cache-init <store-root>
semaprax semantic-cache-persist <manifest> <store-root>
semaprax semantic-cache-load <store-root> <entry-digest>
semaprax semantic-cache-evict <store-root> <entry-digest>
semaprax semantic-cache-lifecycle <manifest> <empty-store-root>
semaprax semantic-cache-cold-open <manifest>
semaprax semantic-cache-warm-open <manifest> <store-root> <entry-digest>
```

`semantic-cache-cold-open` and `semantic-cache-warm-open` are each one
standalone fresh-process invocation that shares `semantic-cache-lifecycle`'s
first two stages' code path
(`VNextSession::open_with_semantic_cache` / `open_with_retained_semantic_cache`)
but, unlike `lifecycle`, does not bundle persist, refresh, and eviction into
the same process. They exist so an external timer comparing one process
launch of each measures cache state as the only varying input — see
[Measured fresh-process workflow timing](#measured-fresh-process-workflow-timing)
below. A `semantic-cache-warm-open` against a stale or evicted digest fails
closed with `SPX-G308`, the same as `semantic-cache-load`; recovery is an
explicit, separate `semantic-cache-cold-open` call, never an implicit
fallback inside the failed command.

Initialization emits `semaprax.semantic-cache-initialized.v1`; persistence emits
`semaprax.semantic-cache-receipt.v1` with `entry_digest`, `compiler_digest`, and
`payload_bytes`. Neither receipt grants source authority, current-source
admission, or commit approval. Load emits the existing
`semaprax.project-semantic-cache-work.v1` report. Each command can run in a fresh
process using the same compiler executable and host-protected store.

The lifecycle command performs a cold semantic open, exact persistence and
authenticated restored open, unchanged explicit refresh, exact eviction, and a
cold rebuild in one process. Its bounded
`semaprax.semantic-cache-lifecycle.v1` receipt includes each existing compiler
work report plus payload/envelope bytes and exact Project/image/cold-work
equality. It rejects a zero-hit restoration: cold admission must resolve a
nonzero module inventory with zero checked-HIR hits, and restored open plus
refresh must reuse the complete inventory with zero resolutions. Successful
completion leaves only the initialized store key and never changes canonical
source. This count-based telemetry is not elapsed-time, RSS, model-token,
cross-process, crash-recovery, target-execution or publication evidence.

Eviction removes one exact digest-selected entry under the same held-root and
exclusive-lock discipline. It emits
`semaprax.semantic-cache-eviction.v1`, binding the removed digest and envelope
byte count plus the remaining completed-entry count. The operation hashes the
held bytes before unlink, rejects absence or digest disagreement, settles the
directory, and reports post-unlink failures as `SPX-I363` uncertainty. It does
not remove the store key, another entry, canonical source, host policy, or any
publication state. Because eviction does not require the selected envelope to
match the running compiler, a host can remove an obsolete but exactly selected
entry after an upgrade. Persisting an unchanged admitted project again rebuilds
the same deterministic entry; a changed project produces a different entry.

Workspace host policy `semaprax.workspace-host-policy.v5` preserves the v4
fields and requires `semantic_cache_entry`, either null or the closed object
`{ "root": <absolute host path>, "entry_digest": <canonical SHA256> }`.
A selected entry requires both `frontend_cache: true` and `semantic_cache: true`.
Older policy schemas reject this field, including null. Selection happens
before the first frame; RPC parameters cannot select cache files, roots, or
keys. Existing candidate archive and source-commit grants remain separate.

A historical load does not inspect the original source paths. Starting a live
workspace from that cache still authenticates the host-bound manifest and all
current source files. Edited inputs invalidate the affected module and reverse
import closure through the ordinary cache path. A historical cache cannot
restore old source into a live workspace or suppress held-input drift checks.
Deleting the store or explicitly evicting an entry leaves canonical source
intact; explicit cold startup and source-derived rebuild remain available. A
selected corrupt cache fails closed rather than silently falling back to a
differently authenticated state.

## Authentication and trust boundary

The store binds the exact SHA256 of the current executable, package name/version,
OS, architecture, endianness, pointer width, and checked-module compatibility.
Different executables from the same package version are incompatible. The host
must trust its static compiler installation and keep it immutable from process
execution through each operation. Hashing the executable file does not attest
already-loaded instructions, dynamically loaded libraries, or a hostile host.
Same-principal tampering, stolen keys, malicious compiler installations, and
compromised operating systems are outside this boundary.

Each envelope contains `SPXSHC01`, the 32-byte compiler digest, a little-endian
u32 context length and compatibility context, a little-endian u64 payload length,
the payload, and a 32-byte HMAC-SHA256 tag. The MAC input is the domain
`semaprax.semantic-cache-store.authenticated-envelope.v1` followed by NUL and
all envelope bytes preceding the tag. The public entry digest hashes the entire
envelope, including the tag. Reminting that public digest after an edit cannot
replace the secret-key MAC. MAC verification precedes payload-controlled
allocation and private HIR decoding; exact compiler/context binding precedes
adoption.

The private codec covers source AST, complete resolved HIR, cleanup inventories,
cleanup plans, and loan plans. It rejects unknown enum tags and static tokens,
noncanonical map/set ordering, duplicate entries, trailing bytes, excessive
lengths, depth, and allocation accounting. It is not a public deserialization
contract or a way for an agent to submit graph facts as canonical meaning.

After decoding authenticated state, load independently parses/formats every
stored canonical source and rederives each synthetic resolver input, including
imports, declarations, IDs, and spans. Checked reuse requires exact equality.
It reruns HIR validation, cross-file/stub checks, linking, Project-profile
admission, and graph generation, then requires exact stored project/workspace
revisions and graph bytes. Every module must be a checked-HIR hit; unexpected
cold resolution rejects restoration. The work report counts this final warm
build, not the preceding independent source parsing or authentication work.
This does not claim runtime equivalence or target execution.

## Filesystem and resource limits

Supported Unix hosts require an absolute normalized root, held directory-chain
checks, an owner-only 0700 dedicated root, and owner-only 0600 regular single-link
key/entry files. Symlink adoption and implicit key rotation are rejected.
The executable must be a bounded, executable, regular single-link file without
group/other write permission. Held paths, file identities, inventory, key, and
compiler bytes are rechecked around operations. Immutable entry publication
uses the existing exclusive staging/install discipline; no canonical source or
Git reference is written.

The payload is bounded to 128 MiB, envelope overhead to 4096 bytes, store inventory
to 32 entries, and compiler executable to 256 MiB. Private codec limits include
128 MiB allocation accounting, one million nodes, depth 256, and exact EOF.
Existing source, AST, checked-module prebounds and Project limits remain in
force. Accounting is not a peak heap/RSS guarantee; input, decoded state, staged
cache, and rebuilt linked representations may coexist.

`SPX-G304/G305` report private codec grammar/capacity rejection. Store diagnostics
use `SPX-G306` for invalid requests, `SPX-G307` for capacity, `SPX-G308` for
binding/compiler mismatch, and `SPX-G309` for failed MAC authentication.
Filesystem failures retain `SPX-I362`; `SPX-I363` represents publication
uncertainty and must not be presented as proof that no cache entry was installed
or removed.
Ordinary source and Project diagnostics propagate.

## Authored evidence

`tests/semantic_cache_store_cli_v1.rs` authors separate-process warm load with
three checked-HIR hits and zero resolver calls; historical loading after source
edits; live startup admission and unchanged refresh; request-level cache and
commit authority rejection; exact entry eviction, source preservation and
deterministic warm rebuild; explicit cold startup after deletion; reminted
public digest with invalid MAC; the composed five-stage lifecycle receipt and
required cold/warm work profile; exact compiler mismatch; and closed older/new
startup policy validation. The compiler-mismatch case applies only when both
executables satisfy the supported 256 MiB bound.

The same harness additionally proves, for the standalone `cold-open`/`warm-open`
pair: unchanged source gives identical `project_revision`/`image_revision`
between one fresh `cold-open` and one fresh `warm-open` process, with the warm
side landing on the existing three-hit/zero-resolve work profile; a body-only
edit to a module nothing imports (`src/app.spx`) invalidates exactly that
module while its two unedited siblings stay a whole-module checked-HIR hit;
editing the shared provider (`src/core.spx`) invalidates only its own
AST-cache entry (#130/#131: parsing is a pure function of a file's own bytes),
while its importers' checked HIR is still rebuilt because the edit shifts the
imported function's byte span, which their compiler-created synthetic AST
embeds; unaffected functions elsewhere still reuse exact monomorphic HIR; and
a `warm-open` against an
evicted digest fails closed with `SPX-G308` and a following `cold-open`
reproduces the original cold product exactly.

Private codec regressions additionally cover full HIR with nonempty cleanup and
loan plans, canonical reencoding, malformed containers, allocation limits,
unknown tags/tokens, and truncation. Store-local regressions cover private key
initialization, hostile filesystem shapes, and authentication before decoding.
These implemented codec, store and cross-process recovery regressions are
HOSTED GREEN for v0.4.0. The cache can reuse authenticated checked HIR under
this exact private profile; broader cache compatibility remains a separate
requirement. Fresh-process time/memory measurement is now available: see
below.

## Measured fresh-process workflow timing

[`benchmarks/performance-v1/observe-semantic-cache-workflow.py`](../benchmarks/performance-v1/observe-semantic-cache-workflow.py)
times `semantic-cache-cold-open` and `semantic-cache-warm-open` as literal,
independent OS-process launches — genuine cross-process latency, not an
in-process capture — for cold open, warm open on unchanged source, warm open
after a local body edit, warm open after a provider edit, and stale-entry
recovery (a failing warm-open followed by the caller's own cold-open). Every
repetition uses an isolated fixture and store directory, and every subprocess
runs a private read-only single-link compiler copy staged once per invocation
of the script (a live `target/debug/semaprax` fails the store's own
single-link/no-group-write check whenever a concurrent build is relinking it
on a shared checkout, which this script assumes is routine). Wall time is an
outer `time.perf_counter()` around the whole process; peak RSS is parsed from
`/usr/bin/time -l` on macOS or `-v` on Linux and recorded `null` with a
disclosed reason elsewhere. The script does not gate on a quiet host — it
records `host_before`/`host_after` load average and available memory around
every single repetition instead, and refuses to run at all without
`--acknowledge-loaded-host`, so a loaded run can never be mistaken for a quiet
one after the fact.

[`results/semantic-cache-workflow-loaded-host.json`](../benchmarks/performance-v1/results/semantic-cache-workflow-loaded-host.json)
is one recorded run, `n=11` fresh-process repetitions per role, on a shared
11-core macOS host with **other agents building concurrently** (load average
5.0-7.5 throughout the run — not idle, not requested to be idle, and not
comparable to the quiet-host discipline `results/baseline.json` requires) and
an unoptimized `dev`-profile binary (not `release`). Reported as measured,
not as a hosted or release-profile claim:

| role | n | wall seconds (min / median / max) |
| --- | ---: | --- |
| `cold_open` | 11 | 0.037 / 0.038 / 1.042 |
| `warm_open` (unchanged) | 11 | 1.070 / 1.090 / 1.122 |
| `warm_open` (local body edit) | 11 | 1.067 / 1.087 / 1.181 |
| `warm_open` (provider edit) | 11 | 1.073 / 1.106 / 1.190 |
| `stale_warm_open_attempt` (fails closed) | 11 | 0.512 / 0.517 / 0.739 |
| `cold_open_recovery` | 11 | 0.037 / 0.039 / 0.045 |

The dominant shape, on this host and this debug build: a fresh-process warm
open costs roughly **28x** a fresh-process cold open's median, not less, and
recovery from a stale/evicted entry costs the same as an ordinary cold open
(no degraded-fallback penalty). This inverts the naive expectation that a
cache hit is cheaper than no cache, and it is the opposite direction from the
now-resolved `interpreter-prepared-evaluator` trace-collection cost in issue
#85 — there the "prepared" path *was* cheap once trace collection was
isolated; here the persisted-store path is measurably expensive on its own
terms, independent of tracing. The likely cost carriers are the private
envelope's HMAC-SHA256 authentication and the private HIR codec's per-field
validation (`docs/SEMANTIC-CACHE-STORE-V1.md`), both unoptimized in a `dev`
build; this has not been isolated further or measured under `--release`, so
it is reported as an open, disclosed observation and a release-profile
re-measurement is the natural next step (a SPX-AI-032 candidate) rather than
an implementation change made on the strength of this number alone. The one
`cold_open` outlier at 1.042s (max, against a 0.038s median) is disclosed
rather than discarded: it is the first repetition's fixture directory, most
plausibly page-cache/disk warmup contending with concurrent build activity on
this host, not a claim about the operation's typical cost.

Re-run with `python3 benchmarks/performance-v1/observe-semantic-cache-workflow.py
--semaprax <built-binary> --repetitions N --output <path>
--acknowledge-loaded-host`; add `--profile release` (label only — build the
release binary yourself and pass it via `--semaprax`) when reporting a
release-profile number. This is local, single-host evidence; it is not a
hosted, cross-platform, or production-latency claim.
