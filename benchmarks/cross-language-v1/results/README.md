# Results

No result document is committed here yet, deliberately.

A `benchmark.cross_language.v1` document produced on this development host
would carry a correct pass/fail outcome, correct provenance, and a correct
digest — the harness's own tests confirm that — but this host runs many
concurrent build/test lanes at once, and any future schema version's timing
field would be measuring contention if captured here. See
[`../docs/METHODOLOGY.md`](../docs/METHODOLOGY.md#no-timing-and-why-this-is-not-a-gap-being-papered-over)
for the full reasoning and what a quiet-host run must do before a result
belongs in this directory.

When a real run is recorded here, name it for the revision it measured
(e.g. `results/<short-commit>.json`) and render it to Markdown the way
`benchmarks/performance-v1/results/baseline.md` does, rather than
overwriting a fixed `baseline.json` silently.

The same discipline applies, doubly, to a `benchmark.cross_language.agent.v1`
document produced through `../agent/`: no such document belongs here either,
for the contention reason above **and** because no run through that seam has
ever called a real model — every one so far used the deterministic replay
transport against a hand-authored fixture (see `../agent/README.md`'s
Non-claims). A real Agent-pilot result belongs here only once a human has
supplied model credentials, run `../agent/live_transport.py` for real, and
the resulting document has been produced on a quiet host under this
directory's existing rule.
