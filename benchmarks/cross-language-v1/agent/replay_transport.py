"""Deterministic, offline replay transport.

Reads one committed JSON fixture describing a scripted attempt sequence and
replays it verbatim: no network call, no credentials, no clock, no random
number generator. Given the same fixture and the same `SolverRequest`, two
runs — on this machine or any other — produce byte-identical transcripts and
usage.

A fixture is **not** a recorded real-model transcript. Nothing in this
repository has ever called a real model: see `live_transport.py` and
`docs/METHODOLOGY.md`. A fixture is a hand-authored script that stands in for
one, the same way `tests/documentation/cross_language_benchmark_suite.rs`'s
`MockLanguage` stands in for a real language toolchain to pin the harness's
own logic. Its purpose is to exercise every step of the driver path —
prompt construction, retry accounting, budget enforcement, transcript
capture, and (when it reaches that far) scoring — not to claim a measured
model outcome.

Fixture schema (`benchmark.cross_language.agent.replay_fixture.v1`):

    {
      "schema": "benchmark.cross_language.agent.replay_fixture.v1",
      "attempts": [
        {
          "attempt": 1,
          "kind": "retryable_error" | "final",
          "prompt_tokens": <int>, "completion_tokens": <int>, "cost_usd": <float>,
          "response_text": "<free text, becomes part of the transcript>",
          "candidate_files": {"<relative path>": "<file content>"}   # only for "final"
        },
        ...
      ]
    }

Attempts are replayed in list order. A `"retryable_error"` attempt is
charged against the budget and retry ceiling and then the next attempt is
tried; a `"final"` attempt's `candidate_files` become the `SolverResponse`.
If the fixture's attempt list is exhausted without a `"final"` attempt,
`RetriesExhaustedError` is raised (the fixture itself declared no successful
outcome, which is a legitimate thing to test).
"""
from __future__ import annotations

import json
import pathlib

from .budget import BudgetLedger, RetriesExhaustedError
from .contracts import SolverRequest, SolverResponse, TranscriptEntry
from .transport import SolverTransport

FIXTURE_SCHEMA = "benchmark.cross_language.agent.replay_fixture.v1"


class ReplayTransport(SolverTransport):
    """Loads one fixture file at construction time and replays it for every
    `complete` call. `fixture_path` is an explicit constructor argument —
    never derived from an environment variable or a hidden default — so the
    exact recorded script a run replayed is always named in the caller's own
    code or CLI invocation.
    """

    def __init__(self, fixture_path):
        self.fixture_path = pathlib.Path(fixture_path)
        document = json.loads(self.fixture_path.read_text())
        if document.get("schema") != FIXTURE_SCHEMA:
            raise ValueError(
                f"{self.fixture_path} declares schema {document.get('schema')!r}, "
                f"expected {FIXTURE_SCHEMA!r}"
            )
        self.attempts = document["attempts"]

    def complete(self, request: SolverRequest) -> SolverResponse:
        ledger = BudgetLedger(request.budget)
        transcript = []
        for row in self.attempts:
            is_retry = row["attempt"] > 1
            prompt_entry = TranscriptEntry(
                attempt=row["attempt"],
                role="prompt",
                kind=row["kind"],
                content=request.prompt,
                prompt_tokens=row["prompt_tokens"],
            )
            response_entry = TranscriptEntry(
                attempt=row["attempt"],
                role="response",
                kind=row["kind"],
                content=row["response_text"],
                completion_tokens=row["completion_tokens"],
                cost_usd=row["cost_usd"],
            )
            # Charge before recording as applied: on a raised
            # BudgetExceededError/RetriesExhaustedError the ledger's usage
            # reflects only what was actually applied prior to this attempt,
            # and the caller can still see what was attempted via the
            # exception's own transcript attribute, set below.
            try:
                ledger.charge_attempt(
                    prompt_tokens=row["prompt_tokens"],
                    completion_tokens=row["completion_tokens"],
                    cost_usd=row["cost_usd"],
                    is_retry=is_retry,
                )
            except (RetriesExhaustedError,) as error:
                error.transcript = transcript + [prompt_entry, response_entry]
                raise
            except Exception as error:  # BudgetExceededError, from .budget
                error.transcript = transcript + [prompt_entry, response_entry]
                raise
            transcript.append(prompt_entry)
            transcript.append(response_entry)
            if row["kind"] == "final":
                return SolverResponse(
                    candidate_files=dict(row["candidate_files"]),
                    usage=ledger.usage,
                    transcript=transcript,
                )
        error = RetriesExhaustedError(
            f"fixture {self.fixture_path} exhausted {len(self.attempts)} attempt(s) "
            "without a final attempt",
            ledger.usage,
            request.budget,
        )
        error.transcript = transcript
        raise error
