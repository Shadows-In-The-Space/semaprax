"""A real-provider transport. Declared. Never exercised in this repository.

This module exists so the seam (`transport.SolverTransport`) has a second,
non-mock implementation on the roster — the same way `adapters.json` declares
Zero, NTNT, Aver, Vera, Hale, and MoonBit as real rows with an honest
`blocked_reason` rather than omitting them. It is not a working integration
with any provider, and nothing in this repository has ever run it against a
real network endpoint:

- This environment holds no model API credentials, and this change does not
  acquire any. `LiveTransport.__init__` refuses to construct at all without
  an explicit, non-empty `api_key` argument — never an environment-variable
  fallback (`os.environ` does not appear in this module) — so the seam
  cannot be satisfied by ambient authority even by accident.
- Even when a real key *is* supplied, `complete()` still refuses. Writing a
  concrete HTTP request/response mapping for a provider's Messages API that
  has never actually been called from this repository, and shipping it as if
  it were a working capability, is exactly the "untested code path shipped
  as if it were a capability" issue #211's audit calls out. The honest state
  is: this is where that call would go, once a human supplies credentials, a
  network-egress decision, and reviews the wire mapping against a real
  response — recorded in `docs/METHODOLOGY.md` as
  `HUMAN_BLOCKED: model budget and credentials`.

`ReplayTransport` (see `replay_transport.py`) is what every test in this
package, and every CI run, actually exercises.
"""
from __future__ import annotations

from .contracts import SolverRequest, SolverResponse
from .transport import CredentialsRequiredError, LiveTransportUnexercisedError, SolverTransport


class LiveTransport(SolverTransport):
    """Structurally typed seam for a real provider call.

    `provider` and `api_key` are ordinary constructor arguments the caller
    must supply explicitly (from a CLI flag such as `--live-api-key`, itself
    never defaulted from the environment — see `run_agent.py`). There is no
    code path in this class, in `run_agent.py`, or anywhere else in this
    package that reads a credential from `os.environ`.
    """

    def __init__(self, provider: str, api_key: str, endpoint: str = ""):
        if not provider or not provider.strip():
            raise CredentialsRequiredError("LiveTransport requires an explicit, non-empty provider")
        if not api_key or not api_key.strip():
            raise CredentialsRequiredError(
                "LiveTransport refuses to construct without an explicitly supplied API key. "
                "This repository has no ambient credential lookup by design (AGENTS.md: "
                "'Capabilities are explicit. ... no ambient ... secret, key ... authority.'). "
                "Pass a real key via --live-api-key to attempt construction; this transport's "
                "complete() still refuses to run — see this module's docstring."
            )
        self.provider = provider
        self.api_key = api_key
        self.endpoint = endpoint

    def complete(self, request: SolverRequest) -> SolverResponse:
        raise LiveTransportUnexercisedError(
            "LiveTransport.complete() has never been executed against a real network endpoint "
            "in this repository: no credentials and no network access are available here, and "
            "this method deliberately refuses to guess at an unverified wire protocol rather "
            "than ship an untested capability. Implementing and verifying the actual HTTP call "
            "is HUMAN_BLOCKED: model budget and credentials for a live Agent pilot, exactly as "
            "docs/METHODOLOGY.md already records for issue #211's live pilot requirement. "
            f"(provider={self.provider!r}, task={request.task_id!r}, language={request.language!r})"
        )
