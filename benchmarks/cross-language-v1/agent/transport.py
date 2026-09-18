"""The solver-transport seam.

`SolverTransport` is the one interface the orchestrator (`orchestrator.py`)
calls to turn a `SolverRequest` into a `SolverResponse`. Two implementations
exist:

- `replay_transport.ReplayTransport`: deterministic, offline, reads a
  committed fixture. This is what CI and every test in this package actually
  exercises.
- `live_transport.LiveTransport`: a real-provider seam. Declared, never
  exercised here. See its module docstring.

Both raise `budget.BudgetExceededError` or `budget.RetriesExhaustedError`
(never a bare exception) when a declared ceiling is crossed, so the
orchestrator can tell "the transport produced a candidate," "the transport
ran out of budget," and "the transport ran out of retries" apart.
"""
from __future__ import annotations

import abc

from .contracts import SolverRequest, SolverResponse


class SolverTransport(abc.ABC):
    """Abstract seam a concrete transport implements. `complete` is the only
    method the orchestrator calls; everything about how a transport obtains
    its candidate (a fixture file, an HTTP call, anything else) stays behind
    this one method.
    """

    @abc.abstractmethod
    def complete(self, request: SolverRequest) -> SolverResponse:
        """Produce one candidate for `request`, or raise
        `budget.BudgetExceededError` / `budget.RetriesExhaustedError` /
        `CredentialsRequiredError` / `LiveTransportUnexercisedError`.
        """
        raise NotImplementedError


class CredentialsRequiredError(Exception):
    """Raised at construction time by a transport that needs real
    credentials it was not given. Never raised for the replay transport,
    which by design needs none.
    """


class LiveTransportUnexercisedError(Exception):
    """Raised by `LiveTransport.complete` even when credentials were
    supplied: this repository has never executed a real call through this
    seam, and refuses to guess at an unverified wire protocol. See
    `live_transport.py`.
    """
