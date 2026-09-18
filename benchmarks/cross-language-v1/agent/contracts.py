"""Explicit, recorded data shapes for the agent-driver seam.

Every field a solver request carries here is something the caller must state
outright: there is no `os.environ.get(...)` anywhere in this module, and none
is permitted to be added — a model API key or provider name read implicitly
from the environment deep inside the harness is exactly the ambient-authority
pattern `AGENTS.md` prohibits ("Capabilities are explicit. Compiler and
generated code gain no ambient filesystem, process, network, home, secret,
key, wallet, or signing authority."). The same discipline applies to this
benchmark harness's own model authority.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ModelIdentity:
    """A model identity is a provider, an exact model name, and an exact
    revision/snapshot label. No field may be a mutable alias: issue #211
    rules out "model aliases" the same way it rules out `latest` dependency
    selectors, and `revision` exists specifically so `model` alone (e.g.
    "claude", "gpt") can never stand in for a pinned snapshot.
    """

    provider: str
    model: str
    revision: str

    def __post_init__(self) -> None:
        for name, value in (("provider", self.provider), ("model", self.model), ("revision", self.revision)):
            if not value or not value.strip():
                raise ValueError(f"ModelIdentity.{name} must be a non-empty, explicit value")
            if value.strip().lower() in {"latest", "@main", "@master", "head"}:
                raise ValueError(f"ModelIdentity.{name} must not be a mutable alias: {value!r}")

    def to_dict(self) -> dict:
        return {"provider": self.provider, "model": self.model, "revision": self.revision}


@dataclass(frozen=True)
class SamplingParams:
    """Sampling is explicit and seeded so a replayed run is reproducible."""

    temperature: float
    top_p: float
    seed: int
    max_output_tokens: int

    def to_dict(self) -> dict:
        return {
            "temperature": self.temperature,
            "top_p": self.top_p,
            "seed": self.seed,
            "max_output_tokens": self.max_output_tokens,
        }


@dataclass(frozen=True)
class PricingRates:
    """Explicit per-1K-token prices the caller supplies, so a cost figure is
    never looked up from an ambient, mutable pricing table inside the
    harness. `0.0`/`0.0` is a legitimate explicit choice for a fixture that
    does not care about cost.
    """

    input_usd_per_1k: float = 0.0
    output_usd_per_1k: float = 0.0

    def cost_for(self, prompt_tokens: int, completion_tokens: int) -> float:
        return (prompt_tokens / 1000.0) * self.input_usd_per_1k + (
            completion_tokens / 1000.0
        ) * self.output_usd_per_1k

    def to_dict(self) -> dict:
        return {"input_usd_per_1k": self.input_usd_per_1k, "output_usd_per_1k": self.output_usd_per_1k}


@dataclass(frozen=True)
class Budget:
    """Every ceiling a run must respect, supplied by the caller. There is no
    default budget: an orchestrator that forgot to pass one fails to
    construct a request at all, rather than silently running unbounded.
    """

    max_prompt_tokens: int
    max_completion_tokens: int
    max_total_tokens: int
    max_retries: int
    max_cost_usd: float

    def to_dict(self) -> dict:
        return {
            "max_prompt_tokens": self.max_prompt_tokens,
            "max_completion_tokens": self.max_completion_tokens,
            "max_total_tokens": self.max_total_tokens,
            "max_retries": self.max_retries,
            "max_cost_usd": self.max_cost_usd,
        }


@dataclass
class Usage:
    """Cumulative usage charged so far. Mutated only through `BudgetLedger`."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    retries_used: int = 0
    cost_usd: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def to_dict(self) -> dict:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "retries_used": self.retries_used,
            "cost_usd": self.cost_usd,
        }


@dataclass(frozen=True)
class TranscriptEntry:
    """One recorded attempt. `content` is kept (these fixtures are small) so
    the transcript is directly auditable; `digest` is bound into the run's
    overall provenance so a transcript cannot be edited after the fact
    without changing the identity a reader checks it against.
    """

    attempt: int
    role: str  # "prompt" or "response"
    kind: str  # "retryable_error" or "final", meaningful for role="response"
    content: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0

    @property
    def digest(self) -> str:
        return sha256_text(f"{self.attempt}\0{self.role}\0{self.kind}\0{self.content}")

    def to_dict(self) -> dict:
        return {
            "attempt": self.attempt,
            "role": self.role,
            "kind": self.kind,
            "digest": self.digest,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cost_usd": self.cost_usd,
        }


def transcript_digest(entries: list) -> str:
    """One digest over an ordered transcript, order-sensitive (unlike
    `run.py::digest_tree`, which is deliberately order-independent over a
    file set): a transcript's order is part of its meaning.
    """
    return sha256_text("\n".join(entry.digest for entry in entries))


@dataclass(frozen=True)
class SolverRequest:
    """Everything a transport needs to produce one candidate, and nothing it
    can obtain any other way. `prompt` is fully materialized text (see
    `prompts.py`), not a path or a template the transport must resolve
    itself, so the exact bytes sent are always known and digestible.
    """

    task_id: str
    language: str
    prompt: str
    model: ModelIdentity
    sampling: SamplingParams
    budget: Budget
    pricing: PricingRates = field(default_factory=PricingRates)

    @property
    def prompt_digest(self) -> str:
        return sha256_text(self.prompt)

    def to_dict(self) -> dict:
        return {
            "task": self.task_id,
            "language": self.language,
            "model": self.model.to_dict(),
            "sampling": self.sampling.to_dict(),
            "budget": self.budget.to_dict(),
            "pricing": self.pricing.to_dict(),
            "prompt_digest": self.prompt_digest,
        }


@dataclass(frozen=True)
class SolverResponse:
    """A transport's successful outcome: the files a solver produced, the
    usage it cost, and the transcript that produced them.
    """

    candidate_files: dict
    usage: Usage
    transcript: list

    @property
    def transcript_digest(self) -> str:
        return transcript_digest(self.transcript)
