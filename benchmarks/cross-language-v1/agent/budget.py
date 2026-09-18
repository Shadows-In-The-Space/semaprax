"""Budget enforcement that fails closed.

`BudgetLedger.charge_attempt` raises the instant an attempt's cumulative
usage would cross any declared ceiling — before the attempt is counted as
applied, and before the orchestrator takes another step. It never clamps,
rounds down, or "continues just this once": the whole point of a recorded
budget (see `contracts.Budget`) is that an Agent-driven run terminates with a
recorded outcome rather than silently running past what was declared.
"""
from __future__ import annotations

from .contracts import Budget, Usage


class BudgetExceededError(Exception):
    """A token or cost ceiling would be crossed. Distinct from
    `RetriesExhaustedError` because the two are different failure shapes an
    orchestrator must report differently: this one means "this attempt would
    cost too much," not "we ran out of attempts."
    """

    def __init__(self, reason: str, usage: Usage, budget: Budget):
        super().__init__(reason)
        self.reason = reason
        self.usage = usage
        self.budget = budget


class RetriesExhaustedError(Exception):
    """The transport's declared retry ceiling was reached without a final
    (successful) attempt.
    """

    def __init__(self, reason: str, usage: Usage, budget: Budget):
        super().__init__(reason)
        self.reason = reason
        self.usage = usage
        self.budget = budget


class BudgetLedger:
    """Accumulates usage against one `Budget` and fails closed.

    `charge_attempt` is the only mutator. On success it commits the new
    totals; on failure it leaves `self.usage` exactly as it was before the
    call, so a caller that catches the exception can still report the usage
    that was actually charged up to (and not including) the attempt that
    tripped the ceiling.
    """

    def __init__(self, budget: Budget):
        self.budget = budget
        self.usage = Usage()

    def charge_attempt(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: float,
        is_retry: bool,
    ) -> None:
        retries_used = self.usage.retries_used + (1 if is_retry else 0)
        if retries_used > self.budget.max_retries:
            raise RetriesExhaustedError(
                f"retry {retries_used} exceeds max_retries={self.budget.max_retries}",
                self.usage,
                self.budget,
            )

        prompt_total = self.usage.prompt_tokens + prompt_tokens
        if prompt_total > self.budget.max_prompt_tokens:
            raise BudgetExceededError(
                f"prompt_tokens {prompt_total} exceeds max_prompt_tokens={self.budget.max_prompt_tokens}",
                self.usage,
                self.budget,
            )

        completion_total = self.usage.completion_tokens + completion_tokens
        if completion_total > self.budget.max_completion_tokens:
            raise BudgetExceededError(
                f"completion_tokens {completion_total} exceeds "
                f"max_completion_tokens={self.budget.max_completion_tokens}",
                self.usage,
                self.budget,
            )

        total = prompt_total + completion_total
        if total > self.budget.max_total_tokens:
            raise BudgetExceededError(
                f"total_tokens {total} exceeds max_total_tokens={self.budget.max_total_tokens}",
                self.usage,
                self.budget,
            )

        cost_total = self.usage.cost_usd + cost_usd
        if cost_total > self.budget.max_cost_usd:
            raise BudgetExceededError(
                f"cost_usd {cost_total:.6f} exceeds max_cost_usd={self.budget.max_cost_usd:.6f}",
                self.usage,
                self.budget,
            )

        self.usage.prompt_tokens = prompt_total
        self.usage.completion_tokens = completion_total
        self.usage.retries_used = retries_used
        self.usage.cost_usd = cost_total
