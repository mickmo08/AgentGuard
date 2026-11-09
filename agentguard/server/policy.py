"""Policy engine.

Semantics (chosen to be safe and order-independent):

1. Rate limits are checked first. A tripped limit blocks the action.
2. Every rule whose agent pattern, action pattern and conditions all match is
   collected. The most restrictive decision wins: block > review > allow.
   Rule order in the file therefore never weakens a decision.
3. If no rule matches, the configured default applies (block unless changed).

Conditions compare action params against literal values. A condition on a
missing param, or a comparison between incompatible types, does not match.
Combined with the default of block, malformed input cannot satisfy an allow rule.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from agentguard.server.config import DECISION_RANK, PolicyConfig, RateLimit, Rule

_MISSING = object()


@dataclass
class PolicyResult:
    decision: str
    reason: str
    rule_id: str | None = None
    matched_rules: list[str] = field(default_factory=list)
    rate_limit: RateLimit | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "matched_rules": self.matched_rules,
            "rate_limited": self.rate_limit is not None,
        }


def _glob_any(value: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)


def _lookup(params: dict[str, Any], path: str) -> Any:
    cur: Any = params
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _num_cmp(fn: Callable[[float, float], bool]) -> Callable[[Any, Any], bool]:
    def cmp(actual: Any, expected: Any) -> bool:
        return _is_number(actual) and _is_number(expected) and fn(actual, expected)

    return cmp


OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": lambda a, e: a == e,
    "ne": lambda a, e: a != e,
    "lt": _num_cmp(lambda a, e: a < e),
    "lte": _num_cmp(lambda a, e: a <= e),
    "gt": _num_cmp(lambda a, e: a > e),
    "gte": _num_cmp(lambda a, e: a >= e),
    "in": lambda a, e: isinstance(e, list) and a in e,
    "not_in": lambda a, e: isinstance(e, list) and a not in e,
    "regex": lambda a, e: isinstance(a, str) and re.fullmatch(str(e), a) is not None,
    "contains": lambda a, e: isinstance(a, (str, list)) and e in a,
}


def validate_rule_conditions(rule: Rule) -> None:
    for path, ops in rule.when.items():
        for op in ops:
            if op not in OPERATORS and op != "exists":
                raise ValueError(f"rule {rule.id!r}: unknown operator {op!r} on {path!r}")


def _conditions_match(when: dict[str, dict[str, Any]], params: dict[str, Any]) -> bool:
    for path, ops in when.items():
        actual = _lookup(params, path)
        for op, expected in ops.items():
            if op == "exists":
                if (actual is not _MISSING) != bool(expected):
                    return False
                continue
            if actual is _MISSING:
                return False
            if not OPERATORS[op](actual, expected):
                return False
    return True


def rule_applies(rule: Rule, agent_id: str, action: str, params: dict[str, Any]) -> bool:
    return (
        _glob_any(agent_id, rule.agents)
        and _glob_any(action, rule.actions)
        and _conditions_match(rule.when, params)
    )


def rate_limit_applies(limit: RateLimit, agent_id: str, action: str) -> bool:
    return _glob_any(agent_id, limit.agents) and _glob_any(action, limit.actions)


class PolicyEngine:
    def __init__(self, config: PolicyConfig):
        for rule in config.rules:
            validate_rule_conditions(rule)
        self.config = config

    def evaluate(
        self,
        agent_id: str,
        action: str,
        params: dict[str, Any],
        recent_count: Callable[[RateLimit], int] | None = None,
    ) -> PolicyResult:
        """Decide what happens to an action.

        `recent_count(limit)` returns how many prior attempts fall inside the
        limit's window for this agent. Passing None skips rate limits (used by
        the dry-run simulator).
        """
        if recent_count is not None:
            for limit in self.config.rate_limits:
                if rate_limit_applies(limit, agent_id, action):
                    used = recent_count(limit)
                    if used >= limit.max:
                        return PolicyResult(
                            decision="block",
                            reason=(
                                f"rate limit {limit.id!r} exceeded: {used} actions in the last "
                                f"{limit.window_seconds}s (max {limit.max})"
                            ),
                            rule_id=limit.id,
                            rate_limit=limit,
                        )

        matched = [r for r in self.config.rules if rule_applies(r, agent_id, action, params)]
        if not matched:
            return PolicyResult(
                decision=self.config.default,
                reason=f"no rule matched; default is {self.config.default}",
            )
        winner = max(matched, key=lambda r: DECISION_RANK[r.decision])
        return PolicyResult(
            decision=winner.decision,
            reason=winner.reason or winner.description or f"matched rule {winner.id!r}",
            rule_id=winner.id,
            matched_rules=[r.id for r in matched],
        )
