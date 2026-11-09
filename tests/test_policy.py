import pytest

from agentguard.server.config import PolicyConfig
from agentguard.server.policy import PolicyEngine


def engine(**kw) -> PolicyEngine:
    return PolicyEngine(PolicyConfig.model_validate(kw))


REFUND_RULES = [
    {"id": "small", "agents": ["support-*"], "action": "payments.refund", "when": {"amount": {"lte": 50}}, "decision": "allow"},
    {"id": "medium", "action": "payments.refund", "when": {"amount": {"gt": 50, "lte": 500}}, "decision": "review"},
    {"id": "large", "action": "payments.refund", "when": {"amount": {"gt": 500}}, "decision": "block"},
]


@pytest.mark.parametrize(
    "amount,decision,rule",
    [(10, "allow", "small"), (50, "allow", "small"), (50.01, "review", "medium"), (500, "review", "medium"), (501, "block", "large")],
)
def test_refund_tiers(amount, decision, rule):
    r = engine(rules=REFUND_RULES).evaluate("support-1", "payments.refund", {"amount": amount})
    assert (r.decision, r.rule_id) == (decision, rule)


def test_default_is_block():
    r = engine(rules=REFUND_RULES).evaluate("support-1", "payments.delete_account", {})
    assert r.decision == "block" and r.rule_id is None


def test_agent_glob_scopes_rules():
    r = engine(rules=REFUND_RULES).evaluate("sales-1", "payments.refund", {"amount": 10})
    assert r.decision == "block"  # small-refund allow rule only covers support-*


def test_most_restrictive_wins_regardless_of_order():
    rules = [
        {"id": "allow-all", "decision": "allow"},
        {"id": "review-eur", "when": {"currency": {"eq": "eur"}}, "decision": "review"},
    ]
    e1, e2 = engine(rules=rules), engine(rules=list(reversed(rules)))
    for e in (e1, e2):
        r = e.evaluate("a", "x.y", {"currency": "eur"})
        assert r.decision == "review" and set(r.matched_rules) == {"allow-all", "review-eur"}


@pytest.mark.parametrize("bad", ["10", None, True, [10], {"v": 10}])
def test_type_confusion_cannot_satisfy_allow(bad):
    r = engine(rules=REFUND_RULES).evaluate("support-1", "payments.refund", {"amount": bad})
    assert r.decision == "block"


def test_missing_param_does_not_match():
    r = engine(rules=REFUND_RULES).evaluate("support-1", "payments.refund", {})
    assert r.decision == "block"


def test_nested_paths_and_operators():
    e = engine(rules=[{"id": "r", "when": {"customer.tier": {"in": ["gold", "platinum"]}, "email": {"regex": r".+@acme\.com"}}, "decision": "allow"}])
    assert e.evaluate("a", "x", {"customer": {"tier": "gold"}, "email": "jo@acme.com"}).decision == "allow"
    assert e.evaluate("a", "x", {"customer": {"tier": "free"}, "email": "jo@acme.com"}).decision == "block"
    assert e.evaluate("a", "x", {"customer": {"tier": "gold"}, "email": "jo@acme.com.evil.io"}).decision == "block"


def test_exists_operator():
    e = engine(default="allow", rules=[{"id": "fx", "when": {"currency": {"exists": True, "ne": "usd"}}, "decision": "review"}])
    assert e.evaluate("a", "x", {}).decision == "allow"
    assert e.evaluate("a", "x", {"currency": "usd"}).decision == "allow"
    assert e.evaluate("a", "x", {"currency": "eur"}).decision == "review"


def test_rate_limit_blocks_before_rules():
    e = engine(rules=[{"id": "ok", "decision": "allow"}], rate_limits=[{"id": "rl", "action": "payments.*", "max": 3, "window_seconds": 60}])
    assert e.evaluate("a", "payments.refund", {}, recent_count=lambda lim: 2).decision == "allow"
    r = e.evaluate("a", "payments.refund", {}, recent_count=lambda lim: 3)
    assert r.decision == "block" and r.rule_id == "rl"
    assert e.evaluate("a", "email.send", {}, recent_count=lambda lim: 99).decision == "allow"


def test_unknown_operator_rejected():
    with pytest.raises(ValueError):
        engine(rules=[{"id": "r", "when": {"amount": {"less_than": 5}}, "decision": "allow"}])


def test_duplicate_ids_rejected():
    with pytest.raises(ValueError):
        engine(rules=[{"id": "r", "decision": "allow"}, {"id": "r", "decision": "block"}])
