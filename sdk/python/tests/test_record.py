"""The Recorder: what a Python agent's tool calls leave behind."""

import asyncio
import datetime

import pytest

from deedwrit import PolicyDenied, ProofLog, Recorder, entry_hash


@pytest.fixture
def rec(tmp_path):
    return Recorder(ProofLog.create(tmp_path / "log"), agent="support-bot", principal="ops@acme.test", namespace="crm")


def test_a_decorated_call_leaves_an_intent_then_a_linked_outcome(rec):
    @rec.tool("refund", metrics=lambda order, amount_cents: {"amount_usd": amount_cents / 100})
    def refund(order, amount_cents=500):
        return {"refunded": order}

    assert refund("ord_1") == {"refunded": "ord_1"}
    intent, outcome = rec.log.entries
    assert intent["phase"] == "intent" and outcome["phase"] == "outcome"
    assert intent["action"]["target"] == "crm.refund"
    assert intent["action"]["metrics"] == {"amount_usd": 5}
    assert "metrics" not in outcome["action"], "metrics are counted once, on the intent"
    assert outcome["ref"] == entry_hash(intent)
    assert outcome["result"]["status"] == "ok"
    assert intent["actor"]["runtime"].startswith("deedwrit-python/")
    # The arguments, defaults included, are committed to.
    assert rec.log.reveal(0, "params", {"order": "ord_1", "amount_cents": 500})
    assert rec.log.audit()["ok"]


def test_a_tool_that_raises_is_recorded_as_an_error_and_the_error_still_propagates(rec):
    @rec.tool()
    def charge(card):
        raise ConnectionError("gateway down")

    with pytest.raises(ConnectionError):
        charge("4242 4242 4242 4242")
    outcome = rec.log.entries[-1]
    assert outcome["result"]["status"] == "error"
    assert outcome["result"]["code"] == "ConnectionError"
    assert "4242 4242 4242 4242" not in str(rec.log.entries), "the card number reached the log"


def test_async_tools_are_recorded_too(rec):
    @rec.tool("lookup")
    async def lookup(q):
        await asyncio.sleep(0)
        return [q]

    assert asyncio.run(lookup("x")) == ["x"]
    assert [r["phase"] for r in rec.log.entries] == ["intent", "outcome"]


def test_a_context_manager_records_whatever_result_is_set(rec):
    with rec.call("update", params={"id": 42}) as c:
        c.result = {"when": datetime.date(2026, 1, 1)}  # not JSON: recorded by repr, never a crash
    assert rec.log.entries[-1]["result"]["status"] == "ok"
    assert rec.log.audit()["ok"]


def test_a_denied_call_never_runs_and_leaves_exactly_one_receipt(tmp_path):
    log = ProofLog.create(tmp_path / "log")
    rec = Recorder(log, agent="a", principal="p", decide=lambda target, params: {"outcome": "deny", "rules": ["no-deletes"], "reason": "deletes are not allowed"})
    ran = []

    @rec.tool("delete_all")
    def delete_all():
        ran.append(True)

    with pytest.raises(PolicyDenied) as err:
        delete_all()
    assert ran == []
    assert log.size == 1 and log.entries[0]["phase"] == "atomic"
    assert log.entries[0]["decision"]["rules"] == ["no-deletes"]
    assert err.value.receipt["seq"] == 0


def test_an_escalation_with_nobody_to_approve_is_a_denial_recorded_as_a_fallback(tmp_path):
    log = ProofLog.create(tmp_path / "log")
    rec = Recorder(log, agent="a", principal="p", decide=lambda t, p: {"outcome": "escalate", "reason": "large refund"})
    with pytest.raises(PolicyDenied):
        with rec.call("refund", {"amount": 10_000}):
            pass
    d = log.entries[0]["decision"]
    assert d["outcome"] == "deny"
    assert d["declined"]["by"] == "policy:no-approver"


def test_a_decide_hook_that_returns_nonsense_is_an_error_not_an_allow(tmp_path):
    rec = Recorder(ProofLog.create(tmp_path / "log"), agent="a", principal="p", decide=lambda t, p: {"outcome": "maybe"})
    with pytest.raises(ValueError):
        with rec.call("x"):
            pass
    assert rec.log.size == 0


def test_without_a_policy_the_receipt_says_so(rec):
    with rec.call("read"):
        pass
    assert rec.log.entries[0]["decision"]["policy"] == "none"
