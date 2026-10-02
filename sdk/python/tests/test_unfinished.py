"""Calls that were authorised and sent and never came back."""

import pytest

from deedwrit import DEFAULT_GRACE_MS, ProofLog, Recorder, entry_hash, find_unfinished

ACTOR = {"agent": "claude", "runtime": "test", "session": "sess_a", "principal": "ops@acme.test"}
ALLOW = {"outcome": "allow", "policy": "p", "rules": []}
NOW = 1_790_000_000_000  # epoch ms; the receipts below are hours older


def ts(ms_ago):
    from datetime import datetime, timezone

    return datetime.fromtimestamp((NOW - ms_ago) / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def intent(log, target, when):
    return log.append(ts=when, phase="intent", actor=ACTOR, action={"kind": "tool_call", "target": target, "params": {}}, decision=ALLOW)


def outcome(log, of, **result):
    return log.append(
        ts=ts(0), phase="outcome", ref=entry_hash(of), actor=ACTOR,
        action={"kind": "tool_call", "target": of["action"]["target"], "params": {}}, decision=ALLOW,
        result={"payload": None, **result},
    )


@pytest.fixture
def log(tmp_path):
    return ProofLog.create(tmp_path / "log")


def test_finished_calls_are_quiet_and_a_missing_outcome_is_reported(log):
    done = intent(log, "crm.query", ts(60_000))
    outcome(log, done, status="ok")
    crashed = intent(log, "stripe.refund", ts(DEFAULT_GRACE_MS + 1))
    found = find_unfinished(log.entries, now=NOW)
    assert [(u["seq"], u["target"], u["session"]) for u in found["unfinished"]] == [(2, "stripe.refund", "sess_a")]
    assert found["unfinished"][0]["intent"] == entry_hash(crashed)
    assert found["abandoned"] == found["inFlight"] == found["orphans"] == []


def test_recent_calls_are_in_flight_and_recorded_give_ups_are_abandoned(log):
    intent(log, "slow.export", ts(30_000))
    cut = intent(log, "db.migrate", ts(3_600_000))
    outcome(log, cut, status="error", code="unfinished")
    found = find_unfinished(log.entries, now=NOW)
    assert [u["target"] for u in found["inFlight"]] == ["slow.export"]
    assert [(u["target"], u["outcomeSeq"]) for u in found["abandoned"]] == [("db.migrate", 2)]
    assert found["unfinished"] == []
    assert len(find_unfinished(log.entries, now=NOW, grace_ms=1_000)["unfinished"]) == 1


def test_an_outcome_for_an_unknown_intent_is_an_orphan_and_junk_does_not_raise(log):
    log.append(
        ts=ts(0), phase="outcome", ref="ab" * 32, actor=ACTOR,
        action={"kind": "tool_call", "target": "x", "params": {}}, decision=ALLOW, result={"status": "ok", "payload": None},
    )
    assert find_unfinished(log.entries, now=NOW)["orphans"] == [{"seq": 0, "ref": "ab" * 32}]
    odd = find_unfinished([None, 7, {"phase": "outcome"}, {"phase": "intent", "ts": "not a date"}], now=NOW)
    assert len(odd["unfinished"]) == 1 and len(odd["orphans"]) == 1


def test_a_recorded_call_that_raises_is_finished(log):
    rec = Recorder(log, agent="claude", principal="ops@acme.test")

    @rec.tool("crm.query")
    def boom():
        raise RuntimeError("upstream down")

    with pytest.raises(RuntimeError):
        boom()
    assert find_unfinished(log.entries)["unfinished"] == []
