"""Actions that started and never finished. Mirrors packages/core/src/unfinished.js.

Every allowed call is recorded twice: an ``intent`` receipt before it runs and
an ``outcome`` receipt, naming the intent's hash in ``ref``, when it returns.
An intent with no outcome is what a process killed mid-call leaves behind: the
log proves the action was authorised and attempted, and not whether it
happened.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Iterable, Optional

from .receipt import entry_hash

DEFAULT_GRACE_MS = 5 * 60_000
"""Five minutes: longer than any tool call a person would wait on."""


def find_unfinished(receipts: Iterable[Any], now: Optional[float] = None, grace_ms: int = DEFAULT_GRACE_MS) -> dict:
    """Find the calls that were sent and never came back.

    Returns a dict with four lists, the same as the JavaScript ``findUnfinished``:

    - ``unfinished``: intents with no outcome, older than ``grace_ms``;
    - ``abandoned``: outcomes recorded as ``unfinished`` (the recorder shut
      down cleanly while the call was out);
    - ``inFlight``: intents with no outcome, younger than ``grace_ms``;
    - ``orphans``: outcomes naming an intent not in ``receipts``. Pass the
      whole log: in a filtered export these are expected.

    ``now`` is epoch milliseconds; it defaults to the current time.
    """
    now_ms = time.time() * 1000 if now is None else now
    receipts = [r for r in receipts if isinstance(r, dict)]

    intents: dict[str, dict] = {}
    for r in receipts:
        if r.get("phase") == "intent":
            intents[entry_hash(r)] = r

    answered: set[str] = set()
    abandoned: list[dict] = []
    orphans: list[dict] = []
    for r in receipts:
        if r.get("phase") != "outcome":
            continue
        ref = r.get("ref") if isinstance(r.get("ref"), str) else ""
        intent = intents.get(ref)
        if intent is None:
            orphans.append({"seq": r.get("seq"), "ref": ref})
            continue
        answered.add(ref)
        if (r.get("result") or {}).get("code") == "unfinished":
            abandoned.append({**_describe(intent, ref), "closedAt": r.get("ts"), "outcomeSeq": r.get("seq")})

    unfinished: list[dict] = []
    in_flight: list[dict] = []
    for h, intent in intents.items():
        if h in answered:
            continue
        at = _epoch_ms(intent.get("ts"))
        # An unparseable timestamp cannot be young.
        young = at is not None and now_ms - at < grace_ms
        (in_flight if young else unfinished).append(_describe(intent, h))

    return {"unfinished": unfinished, "abandoned": abandoned, "inFlight": in_flight, "orphans": orphans}


def _describe(r: dict, h: str) -> dict:
    actor = r.get("actor") or {}
    return {
        "seq": r.get("seq"),
        "ts": r.get("ts"),
        "target": (r.get("action") or {}).get("target"),
        "principal": actor.get("principal"),
        "agent": actor.get("agent"),
        "session": actor.get("session"),
        "intent": h,
    }


def _epoch_ms(ts: Any) -> Optional[float]:
    if not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000
    except ValueError:
        return None
