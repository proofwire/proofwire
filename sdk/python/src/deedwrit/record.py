"""Record the tool calls a Python agent makes, the way the MCP proxy does.

For agents that don't go through MCP, such as LangChain tools, custom
function calling or plain Python, wrap each tool:

    log = ProofLog.open_or_create(".deedwrit")
    rec = Recorder(log, agent="support-bot", principal="ops@acme.com")

    @rec.tool("stripe.refund")
    def refund(order_id: str, amount_cents: int): ...

    with rec.call("crm.update", params={"id": 42}) as call:
        call.result = crm.update(42)

Each call gets an **intent** receipt before it runs, so a crash mid-call still
leaves evidence it was attempted, and an **outcome** receipt, linked to the
intent, when it returns or raises. Pass ``decide=`` to check each call first
against your own rules: a refused call gets one receipt, never runs, and
raises ``PolicyDenied``. (The full Deedwrit policy language, with budgets,
rate limits, escalation and approvals, runs in the ``dw proxy`` MCP proxy.)
"""

from __future__ import annotations

import functools
import inspect
import json
import time
import uuid
from typing import Any, Callable, Optional

from .log import ProofLog
from .receipt import entry_hash

#: Recorded when no ``decide`` hook is given. Honest about what happened:
#: the call was recorded, and no policy was evaluated.
NO_POLICY = {"outcome": "allow", "policy": "none", "rules": [], "reason": "recorded without a policy"}


class PolicyDenied(Exception):
    """The ``decide`` hook refused the call. It did not run."""

    def __init__(self, target: str, decision: dict, receipt: dict):
        super().__init__(f"{target}: refused by policy: {decision.get('reason') or 'no reason given'}")
        self.target = target
        self.decision = decision
        self.receipt = receipt


def _jsonable(value: Any) -> Any:
    """What can go into a receipt: JSON values as themselves, anything else as
    its repr, so recording never fails because a tool returned an object."""
    try:
        return json.loads(json.dumps(value, allow_nan=False, default=repr))
    except (TypeError, ValueError):
        return {"repr": repr(value)[:2000]}


class _Call:
    """An in-flight tool call. Set ``result`` before the block ends to record it."""

    def __init__(self, recorder: "Recorder", target: str, params: Any, metrics: Optional[dict]):
        self._rec = recorder
        self.target = target
        self.params = params
        self.metrics = metrics
        self.result: Any = None
        self.intent: Optional[dict] = None
        self.outcome: Optional[dict] = None
        self._started = 0.0

    def __enter__(self) -> "_Call":
        rec = self._rec
        decision = rec._decide(self.target, self.params)
        if decision["outcome"] != "allow":
            receipt = rec.log.append(
                actor=rec.actor,
                action={"kind": "tool_call", "target": self.target, "params": self.params, **({"metrics": self.metrics} if self.metrics else {})},
                decision=decision,
            )
            raise PolicyDenied(self.target, decision, receipt)
        # Durable before the call runs: a crash mid-call still leaves evidence
        # the action was authorised and attempted.
        self.intent = rec.log.append(
            actor=rec.actor,
            action={"kind": "tool_call", "target": self.target, "params": self.params, **({"metrics": self.metrics} if self.metrics else {})},
            decision=decision,
            phase="intent",
        )
        self._started = time.monotonic()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        assert self.intent is not None
        latency = round((time.monotonic() - self._started) * 1000)
        if exc is None:
            result = {"status": "ok", "latencyMs": latency, "payload": _jsonable(self.result)}
        else:
            result = {
                "status": "error",
                "code": type(exc).__name__,
                "latencyMs": latency,
                "payload": {"error": str(exc)[:2000]},
            }
        # Metrics are left off the outcome: they were counted on the intent,
        # and counting them twice would halve every budget.
        self.outcome = self._rec.log.append(
            actor=self._rec.actor,
            action={"kind": "tool_call", "target": self.target, "params": self.params},
            decision=self.intent["decision"],
            result=result,
            phase="outcome",
            ref=entry_hash(self.intent),
        )
        return False  # never swallow the tool's own exception


class Recorder:
    def __init__(
        self,
        log: ProofLog,
        *,
        agent: str,
        principal: str,
        session: Optional[str] = None,
        namespace: str = "",
        decide: Optional[Callable[[str, Any], dict]] = None,
    ) -> None:
        from . import __version__

        self.log = log
        self.namespace = namespace
        self._decide_hook = decide
        self.actor = {
            "agent": agent,
            "runtime": f"deedwrit-python/{__version__}",
            "session": session or "sess_" + uuid.uuid4().hex[:12],
            "principal": principal,
        }

    def _qualify(self, target: str) -> str:
        return f"{self.namespace}.{target}" if self.namespace else target

    def _decide(self, target: str, params: Any) -> dict:
        if self._decide_hook is None:
            return dict(NO_POLICY)
        d = dict(self._decide_hook(target, params) or {})
        outcome = d.get("outcome")
        if outcome not in ("allow", "deny", "escalate"):
            raise ValueError(f"decide() must return an outcome of allow, deny or escalate; got {outcome!r}")
        d.setdefault("policy", "custom")
        d.setdefault("rules", [])
        d.setdefault("reason", "")
        if outcome == "escalate":
            # Nobody here can approve it, and an escalation nobody can answer
            # is a denial, recorded as the fallback it was, never as a person.
            d["outcome"] = "deny"
            d["declined"] = {"by": "policy:no-approver", "at": _now()}
            d["reason"] = (d["reason"] + " (escalation needs an approver; none is configured)").strip()
        return d

    def call(self, target: str, params: Any = None, metrics: Optional[dict] = None) -> _Call:
        """A context manager around one tool call."""
        return _Call(self, self._qualify(target), _jsonable(params if params is not None else {}), metrics)

    def tool(self, target: Optional[str] = None, *, metrics: Optional[Callable[..., dict]] = None) -> Callable:
        """Decorate a function (sync or async) so every call to it is recorded.

        ``target`` defaults to the function's name. ``metrics`` computes the
        clear-text numbers budgets use; it is called with the function's
        arguments by name, defaults included, exactly as they are recorded.
        """

        def wrap(fn: Callable) -> Callable:
            name = target or fn.__name__
            sig = inspect.signature(fn)

            def params_of(args: tuple, kwargs: dict) -> dict:
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                return dict(bound.arguments)

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    params = params_of(args, kwargs)
                    with self.call(name, params, metrics(**params) if metrics else None) as c:
                        c.result = await fn(*args, **kwargs)
                        return c.result

                return async_wrapper

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                params = params_of(args, kwargs)
                with self.call(name, params, metrics(**params) if metrics else None) as c:
                    c.result = fn(*args, **kwargs)
                    return c.result

            return wrapper

        return wrap


def _now() -> str:
    from .receipt import now_iso

    return now_iso()
