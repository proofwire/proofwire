"""The framework adapters, against the real frameworks. Each test skips where
its framework is not installed (it needs Python 3.10+)."""

import asyncio
import json

import pytest

from vouchwell import ProofLog, Recorder, entry_hash, find_unfinished


def recorder(tmp_path, decide=None):
    return Recorder(ProofLog.create(tmp_path / "log"), agent="support-bot", principal="ops@acme.test", decide=decide)


def no_refunds(target, params):
    if target == "refund":
        return {"outcome": "deny", "policy": "p", "rules": ["no.refunds"], "reason": "refunds need a person"}
    return {"outcome": "allow", "policy": "p", "rules": []}


# ── LangChain ────────────────────────────────────────────────────────────


def test_langchain_structured_tools_are_recorded_and_refusals_reach_the_model(tmp_path):
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    from vouchwell.integrations.langchain import record_tools

    ran = []

    @tool
    def lookup(order_id: str) -> str:
        """Look up an order."""
        return f"order {order_id}: shipped"

    @tool
    def refund(order_id: str, amount: float) -> str:
        """Refund an order."""
        ran.append(order_id)
        return "refunded"

    rec = recorder(tmp_path, decide=no_refunds)
    wrapped_lookup, wrapped_refund = record_tools(rec, [lookup, refund])
    assert wrapped_lookup.name == "lookup" and wrapped_lookup.args == lookup.args

    assert wrapped_lookup.invoke({"order_id": "o_1"}) == "order o_1: shipped"
    reply = wrapped_refund.invoke({"order_id": "o_2", "amount": 45.0})
    assert reply.startswith("Blocked by Vouchwell policy. refunds need a person")
    assert ran == [], "a refused call must not run"

    intent, outcome, denied = rec.log.entries
    assert (intent["phase"], intent["action"]["target"]) == ("intent", "lookup")
    assert outcome["ref"] == entry_hash(intent) and outcome["result"]["status"] == "ok"
    assert (denied["phase"], denied["decision"]["outcome"]) == ("atomic", "deny")
    assert rec.log.audit()["ok"]


def test_langchain_async_and_errors(tmp_path):
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    from vouchwell.integrations.langchain import record_tool

    @tool
    async def fetch(url: str) -> str:
        """Fetch a page."""
        raise ConnectionError("unreachable")

    rec = recorder(tmp_path)
    wrapped = record_tool(rec, fetch)
    with pytest.raises(ConnectionError):
        asyncio.run(wrapped.ainvoke({"url": "https://x.test"}))
    assert rec.log.entries[1]["result"]["status"] == "error"
    assert find_unfinished(rec.log.entries)["unfinished"] == []


def test_langchain_single_input_tools(tmp_path):
    pytest.importorskip("langchain_core")
    from langchain_core.tools import Tool

    from vouchwell.integrations.langchain import record_tool

    upper = Tool(name="upper", description="shout", func=lambda s: s.upper())
    rec = recorder(tmp_path)
    assert record_tool(rec, upper).invoke("hi") == "HI"
    assert rec.log.entries[1]["result"]["status"] == "ok"


# ── OpenAI Agents SDK ────────────────────────────────────────────────────


def test_openai_agents_function_tools_are_recorded_and_refusals_reach_the_model(tmp_path):
    pytest.importorskip("agents")
    from agents import FunctionTool, WebSearchTool, function_tool

    from vouchwell.integrations.openai_agents import record_tools

    ran = []

    @function_tool
    def lookup(order_id: str) -> str:
        """Look up an order."""
        return f"order {order_id}: shipped"

    @function_tool
    def refund(order_id: str, amount: float) -> str:
        """Refund an order."""
        ran.append(order_id)
        return "refunded"

    hosted = WebSearchTool()
    rec = recorder(tmp_path, decide=no_refunds)
    wrapped_lookup, wrapped_refund, passed = record_tools(rec, [lookup, refund, hosted])
    assert isinstance(wrapped_lookup, FunctionTool) and wrapped_lookup.name == "lookup"
    assert wrapped_lookup.params_json_schema == lookup.params_json_schema
    assert passed is hosted, "hosted tools run on OpenAI's side and are passed through"

    async def call(t, args):
        from agents.tool_context import ToolContext

        ctx = ToolContext(context=None, tool_name=t.name, tool_call_id="c1", tool_arguments=json.dumps(args))
        return await t.on_invoke_tool(ctx, json.dumps(args))

    assert asyncio.run(call(wrapped_lookup, {"order_id": "o_1"})) == "order o_1: shipped"
    reply = asyncio.run(call(wrapped_refund, {"order_id": "o_2", "amount": 45}))
    assert reply.startswith("Blocked by Vouchwell policy.")
    assert ran == []

    intent, outcome, denied = rec.log.entries
    assert intent["action"]["params"]["preview"] == {"order_id": "o_1"}
    assert outcome["ref"] == entry_hash(intent)
    assert denied["decision"]["outcome"] == "deny"
    assert rec.log.audit()["ok"]
