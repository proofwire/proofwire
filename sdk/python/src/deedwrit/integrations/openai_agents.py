"""Record, and check, every call an OpenAI Agents SDK agent makes to its function tools.

    from agents import Agent, function_tool
    from deedwrit import ProofLog, Recorder
    from deedwrit.integrations.openai_agents import record_tools

    rec = Recorder(ProofLog.open(".deedwrit"), agent="support-bot", principal="ops@acme.com", decide=my_rules)
    agent = Agent(name="Support", tools=record_tools(rec, [lookup_order, refund]))

Each wrapped tool records an intent before it runs and an outcome after. A
call the ``decide`` hook refuses never runs; the model is told why in the
tool's reply. Tools that are not function tools (hosted tools such as web
search run on OpenAI's side) are passed through unchanged, since nothing
here sees them run.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any, Sequence

from ..record import PolicyDenied, Recorder
from . import refusal

try:
    from agents import FunctionTool
except ImportError as err:  # pragma: no cover - exercised only without the package
    raise ImportError(
        "deedwrit.integrations.openai_agents needs the OpenAI Agents SDK: pip install openai-agents"
    ) from err


def record_tools(recorder: Recorder, tools: Sequence[Any]) -> list[Any]:
    """Wrap each function tool; returns new tools. The originals are untouched."""
    return [record_tool(recorder, t) if isinstance(t, FunctionTool) else t for t in tools]


def record_tool(recorder: Recorder, tool: FunctionTool) -> FunctionTool:
    """Wrap one function tool. See ``record_tools``."""
    original = tool.on_invoke_tool

    async def on_invoke_tool(ctx: Any, input_json: str) -> Any:
        try:
            params: Any = json.loads(input_json) if input_json else {}
        except ValueError:
            params = {"raw": input_json}
        try:
            with recorder.call(tool.name, params) as c:
                c.result = await original(ctx, input_json)
                return c.result
        except PolicyDenied as err:
            return refusal(err)

    return dataclasses.replace(tool, on_invoke_tool=on_invoke_tool)
