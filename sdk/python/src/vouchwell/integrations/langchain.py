"""Record, and check, every call a LangChain or LangGraph agent makes to its tools.

    from vouchwell import ProofLog, Recorder
    from vouchwell.integrations.langchain import record_tools

    rec = Recorder(ProofLog.open(".vouchwell"), agent="support-bot", principal="ops@acme.com", decide=my_rules)
    tools = record_tools(rec, [search, refund])       # use these in place of the originals
    agent = create_react_agent(model, tools)

Each wrapped tool records an intent before it runs and an outcome after,
exactly as ``Recorder.tool`` does. A call the ``decide`` hook refuses never
runs, and the model is told why, in the tool's reply, rather than the agent
crashing: the MCP proxy's behaviour.
"""

from __future__ import annotations

from typing import Any, Sequence

from ..record import PolicyDenied, Recorder
from . import refusal

try:
    from langchain_core.tools import BaseTool, StructuredTool
except ImportError as err:  # pragma: no cover - exercised only without the package
    raise ImportError(
        "vouchwell.integrations.langchain needs langchain-core: pip install langchain-core"
    ) from err


def record_tools(recorder: Recorder, tools: Sequence[BaseTool]) -> list[BaseTool]:
    """Wrap each tool; returns new tools with the same names, descriptions and
    argument schemas. The originals are untouched."""
    return [record_tool(recorder, t) for t in tools]


def record_tool(recorder: Recorder, tool: BaseTool) -> BaseTool:
    """Wrap one tool. See ``record_tools``."""
    if not isinstance(tool, BaseTool):
        raise TypeError(f"record_tool expects a LangChain BaseTool, got {type(tool).__name__}")
    structured = tool.args_schema is not None

    def params_of(args: tuple, kwargs: dict) -> Any:
        return dict(kwargs) if structured else (args[0] if args else kwargs.get("tool_input", ""))

    def invoke_input(args: tuple, kwargs: dict) -> Any:
        return dict(kwargs) if structured else params_of(args, kwargs)

    def run(*args: Any, **kwargs: Any) -> Any:
        try:
            with recorder.call(tool.name, params_of(args, kwargs)) as c:
                c.result = _content(tool.invoke(invoke_input(args, kwargs)))
                return c.result
        except PolicyDenied as err:
            return refusal(err)

    async def arun(*args: Any, **kwargs: Any) -> Any:
        try:
            with recorder.call(tool.name, params_of(args, kwargs)) as c:
                c.result = _content(await tool.ainvoke(invoke_input(args, kwargs)))
                return c.result
        except PolicyDenied as err:
            return refusal(err)

    if structured:
        return StructuredTool.from_function(
            func=run,
            coroutine=arun,
            name=tool.name,
            description=tool.description,
            args_schema=tool.args_schema,
            return_direct=tool.return_direct,
            infer_schema=False,
        )

    def run_text(tool_input: str) -> Any:
        return run(tool_input)

    async def arun_text(tool_input: str) -> Any:
        return await arun(tool_input)

    return StructuredTool.from_function(
        func=run_text,
        coroutine=arun_text,
        name=tool.name,
        description=tool.description,
        return_direct=tool.return_direct,
    )


def _content(output: Any) -> Any:
    """A ToolMessage is recorded as what it carries."""
    return getattr(output, "content", output)
