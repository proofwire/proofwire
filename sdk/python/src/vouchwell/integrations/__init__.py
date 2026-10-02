"""Adapters for agent frameworks. Each module imports its framework lazily, so
``vouchwell`` itself still needs nothing but ``cryptography``.

- ``vouchwell.integrations.langchain``: ``record_tools`` for LangChain /
  LangGraph tools.
- ``vouchwell.integrations.openai_agents``: ``record_tools`` for the OpenAI
  Agents SDK's function tools.
"""

from __future__ import annotations

from typing import Any

from ..record import PolicyDenied


def refusal(err: PolicyDenied) -> str:
    """What the model is told when a call is refused: the same words the MCP
    proxy sends, so an agent behaves the same whichever way it is wrapped."""
    d: Any = err.decision
    rules = ", ".join(d.get("rules") or []) or "none"
    return (
        f"Blocked by Vouchwell policy. {d.get('reason') or ''}\n"
        f"Rules: {rules}\n"
        f"This refusal is recorded as receipt {err.receipt['seq']} in log {err.receipt['log']}."
    )
