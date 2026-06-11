"""Phoenix tracing: ``register(..., auto_instrument=True)`` per ADK doc.

https://arize.com/docs/phoenix/integrations/python/google-adk/google-adk-tracing

Requires ``google-adk>=1.32`` and ``openinference-instrumentation-google-adk>=0.1.11``.

Environment: ``PHOENIX_API_KEY``, ``PHOENIX_COLLECTOR_ENDPOINT``, optional ``PHOENIX_PROJECT_NAME``.

Phoenix captures:
- Every ADK agent invocation, tool call, and LLM call (auto-instrumented)
- Self-correction decisions (manual spans)
- Hallucination guardrail checks (manual GUARDRAIL spans)
- Investigation journal entries

The Phoenix MCP server (@arizeai/phoenix-mcp) additionally gives the agent
runtime access to query its own traces, enabling a self-improvement loop.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from phoenix.otel import register

_provider: Optional[Any] = None


def setup_tracing() -> Optional[Any]:
    """Returns the tracer provider when Phoenix auth is configured, else None.
    
    Call this BEFORE any ADK agent is instantiated. The `auto_instrument=True`
    flag handles GoogleADKInstrumentor setup automatically.
    """
    global _provider
    if _provider is not None:
        return _provider
    if not (os.environ.get("PHOENIX_API_KEY") or "").strip():
        print("⚠ Phoenix not configured — set PHOENIX_API_KEY for observability")
        print("  Sign up free: https://app.phoenix.arize.com")
        return None
    _provider = register(
        project_name=os.environ.get("PHOENIX_PROJECT_NAME", "sift-defender"),
        batch=False,
        auto_instrument=True,
        verbose=False,
    )
    print(f"✓ Phoenix tracing initialized (project: {os.environ.get('PHOENIX_PROJECT_NAME', 'sift-defender')})")
    return _provider
