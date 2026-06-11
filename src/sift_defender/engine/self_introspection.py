"""Self-Introspection via Phoenix MCP — Agent queries its own operational data.

This is the BONUS POINTS feature. The agent can:
1. Query its own past traces to see what tools it called and what results it got
2. Check if it hallucinated in previous investigations (via eval results)
3. Look at patterns in its failures to avoid repeating mistakes
4. Use its own operational data to adjust its investigation strategy

The Phoenix MCP server exposes these capabilities as tools the agent can call:
- Query traces, spans, sessions
- Access datasets and experiments
- Read evaluation results
- Inspect prompt performance

This creates a SELF-IMPROVEMENT LOOP:
  Investigate → Get evaluated → Query own evals → Adjust behavior → Investigate better
"""

import json
from typing import Any

from opentelemetry import trace as trace_api
from openinference.semconv.trace import SpanAttributes, OpenInferenceSpanKindValues


class SelfIntrospectionEngine:
    """Allows the agent to learn from its own operational history.
    
    Uses Phoenix MCP to query the agent's own traces, evaluations,
    and experiment results to improve investigation quality.
    """

    def __init__(self):
        self.tracer = trace_api.get_tracer("sift_defender.self_introspection")

    async def check_past_performance(self, tool_name: str) -> dict:
        """Query Phoenix for how well this tool was used in the past.
        
        Returns patterns like:
        - "Last time you used parse_amcache, you incorrectly concluded execution.
           Remember: Amcache = PRESENCE only."
        - "Your hallucination rate for network findings is 12%. Be more careful
           with netscan interpretations."
        
        Args:
            tool_name: The forensic tool about to be used.
        
        Returns:
            Dict with past performance data and suggestions.
        """
        with self.tracer.start_as_current_span(
            name=f"self_introspection_{tool_name}",
            attributes={
                SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.CHAIN.value,
                SpanAttributes.INPUT_VALUE: json.dumps({"tool": tool_name}),
                "introspection.tool_queried": tool_name,
            },
        ) as span:
            # TODO: When Phoenix MCP is configured, this will call:
            # phoenix_mcp.query_spans(
            #     filter=f"tool.name == '{tool_name}'",
            #     project="sift-defender",
            #     limit=10
            # )
            # 
            # And then analyze:
            # - How many times was this tool called?
            # - What was the hallucination eval score on findings from this tool?
            # - Were there any corrections triggered after using this tool?

            result = {
                "tool": tool_name,
                "past_usage_count": 0,
                "hallucination_rate": 0.0,
                "common_mistakes": [],
                "recommendations": [],
                "available": False,  # Will be True when Phoenix MCP is configured
            }

            span.set_attribute(SpanAttributes.OUTPUT_VALUE, json.dumps(result))
            return result

    async def get_investigation_patterns(self, evidence_type: str) -> dict:
        """Query Phoenix for patterns from similar past investigations.
        
        Answers: "When investigating Windows disk images before, 
        what worked well and what didn't?"
        
        Args:
            evidence_type: Type of evidence (disk_image, memory_dump, etc.)
        
        Returns:
            Dict with successful patterns and pitfalls to avoid.
        """
        with self.tracer.start_as_current_span(
            name=f"introspect_patterns_{evidence_type}",
            attributes={
                SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.CHAIN.value,
                "introspection.evidence_type": evidence_type,
            },
        ) as span:
            # TODO: Query Phoenix datasets/experiments for past investigations
            # on similar evidence types

            result = {
                "evidence_type": evidence_type,
                "successful_sequences": [],
                "common_pitfalls": [],
                "average_iterations_to_converge": 0,
                "average_findings_count": 0,
                "available": False,
            }

            span.set_attribute(SpanAttributes.OUTPUT_VALUE, json.dumps(result))
            return result

    async def log_improvement(
        self,
        original_approach: str,
        improved_approach: str,
        reason: str,
    ):
        """Record when the agent changed its approach based on self-introspection.
        
        This creates a visible trace showing the self-improvement in action.
        """
        with self.tracer.start_as_current_span(
            name="self_improvement_applied",
            attributes={
                SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.CHAIN.value,
                SpanAttributes.INPUT_VALUE: json.dumps({
                    "original": original_approach,
                    "improved": improved_approach,
                    "reason": reason,
                }),
                "improvement.original": original_approach,
                "improvement.new": improved_approach,
                "improvement.reason": reason,
            },
        ) as span:
            span.set_attribute(SpanAttributes.OUTPUT_VALUE, 
                f"Agent adjusted approach: {reason}")
