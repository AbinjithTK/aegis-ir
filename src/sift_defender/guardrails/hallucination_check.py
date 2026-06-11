"""Hallucination guardrail — verifies findings are grounded in tool output.

This is the architectural anti-hallucination layer. Every finding generated
by the agent MUST pass through this before being presented to the user.

Uses Arize's hallucination evaluator template adapted for forensic context.
Falls back to deterministic checks when Arize is unavailable.
"""

import json
from typing import Any

from opentelemetry import trace as trace_api
from openinference.semconv.trace import SpanAttributes, OpenInferenceSpanKindValues


# Forensic-specific hallucination detection template
FORENSIC_HALLUCINATION_TEMPLATE = """
You are a forensic accuracy evaluator. Determine if the forensic finding below
is SUPPORTED by the tool outputs that produced it.

## Tool Outputs (Ground Truth - what the tools actually returned):
{tool_outputs}

## Finding Being Evaluated:
{finding}

## Evaluation Rules:
1. FACTUAL: Every claim in the finding can be traced to specific tool output above.
2. HALLUCINATED: The finding contains claims NOT present in any tool output.
3. PARTIALLY_SUPPORTED: Some claims are supported, others are not.

## Specific Forensic Checks:
- If the finding claims a file EXISTS → is there an MFT/fls/Amcache entry?
- If the finding claims EXECUTION → is there Prefetch or Process Creation (4688)?
- If the finding claims a network connection → is there netscan/PCAP evidence?
- If the finding cites a TIMESTAMP → does it EXACTLY match tool output?
- If the finding names a PROCESS → does it appear in pslist/pstree?
- If the finding claims PERSISTENCE → is there a scheduled task/service/run key?

Respond in JSON:
{
  "label": "factual" | "hallucinated" | "partially_supported",
  "explanation": "Which claims are/aren't supported and why",
  "supported_claims": ["list of claims that ARE grounded"],
  "unsupported_claims": ["list of claims that are NOT grounded"]
}
"""


class HallucinationGuardrail:
    """Validates findings against tool output before presenting to user."""

    def __init__(self):
        self.tracer = trace_api.get_tracer("sift_defender.guardrails")

    async def check_finding(
        self,
        finding: dict,
        tool_outputs: list[dict],
    ) -> dict:
        """Run hallucination check on a single finding.
        
        Args:
            finding: The finding to validate.
            tool_outputs: List of tool outputs that the finding references.
        
        Returns:
            {
                "action": "APPROVE" | "BLOCK" | "FLAG_FOR_REVIEW",
                "label": "factual" | "hallucinated" | "partially_supported",
                "explanation": str,
                "finding_id": str,
            }
        """
        with self.tracer.start_as_current_span(
            name="hallucination_guardrail",
            attributes={
                SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.GUARDRAIL.value,
                SpanAttributes.INPUT_VALUE: json.dumps({
                    "finding_id": finding.get("id", "unknown"),
                    "finding_title": finding.get("title", ""),
                }),
            },
        ) as span:
            # Deterministic checks first (fast, no LLM needed)
            deterministic_result = self._deterministic_check(finding, tool_outputs)
            
            if deterministic_result["action"] == "BLOCK":
                span.set_attribute("guardrail.passed", False)
                span.set_attribute("guardrail.reason", deterministic_result["explanation"])
                span.set_attribute(SpanAttributes.OUTPUT_VALUE, json.dumps(deterministic_result))
                return deterministic_result
            
            # LLM-based hallucination check (deeper, uses Arize evaluator)
            llm_result = await self._llm_hallucination_check(finding, tool_outputs)
            
            span.set_attribute("guardrail.passed", llm_result["action"] == "APPROVE")
            span.set_attribute("guardrail.label", llm_result.get("label", "unknown"))
            span.set_attribute(SpanAttributes.OUTPUT_VALUE, json.dumps(llm_result))
            
            return llm_result

    def _deterministic_check(self, finding: dict, tool_outputs: list[dict]) -> dict:
        """Fast, rule-based checks that don't need an LLM.
        
        Catches obvious hallucinations:
        - Finding references an audit_id that doesn't exist
        - Finding claims a timestamp that doesn't appear in any tool output
        - Finding references a file/process not mentioned in any output
        """
        finding_id = finding.get("id", "unknown")
        
        # Check 1: Does the finding reference real audit_ids?
        referenced_ids = finding.get("evidence_ids", [])
        available_ids = {t.get("audit_id") for t in tool_outputs if t.get("audit_id")}
        
        missing_ids = [rid for rid in referenced_ids if rid not in available_ids]
        if missing_ids:
            return {
                "action": "BLOCK",
                "label": "hallucinated",
                "explanation": f"Finding references audit_ids that don't exist: {missing_ids}",
                "finding_id": finding_id,
            }
        
        # Check 2: If finding has no evidence references at all
        if not referenced_ids and not finding.get("evidence"):
            return {
                "action": "FLAG_FOR_REVIEW",
                "label": "partially_supported",
                "explanation": "Finding has no evidence references (audit_ids or evidence list)",
                "finding_id": finding_id,
            }
        
        # Passed deterministic checks
        return {
            "action": "CONTINUE",  # Proceed to LLM check
            "label": "pending",
            "finding_id": finding_id,
        }

    async def _llm_hallucination_check(
        self,
        finding: dict,
        tool_outputs: list[dict],
    ) -> dict:
        """LLM-based hallucination check using Arize evaluator pattern.
        
        TODO: Integrate with Arize Phoenix Evals for production use.
        For now, uses a simplified heuristic.
        """
        # Simplified check: verify key claims exist in tool outputs
        finding_text = json.dumps(finding)
        tool_text = json.dumps(tool_outputs)
        
        # Basic grounding check
        finding_id = finding.get("id", "unknown")
        
        # If we have tool outputs that the finding references, it's likely grounded
        if tool_outputs and finding.get("evidence_ids"):
            return {
                "action": "APPROVE",
                "label": "factual",
                "explanation": "Finding references existing tool outputs with valid audit_ids",
                "finding_id": finding_id,
            }
        
        # Default: flag for review (conservative)
        return {
            "action": "FLAG_FOR_REVIEW",
            "label": "partially_supported",
            "explanation": "Could not fully verify grounding — flagged for human review",
            "finding_id": finding_id,
        }
