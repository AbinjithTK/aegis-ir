"""Phoenix Self-Introspection Tools — Agent queries its OWN operational data.

THIS IS THE KEY DIFFERENTIATOR for the Arize hackathon track.

Uses the OFFICIAL Phoenix Client SDK (arize-phoenix-client) to:
1. Query own traces via SpanQuery DSL
2. Read annotations/eval results on past spans
3. Log annotations back to spans (self-eval results)
4. Track accuracy improvement over time

Architecture:
  Agent (ADK) → phoenix_introspect_* tools → Phoenix Client SDK → Phoenix Server
  
This creates a SELF-IMPROVEMENT LOOP:
  Investigate → Get evaluated → Query own evals → Adjust behavior → Better investigation
"""

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from opentelemetry import trace
from openinference.semconv.trace import SpanAttributes, OpenInferenceSpanKindValues

tracer = trace.get_tracer("sift_defender.phoenix_introspection")

# Phoenix project name (consistent across all components)
PHOENIX_PROJECT = os.environ.get("PHOENIX_PROJECT_NAME", "aegis-ir")


def _get_phoenix_client():
    """Get Phoenix Client instance for self-introspection."""
    from sift_defender.phoenix.tracer import PhoenixTracer
    client = PhoenixTracer.get_instance().get_client()
    return client


def phoenix_query_past_investigations() -> str:
    """Query Phoenix for a summary of all past investigations.
    
    Uses the Phoenix Client SDK to query your own traces and annotations.
    Returns accuracy trend, past mistakes, and improvement recommendations.
    
    Call this at the START of an investigation to get self-improvement hints.
    
    Returns:
        JSON with investigation history summary and improvement recommendations
    """
    with tracer.start_as_current_span(
        "self_introspect_history",
        attributes={
            SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.CHAIN.value,
            "introspection.type": "history_query",
        },
    ) as span:
        phoenix_data = {}
        
        # Try to query Phoenix via Client SDK
        try:
            client = _get_phoenix_client()
            if client:
                # Get recent spans from our project
                spans_df = client.spans.get_spans_dataframe(
                    project_identifier=PHOENIX_PROJECT,
                    limit=50,
                    root_spans_only=True,
                )
                phoenix_data = {
                    "total_traces": len(spans_df) if spans_df is not None else 0,
                    "connected": True,
                }
                
                # Try to get annotations (eval results)
                try:
                    annotations_df = client.spans.get_span_annotations_dataframe(
                        spans_dataframe=spans_df,
                        project_identifier=PHOENIX_PROJECT,
                    )
                    if annotations_df is not None and len(annotations_df) > 0:
                        phoenix_data["annotations_count"] = len(annotations_df)
                except Exception:
                    pass
        except Exception as e:
            phoenix_data = {"connected": False, "reason": str(e)[:100]}
        
        # Load local improvement history
        from sift_defender.phoenix.improvement_loop import ImprovementLoop
        loop = ImprovementLoop()
        hints = loop.get_pre_investigation_hints()
        trend = loop.get_accuracy_trend()
        tool_effectiveness = loop.get_tool_effectiveness()
        
        output = {
            "success": True,
            "tool": "phoenix_query_past_investigations",
            "phoenix_client": phoenix_data,
            "investigation_count": trend.get("investigations", 0),
            "accuracy_trend": trend,
            "tool_effectiveness": tool_effectiveness,
            "self_improvement_hints": hints,
            "recommendation": _generate_recommendation(trend, hints),
        }
        
        span.set_attribute(SpanAttributes.OUTPUT_VALUE, json.dumps(output)[:1000])
        return json.dumps(output, default=str)[:4000]


def phoenix_query_my_hallucinations() -> str:
    """Query Phoenix for your hallucination history — what did you get wrong?
    
    Uses Phoenix Client SDK to query guardrail spans and annotations.
    Returns specific patterns of hallucinations you've made in the past,
    so you can avoid making the same mistakes again.
    
    Call this BEFORE making claims to check if you've hallucinated on
    similar topics before.
    
    Returns:
        JSON with hallucination patterns and avoidance strategies
    """
    with tracer.start_as_current_span(
        "self_introspect_hallucinations",
        attributes={
            SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.CHAIN.value,
            "introspection.type": "hallucination_query",
        },
    ) as span:
        phoenix_guardrail_data = []
        
        # Query Phoenix for guardrail spans via Client SDK
        try:
            client = _get_phoenix_client()
            if client:
                from phoenix.trace.dsl import SpanQuery
                query = SpanQuery().where("name == 'guardrail_pipeline'").select(
                    action="attributes.guardrail\\.action",
                    score="attributes.guardrail\\.score",
                    passed="attributes.guardrail\\.passed",
                )
                guardrail_df = client.spans.get_spans_dataframe(
                    query=query,
                    project_identifier=PHOENIX_PROJECT,
                    limit=30,
                )
                if guardrail_df is not None and len(guardrail_df) > 0:
                    blocked = guardrail_df[guardrail_df.get("action") == "BLOCK"] if "action" in guardrail_df.columns else []
                    phoenix_guardrail_data = [{
                        "total_guardrail_spans": len(guardrail_df),
                        "blocked_count": len(blocked) if hasattr(blocked, '__len__') else 0,
                    }]
        except Exception:
            pass  # Client may not be available
        
        # Get local hallucination data from improvement loop
        from sift_defender.phoenix.improvement_loop import ImprovementLoop
        loop = ImprovementLoop()
        
        all_mistakes = []
        for record in loop.history:
            all_mistakes.extend(record.get("mistakes_made", []))
        
        # Count patterns
        mistake_patterns = {}
        for m in all_mistakes:
            key = m.lower()[:100]
            mistake_patterns[key] = mistake_patterns.get(key, 0) + 1
        
        # Sort by frequency
        top_mistakes = sorted(mistake_patterns.items(), key=lambda x: -x[1])[:10]
        
        output = {
            "success": True,
            "tool": "phoenix_query_my_hallucinations",
            "total_blocked_findings": sum(r.get("blocked_count", 0) for r in loop.history),
            "total_investigations": len(loop.history),
            "hallucination_patterns": [
                {"pattern": p, "count": c, "avoidance": _avoidance_strategy(p)}
                for p, c in top_mistakes
            ],
            "phoenix_guardrail_data": phoenix_guardrail_data,
            "critical_rules": [
                "NEVER claim execution without Prefetch or Event 4688",
                "NEVER claim C2/network without netscan/pcap/firewall evidence",
                "NEVER claim CONFIRMED with only 1 source",
                "NEVER claim lateral movement without logon events (4624 Type 3/10)",
                "Amcache/Shimcache = PRESENCE only, never execution",
            ],
        }
        
        span.set_attribute(SpanAttributes.OUTPUT_VALUE, json.dumps(output)[:1000])
        return json.dumps(output, default=str)[:4000]


def phoenix_evaluate_my_finding(finding_title: str, evidence_summary: str, confidence: str) -> str:
    """Self-evaluate a finding BEFORE presenting it to the user.
    
    Call this on each major finding to check if it would pass the guardrail.
    This is the agent doing its OWN quality check before committing to a claim.
    
    Args:
        finding_title: Title of the finding you're about to make
        evidence_summary: What evidence supports this finding
        confidence: Your proposed confidence level (CONFIRMED/INFERRED/UNVERIFIED)
    
    Returns:
        JSON with self-evaluation result (would this pass guardrails?)
    """
    with tracer.start_as_current_span(
        "self_evaluate_finding",
        attributes={
            SpanAttributes.OPENINFERENCE_SPAN_KIND: "EVALUATOR",
            SpanAttributes.INPUT_VALUE: json.dumps({
                "title": finding_title,
                "confidence": confidence,
            }),
            "self_eval.title": finding_title,
            "self_eval.confidence": confidence,
        },
    ) as span:
        issues = []
        
        title_lower = finding_title.lower()
        evidence_lower = evidence_summary.lower()
        
        # Rule 1: CONFIRMED needs multiple sources
        if confidence == "CONFIRMED":
            source_indicators = ["splunk", "prefetch", "event log", "4688", "registry", "mft", "amcache"]
            sources_found = sum(1 for s in source_indicators if s in evidence_lower)
            if sources_found < 2:
                issues.append(f"CONFIRMED needs 2+ sources. Only found ~{sources_found} source indicators in evidence.")
        
        # Rule 2: Execution claims
        if any(w in title_lower for w in ["executed", "ran", "launched", "started"]):
            if "prefetch" not in evidence_lower and "4688" not in evidence_lower and "process" not in evidence_lower:
                issues.append("Execution claim without Prefetch/Event 4688/process evidence. Consider downgrading to INFERRED.")
        
        # Rule 3: Network claims
        if any(w in title_lower for w in ["c2", "beacon", "exfiltration", "download", "communication"]):
            if "network" not in evidence_lower and "netscan" not in evidence_lower and "connection" not in evidence_lower and "dns" not in evidence_lower:
                issues.append("Network claim without network evidence. Will be BLOCKED by guardrail.")
        
        # Rule 4: Lateral movement
        if "lateral" in title_lower:
            if "4624" not in evidence_lower and "logon" not in evidence_lower and "rdp" not in evidence_lower:
                issues.append("Lateral movement claim without logon event evidence.")
        
        # Rule 5: Check against past hallucination patterns
        from sift_defender.phoenix.improvement_loop import ImprovementLoop
        loop = ImprovementLoop()
        for record in loop.history[-5:]:
            for mistake in record.get("mistakes_made", []):
                if any(w in mistake.lower() for w in title_lower.split()[:3]):
                    issues.append(f"Similar to past mistake: {mistake[:80]}")
                    break
        
        # Decision
        if len(issues) >= 2:
            verdict = "WOULD_BE_BLOCKED"
            recommendation = "Do NOT present this finding. Gather more evidence first."
        elif len(issues) == 1:
            verdict = "WOULD_BE_FLAGGED"
            recommendation = "Finding will need human review. Consider gathering more evidence."
        else:
            verdict = "WOULD_PASS"
            recommendation = "Finding looks well-grounded. Safe to present."
        
        output = {
            "success": True,
            "tool": "phoenix_evaluate_my_finding",
            "verdict": verdict,
            "issues": issues,
            "recommendation": recommendation,
            "confidence_suggestion": _suggest_confidence(confidence, issues),
        }
        
        span.set_attribute(SpanAttributes.OUTPUT_VALUE, json.dumps(output))
        span.set_attribute("self_eval.verdict", verdict)
        span.set_attribute("self_eval.issues_count", len(issues))
        
        return json.dumps(output)


def phoenix_log_self_improvement(original_action: str, improved_action: str, reason: str) -> str:
    """Log when you change your approach based on self-introspection.
    
    Call this when you decide to do something differently because of what
    you learned from your own operational data. This creates visible evidence
    of self-improvement in Phoenix traces.
    
    Args:
        original_action: What you were going to do
        improved_action: What you're doing instead  
        reason: Why you changed (what self-introspection told you)
    
    Returns:
        JSON confirming the improvement was logged
    """
    with tracer.start_as_current_span(
        "self_improvement_applied",
        attributes={
            SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.CHAIN.value,
            SpanAttributes.INPUT_VALUE: json.dumps({
                "original": original_action,
                "improved": improved_action,
                "reason": reason,
            }),
            "improvement.original": original_action[:200],
            "improvement.new": improved_action[:200],
            "improvement.reason": reason[:200],
            "improvement.visible": True,  # Flag for Phoenix dashboard
        },
    ) as span:
        span.set_attribute(SpanAttributes.OUTPUT_VALUE, 
            f"Self-improvement logged: {reason}")
        
        return json.dumps({
            "success": True,
            "tool": "phoenix_log_self_improvement",
            "logged": True,
            "message": f"Improvement recorded in Phoenix. Original: {original_action[:100]}, New: {improved_action[:100]}, Because: {reason[:100]}",
        })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HELPER FUNCTIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _generate_recommendation(trend: dict, hints: list[str]) -> str:
    """Generate a natural-language recommendation from trends."""
    if trend.get("investigations", 0) == 0:
        return "First investigation. Use default forensic best practices."
    
    accuracy = trend.get("current_accuracy", 1.0)
    improving = trend.get("improving")
    
    if accuracy >= 0.95:
        return "Your accuracy is excellent. Maintain current approach."
    elif accuracy >= 0.8:
        return f"Accuracy at {accuracy:.0%}. Focus on: {hints[0] if hints else 'reducing false positives'}"
    else:
        return f"Accuracy needs improvement ({accuracy:.0%}). Be very conservative with CONFIRMED claims."


def _avoidance_strategy(pattern: str) -> str:
    """Generate avoidance strategy for a hallucination pattern."""
    p = pattern.lower()
    if "network" in p or "c2" in p:
        return "Require netscan/pcap/firewall log before claiming network activity"
    if "execution" in p or "executed" in p:
        return "Require Prefetch or Event 4688 before claiming execution"
    if "confirmed" in p and "source" in p:
        return "Only use CONFIRMED when 2+ independent sources agree"
    if "lateral" in p:
        return "Require Event 4624 Type 3/10 before claiming lateral movement"
    return "Gather additional corroborating evidence before making this claim"


def _suggest_confidence(proposed: str, issues: list[str]) -> str:
    """Suggest appropriate confidence level."""
    if not issues:
        return proposed  # Keep as-is
    if proposed == "CONFIRMED" and len(issues) >= 1:
        return "INFERRED (downgrade — insufficient corroboration for CONFIRMED)"
    if len(issues) >= 2:
        return "UNVERIFIED (too many issues — needs more evidence)"
    return proposed
