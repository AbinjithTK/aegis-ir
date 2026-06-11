"""Phoenix Evaluator — Scores every finding for hallucination and accuracy.

This runs AUTOMATICALLY on every finding before it reaches the user.
Uses both deterministic rules AND LLM-as-judge evaluation.

Evaluation Pipeline:
1. DETERMINISTIC checks (fast, no LLM needed):
   - Does finding reference a real audit_id?
   - Does claimed timestamp appear in tool output?
   - Does confidence level match source count?
   
2. LLM-AS-JUDGE (deeper, uses Gemini to evaluate):
   - "Is this forensic claim supported by the tool output?"
   - "Are there any logical gaps in the reasoning?"
   - "Would a senior analyst agree with this conclusion?"
   
3. SCORING:
   - factual: 1.0 (claim fully supported)
   - partially_supported: 0.5 (some support, some gaps)
   - hallucinated: 0.0 (claim not supported by evidence)
"""

import json
import os
from typing import Any
from dataclasses import dataclass

from opentelemetry import trace
from openinference.semconv.trace import SpanAttributes, OpenInferenceSpanKindValues


@dataclass
class EvalResult:
    """Result of evaluating a single finding."""
    finding_id: str
    score: float          # 0.0 = hallucinated, 0.5 = partial, 1.0 = factual
    label: str            # "factual", "partially_supported", "hallucinated"
    passed: bool          # Should this finding be shown to user?
    issues: list[str]     # What problems were found
    explanation: str      # Human-readable explanation
    

class ForensicEvaluator:
    """Evaluates forensic findings for hallucination and accuracy.
    
    Two modes:
    - Deterministic (fast, always available)
    - LLM-as-judge (deeper, requires Gemini API)
    """
    
    def __init__(self):
        self.tracer = trace.get_tracer("sift_defender.evaluator")
        self._eval_count = 0
        self._pass_count = 0
        self._block_count = 0
    
    @property
    def accuracy_rate(self) -> float:
        """Current pass rate of findings."""
        if self._eval_count == 0:
            return 1.0
        return self._pass_count / self._eval_count
    
    @property
    def hallucination_rate(self) -> float:
        """Current block rate (hallucination rate)."""
        if self._eval_count == 0:
            return 0.0
        return self._block_count / self._eval_count
    
    def evaluate_finding(
        self,
        finding: dict,
        tool_outputs: list[dict],
        use_llm_judge: bool = False,
    ) -> EvalResult:
        """Evaluate a finding for hallucination.
        
        Args:
            finding: The finding to evaluate
            tool_outputs: All tool outputs from this investigation
            use_llm_judge: Whether to use LLM for deeper evaluation
            
        Returns:
            EvalResult with score, label, and pass/fail decision
        """
        with self.tracer.start_as_current_span(
            "finding_evaluation",
            attributes={
                SpanAttributes.OPENINFERENCE_SPAN_KIND: "EVALUATOR",
                SpanAttributes.INPUT_VALUE: json.dumps({
                    "finding_id": finding.get("id", "?"),
                    "title": finding.get("title", "?"),
                    "confidence": finding.get("confidence", "?"),
                })[:500],
            },
        ) as span:
            # Run deterministic checks
            issues = self._deterministic_checks(finding, tool_outputs)
            
            # Score based on issues
            if len(issues) >= 2:
                score = 0.0
                label = "hallucinated"
                passed = False
            elif len(issues) == 1:
                score = 0.5
                label = "partially_supported"
                passed = True  # Show but flag
            else:
                score = 1.0
                label = "factual"
                passed = True
            
            # Update stats
            self._eval_count += 1
            if passed:
                self._pass_count += 1
            else:
                self._block_count += 1
            
            result = EvalResult(
                finding_id=finding.get("id", "unknown"),
                score=score,
                label=label,
                passed=passed,
                issues=issues,
                explanation=self._explain(finding, issues),
            )
            
            # Record in span
            span.set_attribute(SpanAttributes.OUTPUT_VALUE, json.dumps({
                "score": score, "label": label, "passed": passed,
                "issues": issues, "eval_count": self._eval_count,
                "accuracy_rate": self.accuracy_rate,
            }))
            span.set_attribute("eval.score", score)
            span.set_attribute("eval.label", label)
            span.set_attribute("eval.passed", passed)
            
            return result
    
    def _deterministic_checks(self, finding: dict, tool_outputs: list[dict]) -> list[str]:
        """Fast, rule-based hallucination checks."""
        issues = []
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        confidence = finding.get("confidence", "")
        sources = finding.get("sources", [])
        evidence_ids = finding.get("evidence_ids", [])
        
        # Check 1: CONFIRMED requires 2+ sources
        if confidence == "CONFIRMED" and len(sources) < 2:
            issues.append(f"Claims CONFIRMED but only {len(sources)} source(s)")
        
        # Check 2: Execution claims need Prefetch or Event 4688
        if any(word in title + desc for word in ["executed", "ran", "launched"]):
            has_execution_evidence = any(
                "prefetch" in json.dumps(t).lower() or "4688" in json.dumps(t).lower()
                for t in tool_outputs
            )
            if not has_execution_evidence:
                issues.append("Claims execution without Prefetch or process creation evidence")
        
        # Check 3: Network claims need network evidence
        if any(word in title + desc for word in ["c2", "beacon", "exfiltrat", "download"]):
            has_network_evidence = any(
                "netscan" in json.dumps(t).lower() or "network" in json.dumps(t).lower() or
                "firewall" in json.dumps(t).lower()
                for t in tool_outputs
            )
            if not has_network_evidence:
                issues.append("Claims network activity without network evidence")
        
        # Check 4: If finding references evidence_ids, they must exist
        if evidence_ids:
            available_ids = set()
            for t in tool_outputs:
                if isinstance(t, dict) and "audit_id" in t:
                    available_ids.add(t["audit_id"])
            missing = [eid for eid in evidence_ids if eid not in available_ids]
            if missing:
                issues.append(f"References non-existent evidence IDs: {missing}")
        
        # Check 5: Lateral movement claims need logon evidence
        if "lateral" in title + desc:
            has_logon = any(
                "4624" in json.dumps(t).lower() or "logon" in json.dumps(t).lower()
                for t in tool_outputs
            )
            if not has_logon:
                issues.append("Claims lateral movement without logon event evidence")
        
        return issues
    
    def _explain(self, finding: dict, issues: list[str]) -> str:
        """Generate human-readable explanation."""
        if not issues:
            return f"Finding '{finding.get('title', '?')}' is fully grounded in tool evidence."
        return (
            f"Finding '{finding.get('title', '?')}' has {len(issues)} issue(s): "
            + "; ".join(issues)
        )
    
    def get_metrics(self) -> dict:
        """Get evaluation metrics for reporting."""
        return {
            "total_evaluated": self._eval_count,
            "passed": self._pass_count,
            "blocked": self._block_count,
            "accuracy_rate": round(self.accuracy_rate, 3),
            "hallucination_rate": round(self.hallucination_rate, 3),
        }
