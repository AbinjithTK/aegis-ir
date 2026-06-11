"""Phoenix Self-Improvement Loop — Agent learns from its own history.

This implements the CONTINUOUS IMPROVEMENT cycle:

1. After each investigation → store results + eval scores in Phoenix
2. Before next investigation → query Phoenix: "What did I get wrong?"
3. Adjust agent behavior based on failure patterns
4. Measure improvement over time

The Phoenix MCP server (@arizeai/phoenix-mcp) enables this by giving
the agent runtime access to its own trace/eval data.

IMPROVEMENT STRATEGIES:
- Tool selection: "Last time I missed the scheduled task check. Add it to priority list."
- Confidence calibration: "I over-claimed CONFIRMED 30% of the time. Be more conservative."
- Hallucination avoidance: "I hallucinate network claims 15% of the time. Always require evidence."
- Investigation sequencing: "Checking Prefetch BEFORE making claims about execution saves time."
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from opentelemetry import trace
from openinference.semconv.trace import SpanAttributes, OpenInferenceSpanKindValues


class InvestigationRecord:
    """Record of a completed investigation (stored for learning)."""
    
    def __init__(
        self,
        case_id: str,
        evidence_type: str,
        findings_count: int,
        confirmed_count: int,
        inferred_count: int,
        blocked_count: int,
        self_corrections: int,
        accuracy_rate: float,
        hallucination_rate: float,
        tools_used: list[str],
        mistakes_made: list[str],
        investigation_time_seconds: float,
    ):
        self.case_id = case_id
        self.evidence_type = evidence_type
        self.findings_count = findings_count
        self.confirmed_count = confirmed_count
        self.inferred_count = inferred_count
        self.blocked_count = blocked_count
        self.self_corrections = self_corrections
        self.accuracy_rate = accuracy_rate
        self.hallucination_rate = hallucination_rate
        self.tools_used = tools_used
        self.mistakes_made = mistakes_made
        self.investigation_time_seconds = investigation_time_seconds
        self.timestamp = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> dict:
        return self.__dict__


class ImprovementLoop:
    """Tracks agent performance across investigations and generates improvement hints.
    
    Stores investigation records locally (JSON file) and uses them to:
    - Identify recurring failure patterns
    - Generate pre-investigation hints ("Watch out for X")
    - Track accuracy improvement over time
    - Provide metrics for the Phoenix dashboard
    """
    
    HISTORY_FILE = Path("/cases/improvement_history.json")
    
    def __init__(self):
        self.tracer = trace.get_tracer("sift_defender.improvement")
        self.history: list[dict] = self._load_history()
    
    def record_investigation(self, record: InvestigationRecord):
        """Store a completed investigation for future learning."""
        self.history.append(record.to_dict())
        self._save_history()
        
        with self.tracer.start_as_current_span(
            "improvement_record",
            attributes={
                SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.CHAIN.value,
                SpanAttributes.INPUT_VALUE: json.dumps(record.to_dict()),
                "improvement.case_id": record.case_id,
                "improvement.accuracy": record.accuracy_rate,
                "improvement.hallucination_rate": record.hallucination_rate,
            },
        ):
            pass
    
    def get_pre_investigation_hints(self, evidence_type: str = "windows_disk") -> list[str]:
        """Generate hints based on past mistakes.
        
        Called BEFORE an investigation starts to prime the agent
        with lessons learned from previous runs.
        
        Args:
            evidence_type: Type of evidence about to be analyzed
            
        Returns:
            List of hints like "Don't claim execution without Prefetch"
        """
        hints = []
        
        if not self.history:
            # First investigation — return default forensic wisdom
            return [
                "Remember: Amcache proves PRESENCE only, never claim execution from it alone.",
                "Check scheduled tasks if a binary has no Prefetch entry.",
                "Always cross-reference timestamps from multiple sources.",
                "Don't claim C2/network activity without network evidence (netscan/pcap).",
            ]
        
        # Analyze past mistakes
        all_mistakes = []
        for record in self.history:
            all_mistakes.extend(record.get("mistakes_made", []))
        
        # Count recurring patterns
        mistake_counts = {}
        for m in all_mistakes:
            key = m.lower()
            mistake_counts[key] = mistake_counts.get(key, 0) + 1
        
        # Generate hints from top mistakes
        for mistake, count in sorted(mistake_counts.items(), key=lambda x: -x[1])[:5]:
            if count >= 2:
                hints.append(f"⚠️ Recurring issue ({count}x): {mistake}")
        
        # Check accuracy trend
        recent = self.history[-5:]
        avg_accuracy = sum(r.get("accuracy_rate", 1.0) for r in recent) / len(recent)
        if avg_accuracy < 0.9:
            hints.append(f"⚠️ Recent accuracy: {avg_accuracy:.0%}. Be more conservative with CONFIRMED claims.")
        
        # Check hallucination trend
        avg_hallucination = sum(r.get("hallucination_rate", 0) for r in recent) / len(recent)
        if avg_hallucination > 0.05:
            hints.append(f"⚠️ Hallucination rate: {avg_hallucination:.0%}. Verify every claim against tool output.")
        
        # Default hints if no patterns found
        if not hints:
            hints = ["Past investigations show good accuracy. Maintain current approach."]
        
        return hints
    
    def get_accuracy_trend(self) -> dict:
        """Get accuracy metrics over time for the Phoenix dashboard."""
        if not self.history:
            return {"investigations": 0, "trend": "no_data"}
        
        accuracies = [r.get("accuracy_rate", 0) for r in self.history]
        
        # Compare first half to second half
        mid = len(accuracies) // 2
        if mid > 0:
            first_half = sum(accuracies[:mid]) / mid
            second_half = sum(accuracies[mid:]) / (len(accuracies) - mid)
            improving = second_half > first_half
        else:
            improving = None
        
        return {
            "investigations": len(self.history),
            "current_accuracy": accuracies[-1] if accuracies else 0,
            "average_accuracy": sum(accuracies) / len(accuracies),
            "best_accuracy": max(accuracies),
            "worst_accuracy": min(accuracies),
            "improving": improving,
            "trend": "improving" if improving else "stable" if improving is None else "degrading",
        }
    
    def get_tool_effectiveness(self) -> dict:
        """Which tools produce the most reliable findings?"""
        tool_usage = {}
        for record in self.history:
            accuracy = record.get("accuracy_rate", 1.0)
            for tool in record.get("tools_used", []):
                if tool not in tool_usage:
                    tool_usage[tool] = {"uses": 0, "total_accuracy": 0}
                tool_usage[tool]["uses"] += 1
                tool_usage[tool]["total_accuracy"] += accuracy
        
        effectiveness = {}
        for tool, data in tool_usage.items():
            effectiveness[tool] = {
                "uses": data["uses"],
                "avg_accuracy_when_used": round(data["total_accuracy"] / data["uses"], 3),
            }
        
        return effectiveness
    
    def _load_history(self) -> list[dict]:
        """Load investigation history from disk."""
        if self.HISTORY_FILE.exists():
            try:
                return json.loads(self.HISTORY_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                return []
        return []
    
    def _save_history(self):
        """Save investigation history to disk."""
        try:
            self.HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            self.HISTORY_FILE.write_text(json.dumps(self.history, indent=2, default=str))
        except OSError:
            pass
