"""Self-Correction Engine — the core differentiator.

This module runs BETWEEN agent iterations to:
1. Check findings for internal consistency (deterministic rules)
2. Detect gaps in the investigation (what hasn't been checked)
3. Score confidence based on independent source count
4. Determine whether to continue or converge

All decisions are traced to Arize for visibility.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from opentelemetry import trace as trace_api
from openinference.semconv.trace import SpanAttributes, OpenInferenceSpanKindValues


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"       # 2+ independent sources corroborate
    INFERRED = "INFERRED"         # 1 source + logical deduction
    UNVERIFIED = "UNVERIFIED"     # Single source, no cross-check
    CONTRADICTED = "CONTRADICTED" # Sources disagree


@dataclass
class Contradiction:
    finding_a_id: str
    finding_b_id: str
    description: str
    suggested_resolution: str


@dataclass
class Gap:
    description: str
    priority: str  # high, medium, low
    suggested_tool: str
    reason: str


@dataclass
class SelfCorrectionResult:
    iteration: int
    contradictions: list[Contradiction] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    confidence_updates: dict[str, str] = field(default_factory=dict)
    should_continue: bool = True
    convergence_reason: str = ""
    next_action: str = ""


# ──────────────────────────────────────────────────
# CONSISTENCY RULES (Deterministic — no LLM needed)
# ──────────────────────────────────────────────────

CONSISTENCY_RULES = [
    {
        "name": "amcache_without_prefetch",
        "condition": "Binary found in Amcache but NOT in Prefetch",
        "explanation": "Amcache proves PRESENCE, Prefetch proves EXECUTION. Missing Prefetch doesn't mean no execution — scheduled tasks and services may not generate Prefetch.",
        "action": "Check scheduled tasks and services before concluding 'not executed'.",
        "suggested_tool": "get_scheduled_tasks",
    },
    {
        "name": "service_install_without_binary",
        "condition": "Event 7045 (service installed) but no corresponding binary in MFT",
        "explanation": "Service was installed but binary isn't on disk. Possible: binary pre-staged earlier, loaded from ADS, or deleted after install.",
        "action": "Check MFT for earlier file creation, check ADS, check USN journal for deletion.",
        "suggested_tool": "parse_usn_journal",
    },
    {
        "name": "process_in_memory_not_disk",
        "condition": "Process found in memory (pslist) but no binary on disk",
        "explanation": "Process is running but binary was deleted (or is fileless/injected).",
        "action": "Check malfind for injection, check filescan for memory-resident file objects.",
        "suggested_tool": "vol_malfind",
    },
    {
        "name": "network_connection_no_process",
        "condition": "Network connection in netscan but owning PID not in pslist",
        "explanation": "Connection exists but process terminated. Or PID was reused.",
        "action": "Check process tree for terminated processes, check event logs for process exit.",
        "suggested_tool": "vol_pstree",
    },
    {
        "name": "timestamp_inconsistency",
        "condition": "Timestamps in the same attack chain are not chronologically ordered",
        "explanation": "If event B (caused by A) has an earlier timestamp than A, timestamps may be manipulated.",
        "action": "Cross-reference with USN journal and event logs (harder to manipulate).",
        "suggested_tool": "parse_usn_journal",
    },
    {
        "name": "event_log_gap",
        "condition": "Expected event log entries missing for a confirmed action",
        "explanation": "Event logs may have been cleared. Check for Event 1102 (Security log cleared) or Event 104 (System log cleared).",
        "action": "Check for log clearing events, check if log retention explains the gap.",
        "suggested_tool": "parse_evtx",
    },
]

# ──────────────────────────────────────────────────
# GAP DETECTION RULES
# ──────────────────────────────────────────────────

GAP_RULES = [
    {
        "finding_type": "unknown_binary",
        "required_checks": ["amcache", "prefetch", "scheduled_tasks", "services", "evtx_4688"],
        "description": "Unknown binary found — need to determine if/how it executed",
    },
    {
        "finding_type": "persistence_mechanism",
        "required_checks": ["parent_process", "creation_timestamp", "binary_hash"],
        "description": "Persistence found — need to trace who created it and when",
    },
    {
        "finding_type": "network_connection",
        "required_checks": ["process_identification", "threat_intel_lookup", "dns_resolution"],
        "description": "Network IOC found — need to identify process and validate against threat intel",
    },
    {
        "finding_type": "lateral_movement",
        "required_checks": ["source_host_investigation", "credential_analysis", "timeline_correlation"],
        "description": "Lateral movement suspected — need to investigate source and credentials used",
    },
]


class SelfCorrectionEngine:
    """Runs between iterations to check consistency, detect gaps, and score confidence."""

    def __init__(self):
        self.tracer = trace_api.get_tracer("sift_defender.self_correction")
        self.iteration = 0
        self.previous_finding_count = 0
        self.empty_iterations = 0  # Track consecutive iterations with no new findings
        self.max_iterations = 15
        self.convergence_threshold = 3  # Stop after N empty iterations

    def run_check(
        self,
        findings: list[dict],
        tools_run: list[str],
    ) -> SelfCorrectionResult:
        """Run full self-correction check after a sub-agent returns.
        
        Args:
            findings: All findings accumulated so far.
            tools_run: List of tool names already executed.
        
        Returns:
            SelfCorrectionResult with contradictions, gaps, and next action.
        """
        self.iteration += 1

        with self.tracer.start_as_current_span(
            name=f"self_correction_iteration_{self.iteration}",
            attributes={
                SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.CHAIN.value,
                SpanAttributes.INPUT_VALUE: json.dumps({
                    "iteration": self.iteration,
                    "findings_count": len(findings),
                    "tools_run_count": len(tools_run),
                }),
                "self_correction.iteration": self.iteration,
            },
        ) as span:
            # 1. Check consistency
            contradictions = self._check_consistency(findings)

            # 2. Detect gaps
            gaps = self._detect_gaps(findings, tools_run)

            # 3. Score confidence
            confidence_updates = self._score_confidence(findings)

            # 4. Should we continue?
            should_continue, convergence_reason = self._should_continue(findings)

            # 5. Determine next action
            next_action = self._determine_next_action(contradictions, gaps)

            result = SelfCorrectionResult(
                iteration=self.iteration,
                contradictions=contradictions,
                gaps=gaps,
                confidence_updates=confidence_updates,
                should_continue=should_continue,
                convergence_reason=convergence_reason,
                next_action=next_action,
            )

            # Record in Arize span
            span.set_attribute(SpanAttributes.OUTPUT_VALUE, json.dumps({
                "contradictions_count": len(contradictions),
                "gaps_count": len(gaps),
                "confidence_updates": confidence_updates,
                "should_continue": should_continue,
                "convergence_reason": convergence_reason,
                "next_action": next_action,
            }, default=str))
            span.set_attribute("self_correction.contradictions_found", len(contradictions))
            span.set_attribute("self_correction.gaps_found", len(gaps))
            span.set_attribute("self_correction.should_continue", should_continue)

            if contradictions:
                span.set_attribute("self_correction.triggered", True)
                span.set_attribute(
                    "self_correction.trigger_reason",
                    contradictions[0].description,
                )

            return result

    def _check_consistency(self, findings: list[dict]) -> list[Contradiction]:
        """Apply deterministic consistency rules to findings."""
        contradictions = []

        # Extract finding attributes for rule matching
        has_amcache = any("amcache" in str(f.get("source", "")).lower() for f in findings)
        has_prefetch = any("prefetch" in str(f.get("source", "")).lower() for f in findings)
        has_service_install = any("7045" in str(f.get("event_id", "")) for f in findings)
        has_memory_process = any("pslist" in str(f.get("source", "")).lower() for f in findings)
        has_disk_binary = any("mft" in str(f.get("source", "")).lower() for f in findings)

        # Rule: Amcache without Prefetch
        if has_amcache and not has_prefetch:
            # Check if we've already investigated this
            amcache_findings = [f for f in findings if "amcache" in str(f.get("source", "")).lower()]
            for af in amcache_findings:
                binary_name = af.get("binary_name", af.get("title", ""))
                # Check if we have a corresponding prefetch finding
                prefetch_match = any(
                    binary_name.lower() in str(f.get("title", "")).lower()
                    for f in findings
                    if "prefetch" in str(f.get("source", "")).lower()
                )
                if not prefetch_match and binary_name:
                    contradictions.append(Contradiction(
                        finding_a_id=af.get("id", "unknown"),
                        finding_b_id="",
                        description=f"Binary '{binary_name}' found in Amcache but has no Prefetch entry. "
                                    f"This could mean: (a) never executed interactively, "
                                    f"(b) runs via scheduled task/service, (c) Prefetch was cleared.",
                        suggested_resolution="Check scheduled tasks and services for this binary.",
                    ))

        # Rule: Process in memory but not on disk
        if has_memory_process and not has_disk_binary:
            contradictions.append(Contradiction(
                finding_a_id="memory_findings",
                finding_b_id="disk_findings",
                description="Process found in memory but corresponding binary not confirmed on disk. "
                            "Possible: deleted binary, fileless malware, or memory-only payload.",
                suggested_resolution="Run vol_filescan() and check for deleted file objects. "
                                     "Run vol_malfind() for injected code.",
            ))

        return contradictions

    def _detect_gaps(self, findings: list[dict], tools_run: list[str]) -> list[Gap]:
        """Identify what hasn't been checked based on what we've found."""
        gaps = []

        tools_lower = [t.lower() for t in tools_run]

        # If we found unknown binaries but haven't checked prefetch
        has_unknown_binary = any("unknown" in str(f.get("type", "")).lower() for f in findings)
        if has_unknown_binary and "parse_prefetch" not in tools_lower:
            gaps.append(Gap(
                description="Unknown binary detected but Prefetch not yet checked",
                priority="high",
                suggested_tool="parse_prefetch",
                reason="Need to determine if the binary was executed",
            ))

        # If we found persistence but haven't traced parent process
        has_persistence = any("persist" in str(f.get("type", "")).lower() or
                            "scheduled" in str(f.get("title", "")).lower() or
                            "service" in str(f.get("title", "")).lower()
                            for f in findings)
        if has_persistence and "parse_evtx" not in tools_lower:
            gaps.append(Gap(
                description="Persistence mechanism found but haven't traced who created it",
                priority="high",
                suggested_tool="parse_evtx",
                reason="Event 4688 (process creation) will show parent process",
            ))

        # If we have findings but haven't done correlation
        if len(findings) >= 3 and "cross_reference_findings" not in tools_lower:
            gaps.append(Gap(
                description="Multiple findings accumulated but not yet cross-referenced",
                priority="medium",
                suggested_tool="cross_reference_findings",
                reason="Cross-referencing may reveal corroboration or contradictions",
            ))

        # If we haven't extracted IOCs
        if len(findings) >= 2 and "extract_iocs" not in tools_lower:
            gaps.append(Gap(
                description="Findings available but IOCs not yet extracted",
                priority="low",
                suggested_tool="extract_iocs",
                reason="IOCs needed for blocking and threat intel lookup",
            ))

        return gaps

    def _score_confidence(self, findings: list[dict]) -> dict[str, str]:
        """Score confidence for each finding based on corroborating sources."""
        updates = {}

        for finding in findings:
            fid = finding.get("id", "unknown")
            sources = finding.get("sources", [])
            current_confidence = finding.get("confidence", Confidence.UNVERIFIED)

            if len(sources) >= 2:
                new_confidence = Confidence.CONFIRMED
            elif len(sources) == 1:
                new_confidence = Confidence.INFERRED
            else:
                new_confidence = Confidence.UNVERIFIED

            if new_confidence != current_confidence:
                updates[fid] = new_confidence
                finding["confidence"] = new_confidence

        return updates

    def _should_continue(self, findings: list[dict]) -> tuple[bool, str]:
        """Determine whether to continue investigating or converge."""
        current_count = len(findings)

        # Check if we've found new things
        if current_count == self.previous_finding_count:
            self.empty_iterations += 1
        else:
            self.empty_iterations = 0

        self.previous_finding_count = current_count

        # Convergence conditions
        if self.iteration >= self.max_iterations:
            return False, f"Max iterations reached ({self.max_iterations})"

        if self.empty_iterations >= self.convergence_threshold:
            return False, f"No new findings in {self.convergence_threshold} consecutive iterations"

        # Check if all findings are CONFIRMED or have contradictions resolved
        unresolved = [f for f in findings if f.get("confidence") == Confidence.CONTRADICTED]
        if not unresolved and current_count > 0 and self.iteration >= 3:
            # All contradictions resolved and we have findings
            if self.empty_iterations >= 1:
                return False, "All findings consistent, no new leads"

        return True, ""

    def _determine_next_action(
        self, contradictions: list[Contradiction], gaps: list[Gap]
    ) -> str:
        """Determine what the orchestrator should do next."""
        if contradictions:
            return f"RESOLVE_CONTRADICTION: {contradictions[0].suggested_resolution}"

        high_gaps = [g for g in gaps if g.priority == "high"]
        if high_gaps:
            return f"FILL_GAP: {high_gaps[0].description} (use {high_gaps[0].suggested_tool})"

        medium_gaps = [g for g in gaps if g.priority == "medium"]
        if medium_gaps:
            return f"FILL_GAP: {medium_gaps[0].description} (use {medium_gaps[0].suggested_tool})"

        return "CONTINUE_OR_CONVERGE"

    def get_journal_entry(self, result: SelfCorrectionResult) -> str:
        """Generate a markdown journal entry for this iteration's self-correction."""
        lines = [
            f"\n## Self-Correction Check — Iteration {result.iteration}",
            f"**Time**: {datetime.now(timezone.utc).isoformat()}",
            "",
        ]

        if result.contradictions:
            lines.append("### ⚠️ Contradictions Detected")
            for c in result.contradictions:
                lines.append(f"- **{c.description}**")
                lines.append(f"  - Resolution: {c.suggested_resolution}")
            lines.append("")

        if result.gaps:
            lines.append("### 🔍 Gaps Identified")
            for g in result.gaps:
                lines.append(f"- [{g.priority.upper()}] {g.description}")
                lines.append(f"  - Suggested: `{g.suggested_tool}` — {g.reason}")
            lines.append("")

        if result.confidence_updates:
            lines.append("### 📊 Confidence Updates")
            for fid, conf in result.confidence_updates.items():
                lines.append(f"- {fid}: → **{conf}**")
            lines.append("")

        lines.append(f"### Decision: {'CONTINUE' if result.should_continue else 'CONVERGE'}")
        if result.convergence_reason:
            lines.append(f"Reason: {result.convergence_reason}")
        if result.next_action:
            lines.append(f"Next: {result.next_action}")

        return "\n".join(lines)
