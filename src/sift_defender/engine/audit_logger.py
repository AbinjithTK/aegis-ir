"""Structured audit logger — JSONL format for full traceability.

Every tool execution, finding, self-correction decision, and agent action
is logged here. This satisfies hackathon requirement #8: Agent Execution Logs.

Format: One JSON object per line (JSONL), append-only.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sift_defender.tools.base import CASE_DIR


class AuditLogger:
    """Append-only structured logger for investigation audit trail."""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.audit_dir = CASE_DIR / "audit"
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.audit_dir / "execution.jsonl"

    def log_tool_execution(
        self,
        audit_id: str,
        tool_name: str,
        agent_name: str,
        arguments: dict,
        success: bool,
        output_summary: str = "",
        output_length: int = 0,
        duration_ms: float = 0,
    ):
        """Log a forensic tool execution."""
        self._write({
            "type": "tool_execution",
            "audit_id": audit_id,
            "tool": tool_name,
            "agent": agent_name,
            "arguments": arguments,
            "success": success,
            "output_summary": output_summary[:500],
            "output_length": output_length,
            "duration_ms": duration_ms,
        })

    def log_finding(
        self,
        finding_id: str,
        title: str,
        confidence: str,
        sources: list[str],
        evidence_audit_ids: list[str],
        agent_name: str,
    ):
        """Log a finding creation."""
        self._write({
            "type": "finding",
            "finding_id": finding_id,
            "title": title,
            "confidence": confidence,
            "sources": sources,
            "evidence_audit_ids": evidence_audit_ids,
            "agent": agent_name,
        })

    def log_self_correction(
        self,
        iteration: int,
        contradictions_count: int,
        gaps_count: int,
        triggered: bool,
        trigger_reason: str = "",
        action_taken: str = "",
    ):
        """Log a self-correction check."""
        self._write({
            "type": "self_correction",
            "iteration": iteration,
            "contradictions_count": contradictions_count,
            "gaps_count": gaps_count,
            "triggered": triggered,
            "trigger_reason": trigger_reason,
            "action_taken": action_taken,
        })

    def log_confidence_update(
        self,
        finding_id: str,
        old_confidence: str,
        new_confidence: str,
        reason: str,
    ):
        """Log a confidence level change."""
        self._write({
            "type": "confidence_update",
            "finding_id": finding_id,
            "old_confidence": old_confidence,
            "new_confidence": new_confidence,
            "reason": reason,
        })

    def log_human_decision(
        self,
        finding_id: str,
        action: str,  # approve, reject, investigate_more
        reason: str = "",
    ):
        """Log a human-in-the-loop decision."""
        self._write({
            "type": "human_decision",
            "finding_id": finding_id,
            "action": action,
            "reason": reason,
        })

    def log_guardrail_check(
        self,
        finding_id: str,
        passed: bool,
        label: str,
        explanation: str,
    ):
        """Log a hallucination guardrail check result."""
        self._write({
            "type": "guardrail_check",
            "finding_id": finding_id,
            "passed": passed,
            "label": label,
            "explanation": explanation[:500],
        })

    def log_investigation_start(self, evidence_path: str, directive: str):
        """Log the start of an investigation."""
        self._write({
            "type": "investigation_start",
            "case_id": self.case_id,
            "evidence_path": evidence_path,
            "directive": directive,
        })

    def log_investigation_complete(
        self,
        total_iterations: int,
        total_findings: int,
        convergence_reason: str,
        self_corrections_triggered: int,
    ):
        """Log investigation completion."""
        self._write({
            "type": "investigation_complete",
            "case_id": self.case_id,
            "total_iterations": total_iterations,
            "total_findings": total_findings,
            "convergence_reason": convergence_reason,
            "self_corrections_triggered": self_corrections_triggered,
        })

    def _write(self, entry: dict):
        """Append entry to JSONL log file."""
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        entry["case_id"] = self.case_id

        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            pass  # Don't crash the investigation if logging fails

    def get_all_entries(self) -> list[dict]:
        """Read all log entries (for report generation)."""
        if not self.log_file.exists():
            return []
        entries = []
        with open(self.log_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return entries

    def get_tool_executions(self) -> list[dict]:
        """Get only tool execution entries."""
        return [e for e in self.get_all_entries() if e.get("type") == "tool_execution"]

    def get_self_corrections(self) -> list[dict]:
        """Get only self-correction entries."""
        return [e for e in self.get_all_entries() if e.get("type") == "self_correction"]
