"""Investigation Journal — human-readable record of agent reasoning.

Generates a Markdown file showing what the agent did at each step,
why it made each decision, and where it self-corrected.

This is the "demo star" — what judges read to understand the agent's reasoning.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sift_defender.tools.base import CASE_DIR


class InvestigationJournal:
    """Builds a running markdown log of the investigation."""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.entries: list[str] = []
        self._init_header()

    def _init_header(self):
        self.entries.append(f"# Investigation Journal — {self.case_id}\n")
        self.entries.append(f"**Started**: {datetime.now(timezone.utc).isoformat()}")
        self.entries.append(f"**Agent**: SIFT Defender v0.1.0")
        self.entries.append(f"**Engine**: Google ADK + Arize AX")
        self.entries.append("")

    def log_iteration_start(self, iteration: int, agent_name: str, focus: str):
        """Log the start of a new investigation iteration."""
        self.entries.append(f"\n---\n")
        self.entries.append(f"## Iteration {iteration}: {agent_name}")
        self.entries.append(f"**Time**: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")
        self.entries.append(f"**Focus**: {focus}")
        self.entries.append("")

    def log_reasoning(self, reasoning: str):
        """Log the agent's reasoning for its next action."""
        self.entries.append(f"### Reasoning")
        self.entries.append(reasoning)
        self.entries.append("")

    def log_tool_call(self, tool_name: str, args: dict, audit_id: str):
        """Log a tool call with its parameters."""
        args_str = ", ".join(f"{k}={v!r}" for k, v in args.items()) if args else ""
        self.entries.append(f"- `{tool_name}({args_str})` → audit_id: `{audit_id}`")

    def log_tool_result(self, tool_name: str, summary: str):
        """Log the key result from a tool call."""
        self.entries.append(f"  - Result: {summary}")

    def log_finding(self, finding_id: str, title: str, confidence: str, sources: list[str]):
        """Log a new finding."""
        self.entries.append(f"\n### ✓ Finding: {finding_id}")
        self.entries.append(f"**{title}**")
        self.entries.append(f"- Confidence: **{confidence}**")
        self.entries.append(f"- Sources: {', '.join(sources)}")
        self.entries.append("")

    def log_self_correction(
        self,
        issue: str,
        action_taken: str,
        resolution: str | None = None,
    ):
        """Log a self-correction event — the money shot for demos."""
        self.entries.append(f"\n### ⚠️ SELF-CORRECTION TRIGGERED")
        self.entries.append(f"**Issue**: {issue}")
        self.entries.append(f"**Action**: {action_taken}")
        if resolution:
            self.entries.append(f"**Resolution**: {resolution}")
        self.entries.append("")

    def log_confidence_update(self, finding_id: str, old: str, new: str, reason: str):
        """Log a confidence level change."""
        self.entries.append(f"- {finding_id}: {old} → **{new}** ({reason})")

    def log_gap_identified(self, description: str, suggested_tool: str):
        """Log an identified investigation gap."""
        self.entries.append(f"- Gap: {description}")
        self.entries.append(f"  - Suggested: `{suggested_tool}`")

    def log_convergence(self, reason: str, total_findings: int, total_iterations: int):
        """Log the investigation completion."""
        self.entries.append(f"\n---\n")
        self.entries.append(f"## Investigation Complete")
        self.entries.append(f"**Reason**: {reason}")
        self.entries.append(f"**Total findings**: {total_findings}")
        self.entries.append(f"**Total iterations**: {total_iterations}")
        self.entries.append(f"**Completed**: {datetime.now(timezone.utc).isoformat()}")

    def log_summary(
        self,
        confirmed_count: int,
        inferred_count: int,
        contradicted_count: int,
        self_corrections: int,
        gaps_remaining: list[str],
    ):
        """Log the final summary."""
        self.entries.append(f"\n### Summary")
        self.entries.append(f"- CONFIRMED findings: {confirmed_count}")
        self.entries.append(f"- INFERRED findings: {inferred_count}")
        self.entries.append(f"- Self-corrections: {self_corrections}")
        if gaps_remaining:
            self.entries.append(f"\n### Gaps Acknowledged")
            for gap in gaps_remaining:
                self.entries.append(f"- {gap}")

    def get_markdown(self) -> str:
        """Get the full journal as a markdown string."""
        return "\n".join(self.entries)

    def save(self):
        """Save journal to the case directory."""
        journal_path = CASE_DIR / "journal.md"
        journal_path.parent.mkdir(parents=True, exist_ok=True)
        journal_path.write_text(self.get_markdown())

    def append_raw(self, text: str):
        """Append raw text to the journal."""
        self.entries.append(text)
