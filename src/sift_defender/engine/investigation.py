"""Investigation Manager — orchestrates the full investigation lifecycle.

This connects:
- FastAPI web layer (receives requests, sends WebSocket updates)
- ADK agents (reasoning engine)
- Self-correction engine (between iterations)
- Hallucination guardrails (before presenting findings)
- Audit logger (structured JSONL)
- Journal (human-readable markdown)
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sift_defender.engine.audit_logger import AuditLogger
from sift_defender.engine.journal import InvestigationJournal
from sift_defender.engine.self_correction import SelfCorrectionEngine, Confidence
from sift_defender.guardrails.hallucination_check import HallucinationGuardrail
from sift_defender.tools.base import CASE_DIR


class InvestigationManager:
    """Manages a single investigation from start to completion.
    
    Coordinates between:
    - The ADK agent system (agent reasoning)
    - The self-correction engine (between iterations)
    - The hallucination guardrail (before presenting findings)
    - The web layer (real-time updates via callback)
    """

    def __init__(self, case_id: str | None = None):
        self.case_id = case_id or self._generate_case_id()
        self.findings: list[dict] = []
        self.tools_run: list[str] = []
        self.tool_outputs: list[dict] = []
        self.iteration = 0
        self.self_corrections_triggered = 0

        # Components
        self.correction_engine = SelfCorrectionEngine()
        self.guardrail = HallucinationGuardrail()
        self.audit = AuditLogger(self.case_id)
        self.journal = InvestigationJournal(self.case_id)

        # Callback for real-time WebSocket updates
        self._update_callback: Callable | None = None

    def set_update_callback(self, callback: Callable):
        """Set callback for real-time updates to the web interface."""
        self._update_callback = callback

    async def start_investigation(self, evidence_path: str, directive: str):
        """Start a new investigation.
        
        This is the main entry point called from the API layer.
        """
        self.audit.log_investigation_start(evidence_path, directive)
        self.journal.log_iteration_start(0, "orchestrator", "Investigation initialization")
        self.journal.log_reasoning(
            f"Starting investigation on evidence at: {evidence_path}\n"
            f"Directive: {directive}"
        )

        await self._send_update({
            "type": "thinking",
            "agent": "orchestrator",
            "message": f"Starting investigation. Evidence: {evidence_path}",
        })

        # TODO: Wire up actual ADK agent execution here
        # For now, this is the integration point where we'll call:
        #
        # from google.adk.runners import InMemoryRunner
        # from sift_defender.agents.orchestrator import root_agent
        #
        # runner = InMemoryRunner(agent=root_agent, app_name="sift_defender")
        # session = await runner.session_service.create_session(...)
        # async for event in runner.run_async(...):
        #     await self._handle_agent_event(event)

        await self._send_update({
            "type": "thinking",
            "agent": "orchestrator",
            "message": "Classifying evidence type and planning investigation strategy...",
        })

    async def record_tool_call(
        self,
        tool_name: str,
        agent_name: str,
        arguments: dict,
        audit_id: str,
    ):
        """Record when a tool is called (before execution)."""
        self.tools_run.append(tool_name)
        self.journal.log_tool_call(tool_name, arguments, audit_id)

        await self._send_update({
            "type": "tool_call",
            "agent": agent_name,
            "tool": tool_name,
            "args": json.dumps(arguments)[:200],
        })

    async def record_tool_result(
        self,
        tool_name: str,
        agent_name: str,
        audit_id: str,
        result: dict,
        duration_ms: float = 0,
    ):
        """Record tool execution result."""
        self.tool_outputs.append(result)

        summary = result.get("data", {})
        if isinstance(summary, dict):
            summary = str(summary)[:200]
        elif isinstance(summary, list):
            summary = f"{len(summary)} entries"
        else:
            summary = str(summary)[:200]

        self.audit.log_tool_execution(
            audit_id=audit_id,
            tool_name=tool_name,
            agent_name=agent_name,
            arguments={},
            success=result.get("success", True),
            output_summary=summary,
            duration_ms=duration_ms,
        )

        self.journal.log_tool_result(tool_name, summary)

        await self._send_update({
            "type": "tool_result",
            "agent": agent_name,
            "tool": tool_name,
            "summary": summary,
        })

    async def record_finding(self, finding: dict):
        """Record a new finding — runs through guardrail before presenting."""
        # Run hallucination guardrail
        guardrail_result = await self.guardrail.check_finding(
            finding, self.tool_outputs
        )

        self.audit.log_guardrail_check(
            finding_id=finding.get("id", "unknown"),
            passed=guardrail_result["action"] != "BLOCK",
            label=guardrail_result.get("label", "unknown"),
            explanation=guardrail_result.get("explanation", ""),
        )

        if guardrail_result["action"] == "BLOCK":
            # Hallucination detected — don't present to user
            await self._send_update({
                "type": "self_correction",
                "agent": "guardrail",
                "message": f"⛔ Finding blocked by hallucination guardrail: {guardrail_result['explanation']}",
            })
            return

        # Finding passes guardrail — add to list
        self.findings.append(finding)

        self.audit.log_finding(
            finding_id=finding.get("id", ""),
            title=finding.get("title", ""),
            confidence=finding.get("confidence", "UNVERIFIED"),
            sources=finding.get("sources", []),
            evidence_audit_ids=finding.get("evidence_ids", []),
            agent_name=finding.get("agent", "unknown"),
        )

        self.journal.log_finding(
            finding_id=finding.get("id", ""),
            title=finding.get("title", ""),
            confidence=finding.get("confidence", "UNVERIFIED"),
            sources=finding.get("sources", []),
        )

        await self._send_update({
            "type": "finding",
            "id": finding.get("id", ""),
            "title": finding.get("title", ""),
            "description": finding.get("description", ""),
            "confidence": finding.get("confidence", "UNVERIFIED"),
            "mitre": finding.get("mitre", ""),
            "agent": finding.get("agent", ""),
        })

    async def run_self_correction(self):
        """Run self-correction check between iterations."""
        self.iteration += 1

        result = self.correction_engine.run_check(self.findings, self.tools_run)

        self.audit.log_self_correction(
            iteration=result.iteration,
            contradictions_count=len(result.contradictions),
            gaps_count=len(result.gaps),
            triggered=len(result.contradictions) > 0,
            trigger_reason=result.contradictions[0].description if result.contradictions else "",
            action_taken=result.next_action,
        )

        # Log to journal
        journal_entry = self.correction_engine.get_journal_entry(result)
        self.journal.append_raw(journal_entry)

        # Send updates
        await self._send_update({
            "type": "iteration",
            "iteration": result.iteration,
            "max_iterations": self.correction_engine.max_iterations,
        })

        if result.contradictions:
            self.self_corrections_triggered += 1
            for c in result.contradictions:
                await self._send_update({
                    "type": "self_correction",
                    "agent": "self_correction",
                    "message": c.description,
                    "resolution": c.suggested_resolution,
                })

        return result

    async def complete_investigation(self, reason: str):
        """Finalize the investigation."""
        confirmed = [f for f in self.findings if f.get("confidence") == "CONFIRMED"]
        inferred = [f for f in self.findings if f.get("confidence") == "INFERRED"]

        self.journal.log_convergence(
            reason=reason,
            total_findings=len(self.findings),
            total_iterations=self.iteration,
        )
        self.journal.log_summary(
            confirmed_count=len(confirmed),
            inferred_count=len(inferred),
            contradicted_count=0,
            self_corrections=self.self_corrections_triggered,
            gaps_remaining=[],
        )
        self.journal.save()

        self.audit.log_investigation_complete(
            total_iterations=self.iteration,
            total_findings=len(self.findings),
            convergence_reason=reason,
            self_corrections_triggered=self.self_corrections_triggered,
        )

        # Save findings
        findings_path = CASE_DIR / "findings.json"
        findings_path.parent.mkdir(parents=True, exist_ok=True)
        findings_path.write_text(json.dumps(self.findings, indent=2, default=str))

        await self._send_update({
            "type": "complete",
            "finding_count": len(self.findings),
            "iterations": self.iteration,
            "self_corrections": self.self_corrections_triggered,
        })

    async def _send_update(self, data: dict):
        """Send real-time update to web interface."""
        if self._update_callback:
            await self._update_callback(data)

    def _generate_case_id(self) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        short = uuid.uuid4().hex[:6]
        return f"CASE-{ts}-{short}"
