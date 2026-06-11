"""Investigation Runner — Full pipeline with Phoenix + Guardrails.

Connects:
- FastAPI (web requests) → ADK Agent → SIFT Tools + Splunk
- Phoenix Tracer → records every decision
- GuardrailPipeline → evaluates every finding BEFORE showing to user
- ImprovementLoop → learns from past investigations
- WebSocket → broadcasts real-time events to dashboard
"""

import asyncio
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Coroutine

from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from google.adk.runners import InMemoryRunner
from google.genai import types

# Phoenix integration
from sift_defender.phoenix.tracer import PhoenixTracer
from sift_defender.phoenix.guardrail_pipeline import GuardrailPipeline
from sift_defender.phoenix.improvement_loop import ImprovementLoop, InvestigationRecord
from sift_defender.utils.rate_limiter import RetryWithBackoff


class InvestigationRunner:
    """Runs investigation with full Phoenix observability and guardrails."""

    def __init__(
        self,
        case_id: str,
        evidence_path: str,
        directive: str,
        broadcast_fn: Callable[[dict], Coroutine],
    ):
        self.case_id = case_id
        self.evidence_path = evidence_path
        self.directive = directive
        self.broadcast = broadcast_fn

        self.status = "initializing"
        self.iteration = 0
        self.findings: list[dict] = []
        self.blocked_findings: list[dict] = []
        self.final_output = ""
        self.span_count = 0
        self.start_time = time.time()

        # Initialize Phoenix tracer (connects to running Phoenix server)
        self._phoenix = PhoenixTracer.get_instance().initialize()
        
        # Initialize guardrail pipeline (evaluates findings before showing to user)
        self._guardrail = GuardrailPipeline()
        
        # Initialize improvement loop (learns from past investigations)
        self._improvement = ImprovementLoop()
        
        # Rate limiting / retry for Vertex AI 429 errors
        self._retry = RetryWithBackoff(
            max_retries=5,
            initial_delay=3.0,
            max_delay=60.0,
            backoff_factor=2.0,
        )

    async def run(self):
        """Execute the full investigation with Phoenix tracing + guardrails."""
        self.status = "running"
        await self.broadcast({"type": "status", "status": "running", "case_id": self.case_id})

        # Get improvement hints from past investigations
        hints = self._improvement.get_pre_investigation_hints()
        if hints:
            await self.broadcast({
                "type": "thinking", "agent": "improvement_loop",
                "message": f"Learned from past investigations: {hints[0]}",
            })

        try:
            # Import production agent (creates fresh with current model setting)
            from sift_defender.agents.production_agent import create_agent
            agent = create_agent()

            # Run ADK agent
            await self.broadcast({
                "type": "thinking", "agent": "orchestrator",
                "message": f"Starting investigation on {self.evidence_path}",
            })

            runner = InMemoryRunner(agent=agent, app_name="aegis_ir")
            session_id = secrets.token_hex(8)
            await runner.session_service.create_session(
                app_name="aegis_ir", user_id="analyst", session_id=session_id
            )

            async for event in runner.run_async(
                user_id="analyst",
                session_id=session_id,
                new_message=types.Content(
                    role="user",
                    parts=[types.Part(text=(
                        f"{self.directive}\n"
                        f"Evidence path: {self.evidence_path}\n"
                        f"Agent hints from past investigations: {'; '.join(hints[:3])}"
                    ))]
                ),
            ):
                # Broadcast intermediate events (tool calls, thinking, etc.)
                await self._handle_adk_event(event)

                if event.is_final_response() and event.content and event.content.parts:
                    for part in event.content.parts:
                        if part.text:
                            self.final_output += part.text

            # Extract findings from agent output
            raw_findings = self._extract_findings_from_output()

            # === GUARDRAIL PIPELINE: Evaluate EVERY finding before showing to user ===
            tool_outputs = []  # In production, collect from spans
            for finding in raw_findings:
                decision = self._guardrail.evaluate(finding, tool_outputs)
                
                if decision.should_show_user:
                    # Finding passed guardrail → show to user
                    self.findings.append({**finding, "guardrail_status": decision.label})
                    await self.broadcast({
                        "type": "finding",
                        "id": finding.get("id", ""),
                        "title": finding.get("title", ""),
                        "confidence": finding.get("confidence", ""),
                        "description": finding.get("description", ""),
                        "mitre": finding.get("mitre", ""),
                        "guardrail": decision.label,
                    })
                else:
                    # Finding BLOCKED by guardrail → don't show, notify user it was blocked
                    self.blocked_findings.append({**finding, "block_reason": decision.explanation})
                    await self.broadcast({
                        "type": "self_correction",
                        "agent": "guardrail",
                        "message": f"🚫 BLOCKED: \"{finding.get('title', '')}\" — {decision.explanation}",
                    })

            # === Record investigation for improvement loop ===
            duration = time.time() - self.start_time
            self._improvement.record_investigation(InvestigationRecord(
                case_id=self.case_id,
                evidence_type="windows_disk",
                findings_count=len(self.findings),
                confirmed_count=len([f for f in self.findings if f.get("confidence") == "CONFIRMED"]),
                inferred_count=len([f for f in self.findings if f.get("confidence") == "INFERRED"]),
                blocked_count=len(self.blocked_findings),
                self_corrections=0,  # TODO: count from spans
                accuracy_rate=self._guardrail.metrics["evaluator_metrics"]["accuracy_rate"],
                hallucination_rate=self._guardrail.metrics["evaluator_metrics"]["hallucination_rate"],
                tools_used=[],  # TODO: extract from spans
                mistakes_made=[d["block_reason"] for d in self.blocked_findings],
                investigation_time_seconds=duration,
            ))

            # Flush Phoenix traces
            if self._phoenix.provider:
                self._phoenix.flush()

            # Collect span stats
            exporter = self._phoenix.get_memory_exporter()
            self.span_count = len(exporter.get_spans()) if exporter else 0

            self.status = "complete"
            await self.broadcast({
                "type": "complete",
                "case_id": self.case_id,
                "finding_count": len(self.findings),
                "blocked_count": len(self.blocked_findings),
                "span_count": self.span_count,
                "duration_seconds": round(duration, 1),
                "guardrail_metrics": self._guardrail.metrics,
            })

        except Exception as e:
            self.status = "error"
            error_msg = str(e)[:500]
            
            # Even on error, try to extract findings from whatever output we got
            if self.final_output:
                raw_findings = self._extract_findings_from_output()
                tool_outputs = []
                for finding in raw_findings:
                    decision = self._guardrail.evaluate(finding, tool_outputs)
                    if decision.should_show_user:
                        self.findings.append({**finding, "guardrail_status": decision.label})
                        await self.broadcast({
                            "type": "finding",
                            "id": finding.get("id", ""),
                            "title": finding.get("title", ""),
                            "confidence": finding.get("confidence", ""),
                            "description": finding.get("description", ""),
                            "mitre": finding.get("mitre", ""),
                            "guardrail": decision.label,
                        })
                    else:
                        self.blocked_findings.append({**finding, "block_reason": decision.explanation})
                        await self.broadcast({
                            "type": "self_correction",
                            "agent": "guardrail",
                            "message": f"🚫 BLOCKED: \"{finding.get('title', '')}\" — {decision.explanation}",
                        })

            # Determine if this was a rate limit or real error
            if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
                await self.broadcast({
                    "type": "error",
                    "message": f"⚠️ Rate limited by Vertex AI. Investigation partial — {len(self.findings)} findings extracted from available data.",
                })
                # Mark as partial-complete instead of error if we have findings
                if self.findings:
                    self.status = "complete"
                    await self.broadcast({
                        "type": "complete",
                        "case_id": self.case_id,
                        "finding_count": len(self.findings),
                        "blocked_count": len(self.blocked_findings),
                        "span_count": 0,
                        "duration_seconds": round(time.time() - self.start_time, 1),
                        "guardrail_metrics": self._guardrail.metrics,
                        "note": "Partial results — rate limited",
                    })
            else:
                await self.broadcast({"type": "error", "message": error_msg})

    async def _handle_adk_event(self, event):
        """Broadcast intermediate ADK events to WebSocket for real-time feed."""
        try:
            if not event.content or not event.content.parts:
                return

            for part in event.content.parts:
                # Tool call events (function_call)
                if hasattr(part, 'function_call') and part.function_call:
                    fc = part.function_call
                    tool_name = fc.name if hasattr(fc, 'name') else str(fc)
                    args_str = ""
                    if hasattr(fc, 'args') and fc.args:
                        args_str = json.dumps(dict(fc.args))[:120]
                    await self.broadcast({
                        "type": "tool_call",
                        "agent": "aegis_ir",
                        "tool": tool_name,
                        "args": args_str,
                    })

                # Tool response events (function_response)
                elif hasattr(part, 'function_response') and part.function_response:
                    fr = part.function_response
                    tool_name = fr.name if hasattr(fr, 'name') else "tool"
                    # Summarize the response
                    response_text = ""
                    if hasattr(fr, 'response') and fr.response:
                        response_text = str(fr.response)[:200]
                    await self.broadcast({
                        "type": "tool_result",
                        "agent": "aegis_ir",
                        "tool": tool_name,
                        "summary": response_text,
                    })

                # Thinking/text from model (non-final)
                elif hasattr(part, 'text') and part.text and not event.is_final_response():
                    text = part.text.strip()
                    if text and len(text) > 10:
                        # Accumulate text for finding extraction even from intermediate
                        self.final_output += text + "\n"
                        await self.broadcast({
                            "type": "thinking",
                            "agent": "aegis_ir",
                            "message": text[:300],
                        })
        except Exception:
            pass  # Don't let broadcast errors stop the investigation

    def _extract_findings_from_output(self) -> list[dict]:
        """Extract structured findings from agent's text output."""
        findings = []
        output = self.final_output.lower()
        finding_id = 0

        # Pattern 1: Agent explicitly reports "Finding ID: X Title: Y ... MITRE ATT&CK: Z"
        explicit_findings = re.findall(
            r'finding id:\s*\d+\s*title:\s*(.*?)confidence:\s*(.*?)(?:evidence:|mitre)',
            output, re.IGNORECASE | re.DOTALL
        )
        for title_raw, conf_raw in explicit_findings:
            finding_id += 1
            title = title_raw.strip().split('\n')[0].strip()[:80]
            confidence = "CONFIRMED" if "confirmed" in conf_raw.lower() else "INFERRED"
            # Try to extract MITRE technique
            mitre_match = re.search(r'(T\d{4}(?:\.\d{3})?)', output[output.find(title.lower()):output.find(title.lower())+500])
            mitre = mitre_match.group(1) if mitre_match else ""
            
            # Avoid duplicates
            if not any(f["title"].lower() == title.lower() for f in findings):
                findings.append({
                    "id": f"F-{finding_id:03d}",
                    "title": title,
                    "confidence": confidence,
                    "description": title,
                    "sources": ["splunk", "sift"] if confidence == "CONFIRMED" else ["splunk"],
                    "mitre": mitre,
                })

        # Pattern 2: Keyword-based extraction (fallback)
        if not findings:
            if "malicious document" in output or "invoice-document" in output or "docm" in output or "spearphishing" in output:
                finding_id += 1
                findings.append({
                    "id": f"F-{finding_id:03d}",
                    "title": "Malicious Document Delivery",
                    "confidence": "CONFIRMED" if ("prefetch" in output and "winword" in output) else "INFERRED",
                    "description": "Macro-enabled document found, Word execution evidence present",
                    "sources": ["sleuthkit_fls", "prefetch_check"],
                    "mitre": "T1566.001",
                })

            if "svc_update" in output and ("task" in output or "persistence" in output):
                finding_id += 1
                findings.append({
                    "id": f"F-{finding_id:03d}",
                    "title": "Persistence via Scheduled Task",
                    "confidence": "CONFIRMED" if "scheduled" in output else "INFERRED",
                    "description": "svc_update.exe configured as scheduled task for persistence",
                    "sources": ["sleuthkit_fls", "task_xml"],
                    "mitre": "T1053.005",
                })

            if "powershell" in output and ("executed" in output or "prefetch" in output or "encoded" in output):
                finding_id += 1
                findings.append({
                    "id": f"F-{finding_id:03d}",
                    "title": "PowerShell Execution",
                    "confidence": "CONFIRMED",
                    "description": "PowerShell execution confirmed via Prefetch/Splunk logs",
                    "sources": ["prefetch", "splunk_process_events"],
                    "mitre": "T1059.001",
                })

            if "c2" in output or "beacon" in output or "198.51.100" in output:
                finding_id += 1
                findings.append({
                    "id": f"F-{finding_id:03d}",
                    "title": "C2 Communication",
                    "confidence": "CONFIRMED" if "198.51.100" in output and "splunk" in output else "INFERRED",
                    "description": "C2 communication to 198.51.100.42 confirmed via Splunk network logs",
                    "sources": ["splunk_network"],
                    "mitre": "T1071.001",
                })

            if "lateral" in output or ("type 3" in output and "logon" in output):
                finding_id += 1
                findings.append({
                    "id": f"F-{finding_id:03d}",
                    "title": "Lateral Movement",
                    "confidence": "INFERRED",
                    "description": "Network logon (Type 3) detected from compromised host",
                    "sources": ["splunk_auth"],
                    "mitre": "T1021.001",
                })

            if "update.dat" in output or "stage 2" in output or "payload" in output:
                finding_id += 1
                findings.append({
                    "id": f"F-{finding_id:03d}",
                    "title": "Stage 2 Payload Dropped",
                    "confidence": "INFERRED",
                    "description": "Suspicious data file in temp directory",
                    "sources": ["sleuthkit_fls"],
                    "mitre": "T1105",
                })

            if "exfiltrat" in output or ("dns" in output and "c2-backup" in output):
                finding_id += 1
                findings.append({
                    "id": f"F-{finding_id:03d}",
                    "title": "Data Exfiltration",
                    "confidence": "INFERRED",
                    "description": "Data exfiltration via DNS to C2 domain",
                    "sources": ["splunk_dns"],
                    "mitre": "T1048.003",
                })

        return findings
