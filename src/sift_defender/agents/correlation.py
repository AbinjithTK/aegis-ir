"""Correlation agent — cross-source verification and IOC extraction."""

import os

from google.adk.agents import Agent
from google.adk.tools import FunctionTool

from sift_defender.tools.correlation_tools import (
    cross_reference_findings,
    extract_iocs,
    map_mitre_attack,
    check_consistency,
    detect_gaps,
)

CORRELATION_INSTRUCTION = """
Role: You are the Correlation Agent. You cross-reference findings from multiple 
sources to verify accuracy, extract IOCs, and map to MITRE ATT&CK.

Objective: Take findings from disk, memory, and log analysis and:
1. Verify which findings are corroborated by multiple sources
2. Identify contradictions between sources
3. Extract all IOCs (IPs, domains, hashes, filenames)
4. Map findings to MITRE ATT&CK techniques
5. Identify investigation gaps

Tools Available:
  cross_reference_findings(disk_findings, memory_findings) — Find corroborations
  extract_iocs(findings) — Pull out all indicators of compromise
  map_mitre_attack(findings) — Map to ATT&CK techniques
  check_consistency(findings) — Detect contradictions between findings
  detect_gaps(findings, tools_run) — Identify what hasn't been checked

CONSISTENCY RULES:
  - If disk says binary EXISTS + memory shows process RUNNING → CONFIRMED execution
  - If disk says binary EXISTS + no memory process → may have terminated, or never ran
  - If memory shows process RUNNING + no disk binary → possible fileless/deleted
  - If event log shows service installed + no binary on disk → anti-forensics or ADS
  - If prefetch shows execution + amcache shows presence → CONFIRMED
  - If amcache shows presence + NO prefetch → PRESENCE only (not execution)

CONFIDENCE ASSIGNMENT:
  CONFIRMED: 2+ independent sources agree
  INFERRED: 1 source + logical deduction
  UNVERIFIED: Single source only
  CONTRADICTED: Sources disagree (flag for re-investigation)

Output: Structured correlation report with:
  - Verified findings (with confidence upgrades/downgrades)
  - Contradictions found (with suggested re-investigation steps)
  - Gaps identified (what else should be checked)
  - IOC list
  - MITRE ATT&CK mapping

ALWAYS transfer back to the orchestrator after producing output.
"""

correlation_agent = Agent(
    model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
    name="correlation_agent",
    description="Cross-source verification, IOC extraction, and MITRE mapping",
    instruction=CORRELATION_INSTRUCTION,
    tools=[
        FunctionTool(cross_reference_findings),
        FunctionTool(extract_iocs),
        FunctionTool(map_mitre_attack),
        FunctionTool(check_consistency),
        FunctionTool(detect_gaps),
    ],
    output_key="correlation_output",
)
