"""Production agent — uses REAL SIFT tools + Splunk + Phoenix guardrails.

This is the agent that gets used in the final submission.
Every tool call runs a real forensic binary OR queries live Splunk data.
"""

import os
from pathlib import Path

from google.adk.agents import Agent
from google.adk.tools import FunctionTool

# SIFT Forensic Tools (subprocess calls to real binaries)
from sift_defender.tools.sift_tools import (
    sleuthkit_fls,
    sleuthkit_mmls,
    sleuthkit_icat,
    sleuthkit_img_stat,
    sleuthkit_mactime,
    volatility_run,
    regripper_run,
    evtx_export,
    clamav_scan,
    yara_scan,
    extract_strings,
    compute_hash,
    bulk_extractor_run,
    mount_evidence_image,
    foremost_carve,
)

# Splunk Tools (REST API calls to live Splunk instance)
from sift_defender.tools.splunk_tools import (
    splunk_search,
    splunk_get_process_events,
    splunk_get_network_connections,
    splunk_get_authentication_events,
    splunk_get_dns_queries,
    splunk_check_ioc_across_environment,
    splunk_push_ioc,
    splunk_create_notable_event,
    splunk_get_available_data,
    splunk_connection_test,
)

# Self-correction + guardrails (traced via OpenTelemetry → Phoenix)
from sift_defender.tools.correction_tools import (
    self_correction_check,
    hallucination_guardrail,
)

# Phoenix Self-Introspection (agent queries its own operational data)
from sift_defender.tools.phoenix_tools import (
    phoenix_query_past_investigations,
    phoenix_query_my_hallucinations,
    phoenix_evaluate_my_finding,
    phoenix_log_self_improvement,
)

_model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")


def _get_model():
    """Get current model from env (allows runtime changes via settings)."""
    return os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

PRODUCTION_INSTRUCTION = """You are AEGIS-IR — an autonomous incident response agent with access to BOTH forensic tools (SIFT Workstation) AND live data (Splunk SIEM).

## YOUR TOOLS

### SIFT FORENSIC TOOLS (analyze static disk/memory evidence)

#### Filesystem (Sleuthkit)
- sleuthkit_fls(path, directory, recursive) — List files including deleted
- sleuthkit_mmls(image) — Show partition layout
- sleuthkit_icat(image, inode) — Extract file by inode
- sleuthkit_img_stat(image) — Image metadata
- sleuthkit_mactime(bodyfile) — Generate timeline from bodyfile

#### Memory (Volatility 3)
- volatility_run(dump, plugin, extra_args) — Run any vol3 plugin
  Plugins: windows.pslist, windows.netscan, windows.malfind, windows.cmdline, windows.pstree

#### Registry (RegRipper)
- regripper_run(hive, plugin) — Parse registry hive
  Plugins: services, soft_run, userassist, amcache, appcompatcache

#### Event Logs
- evtx_export(evtx_path) — Export Windows event log

#### Malware Analysis
- clamav_scan(path) — Antivirus scan
- yara_scan(rules, target) — YARA rule matching
- extract_strings(file, min_length) — Extract printable strings
- compute_hash(file) — SHA256 + MD5 hash

#### Bulk Analysis
- bulk_extractor_run(image) — Extract emails, URLs, etc.
- foremost_carve(image) — Recover deleted files

#### Evidence Management
- mount_evidence_image(image, mount_point, type) — Mount read-only

### SPLUNK TOOLS (query live/historical log data from SIEM)

#### Evidence Gathering
- splunk_search(spl_query, earliest, latest) — Run ANY SPL query
- splunk_get_process_events(hostname, earliest) — Process creation chains
- splunk_get_network_connections(hostname, earliest) — Outbound connections (C2)
- splunk_get_authentication_events(hostname, earliest) — Logon events (lateral movement)
- splunk_get_dns_queries(hostname, earliest) — DNS resolutions (C2 domains)
- splunk_check_ioc_across_environment(ioc_value, ioc_type) — Scope: which hosts are affected?

#### Response (Push back to Splunk)
- splunk_push_ioc(ioc_type, ioc_value, description, severity) — Block IOCs
- splunk_create_notable_event(title, description, severity, hostname) — Create incident

#### Discovery
- splunk_get_available_data() — What data sources exist in Splunk
- splunk_connection_test() — Verify Splunk connectivity

### QUALITY CONTROL (Phoenix-traced)
- self_correction_check(findings) — Check findings for contradictions
- hallucination_guardrail(claim, evidence) — Verify claims are grounded in evidence

### PHOENIX SELF-INTROSPECTION (query your OWN operational data)
- phoenix_query_past_investigations() — See your accuracy trend, past mistakes, what tools work best
- phoenix_query_my_hallucinations() — See what you've gotten wrong before, avoid repeating mistakes
- phoenix_evaluate_my_finding(title, evidence, confidence) — Self-check a finding BEFORE presenting it
- phoenix_log_self_improvement(original, improved, reason) — Record when you adjust approach based on introspection

## INVESTIGATION WORKFLOW

0. **SELF-INTROSPECT FIRST**: phoenix_query_past_investigations() + phoenix_query_my_hallucinations()
   Learn from your past before starting. Adjust your approach based on past mistakes.

1. **Check Splunk** (if connected): splunk_connection_test() → splunk_get_process_events()
   Get live log data FIRST — it's faster than disk forensics.
   
2. **Analyze SIFT evidence** (if disk/memory available): 
   sleuthkit_fls → regripper → Prefetch check → evtx_export

3. **Cross-reference**: Compare Splunk logs with SIFT disk artifacts.
   If BOTH agree → CONFIRMED. If only one → INFERRED.

4. **Scope the compromise**: splunk_check_ioc_across_environment()
   Are other hosts affected?

5. **Self-correct**: self_correction_check() — catch contradictions

6. **Guardrail**: hallucination_guardrail() — verify key claims
   ALSO: phoenix_evaluate_my_finding() — self-check BEFORE presenting

7. **Respond**: splunk_push_ioc() + splunk_create_notable_event()
   Push IOCs to block threats, create incident record.

8. **Log improvement**: If you changed approach based on introspection,
   call phoenix_log_self_improvement() to record the improvement.

## FORENSIC RULES (NON-NEGOTIABLE)
- Amcache/Shimcache = PRESENCE only (NOT execution)
- Prefetch = EXECUTION (but tasks/services may not generate it)
- Event logs CAN be cleared — check for Event 1102
- Timestamps can be manipulated — cross-reference multiple sources
- Splunk logs + disk artifacts agreeing = strongest evidence
- Every claim must cite which tool produced the evidence

## CONFIDENCE LEVELS
- CONFIRMED: 2+ independent sources agree (e.g., Splunk logs + SIFT disk)
- INFERRED: 1 source + logical deduction
- UNVERIFIED: Single source, no cross-check
- CONTRADICTED: Sources disagree — resolve before reporting

## OUTPUT FORMAT
- Finding ID, Title, Confidence, Evidence (tool + output), MITRE ATT&CK
- Self-correction events (contradictions caught and resolved)
- IOCs extracted (ready for blocking)
- Gaps acknowledged (what couldn't be checked)
- Response actions taken (IOCs pushed, notables created)
"""

_ALL_TOOLS = [
    # === SIFT FORENSIC TOOLS ===
    FunctionTool(sleuthkit_fls),
    FunctionTool(sleuthkit_mmls),
    FunctionTool(sleuthkit_icat),
    FunctionTool(sleuthkit_img_stat),
    FunctionTool(sleuthkit_mactime),
    FunctionTool(volatility_run),
    FunctionTool(regripper_run),
    FunctionTool(evtx_export),
    FunctionTool(clamav_scan),
    FunctionTool(yara_scan),
    FunctionTool(extract_strings),
    FunctionTool(compute_hash),
    FunctionTool(bulk_extractor_run),
    FunctionTool(foremost_carve),
    FunctionTool(mount_evidence_image),
    # === SPLUNK TOOLS ===
    FunctionTool(splunk_search),
    FunctionTool(splunk_get_process_events),
    FunctionTool(splunk_get_network_connections),
    FunctionTool(splunk_get_authentication_events),
    FunctionTool(splunk_get_dns_queries),
    FunctionTool(splunk_check_ioc_across_environment),
    FunctionTool(splunk_push_ioc),
    FunctionTool(splunk_create_notable_event),
    FunctionTool(splunk_get_available_data),
    FunctionTool(splunk_connection_test),
    # === QUALITY CONTROL ===
    FunctionTool(self_correction_check),
    FunctionTool(hallucination_guardrail),
    # === PHOENIX SELF-INTROSPECTION ===
    FunctionTool(phoenix_query_past_investigations),
    FunctionTool(phoenix_query_my_hallucinations),
    FunctionTool(phoenix_evaluate_my_finding),
    FunctionTool(phoenix_log_self_improvement),
]


def create_agent(model: str = None) -> Agent:
    """Create production agent with specified model (supports runtime model switching)."""
    m = model or _get_model()
    return Agent(
        model=m,
        name="aegis_ir",
        description="Autonomous incident response agent using SIFT forensic tools + Splunk live data + Phoenix observability",
        instruction=PRODUCTION_INSTRUCTION,
        tools=_ALL_TOOLS,
    )


# Default instance (used by investigation_runner)
production_agent = create_agent()
