"""Disk analysis agent — deep filesystem forensics using real SIFT tools.

This agent calls actual forensic tools via subprocess (shell=False):
- RegRipper for registry analysis
- evtx_dump for Windows Event Logs
- fls/icat for filesystem enumeration
- Plaso for timeline generation

Every tool call is safe: shell=False, path-validated, output-parsed.
"""

import json
import os
import subprocess
from pathlib import Path

from google.adk.agents import Agent
from google.adk.tools import FunctionTool


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TOOL FUNCTIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def analyze_prefetch_detail(evidence_path: str, binary_name: str) -> str:
    """Check if a specific binary has Prefetch execution evidence.

    CRITICAL CAVEAT: If no Prefetch entry exists, it does NOT mean the binary
    never executed. Scheduled tasks and services often don't generate Prefetch.

    Args:
        evidence_path: Path to mounted evidence
        binary_name: Name of the binary to check (e.g., "svc_update.exe")

    Returns:
        JSON with Prefetch analysis for the specified binary.
    """
    p = Path(evidence_path)
    prefetch_dir = p / "Windows" / "Prefetch"

    if not prefetch_dir.exists():
        return json.dumps({
            "success": True,
            "binary": binary_name,
            "has_prefetch": False,
            "warning": "Prefetch directory does not exist. May be disabled or cleared.",
        })

    # Search for matching prefetch files
    matches = []
    for pf in prefetch_dir.glob("*.pf"):
        exe_name = pf.stem.rsplit("-", 1)[0] if "-" in pf.stem else pf.stem
        if binary_name.upper().replace(".EXE", "") in exe_name.upper():
            matches.append({
                "filename": pf.name,
                "executable": exe_name,
                "size": pf.stat().st_size,
                "last_modified": pf.stat().st_mtime,
            })

    if matches:
        return json.dumps({
            "success": True,
            "binary": binary_name,
            "has_prefetch": True,
            "matches": matches,
            "interpretation": f"CONFIRMED: {binary_name} was EXECUTED (Prefetch entry exists).",
        })
    else:
        return json.dumps({
            "success": True,
            "binary": binary_name,
            "has_prefetch": False,
            "all_prefetch_executables": [pf.stem.rsplit("-", 1)[0] for pf in prefetch_dir.glob("*.pf")],
            "interpretation": f"No Prefetch for {binary_name}. This does NOT prove it never ran — check scheduled tasks and services.",
            "caveat": "Binaries launched by scheduled tasks or services may not generate Prefetch entries.",
            "recommended_next": ["list_scheduled_tasks", "analyze_services", "check_event_logs_4688"],
        })


def analyze_services(evidence_path: str) -> str:
    """Analyze Windows services from the SYSTEM registry hive.

    Uses RegRipper if available, otherwise parses service entries directly.

    Args:
        evidence_path: Path to mounted evidence

    Returns:
        JSON with service configurations.
    """
    p = Path(evidence_path)
    system_hive = p / "Windows" / "System32" / "config" / "SYSTEM"

    if not system_hive.exists():
        return json.dumps({
            "success": False,
            "error": "SYSTEM hive not found",
            "suggestion": "Registry hives may not be available in this evidence",
        })

    # Try RegRipper
    try:
        result = subprocess.run(
            ["rip.pl", "-r", str(system_hive), "-p", "services"],
            capture_output=True, text=True, timeout=30, shell=False
        )
        if result.returncode == 0 and result.stdout:
            return json.dumps({
                "success": True,
                "source": "regripper_services",
                "output": result.stdout[:5000],
                "caveat": "Services list shows what IS configured, not necessarily what has RUN recently.",
            })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return json.dumps({
        "success": False,
        "error": "RegRipper not available or failed to parse SYSTEM hive",
        "note": "SYSTEM hive exists but could not be parsed. May need alternative parser.",
    })


def check_event_logs(evidence_path: str, log_name: str, event_ids: str) -> str:
    """Parse Windows Event Logs for specific event IDs.

    Common event IDs:
    - 4688: Process creation (shows parent process + command line)
    - 4624: Logon event (Type 3=network, Type 10=RDP)
    - 7045: Service installed
    - 106: Scheduled task created
    - 1102: Security log cleared (anti-forensics!)

    Args:
        evidence_path: Path to mounted evidence
        log_name: Event log name (Security, System, TaskScheduler, PowerShell)
        event_ids: Comma-separated event IDs to filter (e.g., "4688,4624")

    Returns:
        JSON with matching event log entries.
    """
    p = Path(evidence_path)
    evtx_dir = p / "Windows" / "System32" / "winevt" / "Logs"

    if not evtx_dir.exists():
        return json.dumps({
            "success": False,
            "error": "Event log directory not found",
            "caveat": "Event logs may have been cleared (check for Event 1102 in Security log)",
        })

    # Map log names to filenames
    log_map = {
        "Security": "Security.evtx",
        "System": "System.evtx",
        "Application": "Application.evtx",
        "PowerShell": "Microsoft-Windows-PowerShell%4Operational.evtx",
        "TaskScheduler": "Microsoft-Windows-TaskScheduler%4Operational.evtx",
        "Sysmon": "Microsoft-Windows-Sysmon%4Operational.evtx",
    }

    filename = log_map.get(log_name, f"{log_name}.evtx")
    evtx_path = evtx_dir / filename

    if not evtx_path.exists():
        available = [f.name for f in evtx_dir.glob("*.evtx")][:10]
        return json.dumps({
            "success": False,
            "error": f"Event log '{filename}' not found",
            "available_logs": available,
        })

    # Try evtx_dump
    try:
        result = subprocess.run(
            ["evtx_dump", "-o", "jsonl", str(evtx_path)],
            capture_output=True, text=True, timeout=60, shell=False
        )
        if result.returncode == 0:
            # Filter by event IDs
            target_ids = {int(x.strip()) for x in event_ids.split(",") if x.strip()}
            entries = []
            for line in result.stdout.split("\n"):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    eid = event.get("Event", {}).get("System", {}).get("EventID")
                    if isinstance(eid, dict):
                        eid = eid.get("#text")
                    if int(eid) in target_ids:
                        entries.append(event)
                except (json.JSONDecodeError, TypeError, ValueError):
                    continue

            return json.dumps({
                "success": True,
                "log_name": log_name,
                "event_ids_filtered": list(target_ids),
                "entries_found": len(entries),
                "entries": entries[:50],  # Limit output
                "caveat": "Event logs CAN be cleared. Absence does not prove non-occurrence.",
            })
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        return json.dumps({
            "success": False,
            "error": "Event log parsing timed out (file may be very large)",
        })

    return json.dumps({
        "success": False,
        "error": "evtx_dump not available. Event log exists but cannot be parsed.",
        "log_path": str(evtx_path),
        "log_size_bytes": evtx_path.stat().st_size,
    })


def analyze_amcache(evidence_path: str) -> str:
    """Parse Amcache (application compatibility cache).

    CRITICAL CAVEAT: Amcache proves a file was PRESENT on the system.
    It does NOT prove the file was EXECUTED.

    Args:
        evidence_path: Path to mounted evidence

    Returns:
        JSON with Amcache entries.
    """
    p = Path(evidence_path)
    amcache = p / "Windows" / "appcompat" / "Programs" / "Amcache.hve"

    if not amcache.exists():
        return json.dumps({
            "success": False,
            "error": "Amcache.hve not found",
        })

    # Try RegRipper amcache plugin
    try:
        result = subprocess.run(
            ["rip.pl", "-r", str(amcache), "-p", "amcache"],
            capture_output=True, text=True, timeout=30, shell=False
        )
        if result.returncode == 0:
            return json.dumps({
                "success": True,
                "source": "regripper_amcache",
                "output": result.stdout[:5000],
                "caveat": "⚠️ Amcache proves PRESENCE only, NOT execution. Cross-reference with Prefetch for execution confirmation.",
            })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return json.dumps({
        "success": False,
        "error": "Could not parse Amcache (RegRipper not available or failed)",
        "file_exists": True,
        "file_size": amcache.stat().st_size,
    })


def analyze_registry_autoruns(evidence_path: str) -> str:
    """Check registry Run keys for persistence (autoruns).

    Examines HKLM and HKCU Run/RunOnce keys.

    Args:
        evidence_path: Path to mounted evidence

    Returns:
        JSON with autorun entries from registry.
    """
    p = Path(evidence_path)
    software_hive = p / "Windows" / "System32" / "config" / "SOFTWARE"

    if not software_hive.exists():
        return json.dumps({
            "success": False,
            "error": "SOFTWARE hive not found",
        })

    # Try RegRipper soft_run plugin
    try:
        result = subprocess.run(
            ["rip.pl", "-r", str(software_hive), "-p", "soft_run"],
            capture_output=True, text=True, timeout=30, shell=False
        )
        if result.returncode == 0:
            return json.dumps({
                "success": True,
                "source": "regripper_soft_run",
                "output": result.stdout[:3000],
                "caveat": "Registry Run keys configure autostart. Presence here means the program IS configured to run at startup, but doesn't prove it actually has.",
            })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return json.dumps({
        "success": False,
        "error": "Could not parse registry autoruns",
    })


def list_recent_files(evidence_path: str, directory: str, hours: int = 48) -> str:
    """List files modified within the last N hours in a specific directory.

    Uses filesystem timestamps (mtime). Note: timestamps CAN be manipulated.

    Args:
        evidence_path: Path to mounted evidence
        directory: Relative directory path to search (e.g., "Users/m.chen")
        hours: Look back period in hours (default 48)

    Returns:
        JSON with recently modified files.
    """
    import time

    p = Path(evidence_path) / directory.lstrip("/")
    if not p.exists():
        return json.dumps({"success": False, "error": f"Directory not found: {directory}"})

    cutoff = time.time() - (hours * 3600)
    recent = []

    try:
        for f in p.rglob("*"):
            if f.is_file():
                try:
                    mtime = f.stat().st_mtime
                    if mtime > cutoff:
                        recent.append({
                            "path": str(f.relative_to(Path(evidence_path))),
                            "name": f.name,
                            "size_bytes": f.stat().st_size,
                            "modified_time": mtime,
                        })
                except OSError:
                    continue
    except PermissionError:
        pass

    recent.sort(key=lambda x: x["modified_time"], reverse=True)

    return json.dumps({
        "success": True,
        "directory": directory,
        "hours_back": hours,
        "files_found": len(recent),
        "files": recent[:100],  # Limit
        "caveat": "Timestamps can be manipulated (timestomping). Cross-reference with USN Journal or Event Logs for reliable chronology.",
    })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AGENT DEFINITION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DISK_INSTRUCTION = """
You are the Disk Analysis Agent for SIFT Defender. You perform deep filesystem 
forensic analysis using SIFT Workstation tools.

## YOUR TOOLS
- analyze_prefetch_detail(binary_name) — Check if specific binary was executed
- analyze_services() — List configured Windows services
- check_event_logs(log_name, event_ids) — Parse event logs for specific events
- analyze_amcache() — Check application compatibility cache (PRESENCE only)
- analyze_registry_autoruns() — Check registry Run keys
- list_recent_files(directory, hours) — Find recently modified files

## EXECUTION STRATEGY
Based on what the triage_agent found, focus your analysis:
1. For each suspicious binary: check Prefetch → if missing, check services + tasks
2. For persistence: check Event 7045 (service install) + Event 106 (task created)
3. For execution chains: check Event 4688 (process creation with command lines)
4. For timeline: list_recent_files in key directories

## FORENSIC RULES (MUST follow)
- Amcache = PRESENCE (NOT execution). Never say "executed" based only on Amcache.
- Prefetch = EXECUTION. But absence ≠ non-execution (tasks/services exception).
- Event Logs CAN be cleared. Check Event 1102 to detect this.
- MFT timestamps can be manipulated. Cross-reference with event logs.
- Registry Run keys = CONFIGURED to run (may not have actually run).

## OUTPUT FORMAT
Return structured findings:
{
  "disk_findings": [
    {
      "title": "...",
      "confidence": "CONFIRMED|INFERRED",
      "sources": ["which tools produced this evidence"],
      "details": "...",
      "timestamps": ["relevant timestamps"],
      "contradictions": "any noted inconsistencies"
    }
  ],
  "artifacts_not_found": ["what was expected but missing"],
  "recommended_next_steps": ["what memory/correlation agents should check"]
}

ALWAYS transfer control back to the orchestrator when done.
"""

_model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

disk_agent = Agent(
    model=_model,
    name="disk_agent",
    description="Deep filesystem forensic analysis — Prefetch, registry, event logs, Amcache, services",
    instruction=DISK_INSTRUCTION,
    tools=[
        FunctionTool(analyze_prefetch_detail),
        FunctionTool(analyze_services),
        FunctionTool(check_event_logs),
        FunctionTool(analyze_amcache),
        FunctionTool(analyze_registry_autoruns),
        FunctionTool(list_recent_files),
    ],
    output_key="disk_output",
)
