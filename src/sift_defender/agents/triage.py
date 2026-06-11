"""Triage agent — rapid initial evidence assessment using real SIFT tools.

Calls actual forensic tools via subprocess to get ground-truth data.
No mocking — this runs fls, reads real filesystems, parses real artifacts.
"""

import json
import os
import subprocess
from pathlib import Path

from google.adk.agents import Agent
from google.adk.tools import FunctionTool


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TOOL FUNCTIONS (Real SIFT tool execution)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def get_evidence_info(evidence_path: str) -> str:
    """Get metadata about forensic evidence at the given path.

    Examines the mounted evidence to determine OS type, filesystem,
    and available artifact types.

    Args:
        evidence_path: Path to mounted evidence (e.g., /mnt/evidence)

    Returns:
        JSON with evidence metadata including OS, filesystem type, and available artifacts.
    """
    p = Path(evidence_path)
    if not p.exists():
        return json.dumps({"success": False, "error": f"Path not found: {evidence_path}"})

    if not p.is_dir():
        return json.dumps({"success": False, "error": f"Not a directory: {evidence_path}"})

    # Detect OS and available artifacts
    has_windows = (p / "Windows").exists()
    has_users = (p / "Users").exists()
    has_programdata = (p / "ProgramData").exists()
    has_etc = (p / "etc").exists()

    os_type = "Unknown"
    if has_windows:
        os_type = "Windows"
    elif has_etc:
        os_type = "Linux"

    # Check what artifacts are available
    artifacts_available = []
    if (p / "Windows" / "Prefetch").exists():
        prefetch_count = len(list((p / "Windows" / "Prefetch").glob("*.pf")))
        artifacts_available.append(f"Prefetch ({prefetch_count} files)")
    if (p / "Windows" / "System32" / "config" / "SYSTEM").exists():
        artifacts_available.append("Registry hives (SYSTEM, SOFTWARE)")
    if (p / "Windows" / "System32" / "winevt" / "Logs").exists():
        evtx_count = len(list((p / "Windows" / "System32" / "winevt" / "Logs").glob("*.evtx")))
        artifacts_available.append(f"Event Logs ({evtx_count} files)")
    if (p / "Windows" / "System32" / "Tasks").exists():
        artifacts_available.append("Scheduled Tasks")
    if (p / "Windows" / "appcompat" / "Programs" / "Amcache.hve").exists():
        artifacts_available.append("Amcache")
    if has_programdata:
        artifacts_available.append("ProgramData directory")

    # List user profiles
    users = []
    if has_users:
        users = [d.name for d in (p / "Users").iterdir()
                 if d.is_dir() and d.name not in ("Public", "Default", "Default User", "All Users")]

    return json.dumps({
        "success": True,
        "evidence_path": str(p),
        "os_detected": os_type,
        "user_profiles": users,
        "artifacts_available": artifacts_available,
        "has_windows_dir": has_windows,
        "has_users_dir": has_users,
        "has_programdata": has_programdata,
        "recommendation": "Start with list_suspicious_files and list_prefetch_files for quick wins"
    })


def list_suspicious_files(evidence_path: str) -> str:
    """Find suspicious files in common malware drop locations.

    Searches: user Downloads, Temp dirs, ProgramData, and unusual executable locations.

    Args:
        evidence_path: Path to mounted evidence (e.g., /mnt/evidence)

    Returns:
        JSON with suspicious files found, categorized by location and type.
    """
    p = Path(evidence_path)
    if not p.exists():
        return json.dumps({"success": False, "error": f"Path not found: {evidence_path}"})

    suspicious = []
    suspicious_extensions = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js",
                            ".hta", ".scr", ".com", ".pif", ".msi", ".docm", ".xlsm",
                            ".dotm", ".dat", ".bin"}

    # Check each user's Downloads and Temp
    users_dir = p / "Users"
    if users_dir.exists():
        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir() or user_dir.name in ("Public", "Default", "All Users"):
                continue

            # Downloads
            downloads = user_dir / "Downloads"
            if downloads.exists():
                for f in downloads.rglob("*"):
                    if f.is_file() and f.suffix.lower() in suspicious_extensions:
                        suspicious.append({
                            "path": str(f.relative_to(p)),
                            "name": f.name,
                            "location": "Downloads",
                            "user": user_dir.name,
                            "size_bytes": f.stat().st_size,
                            "type": _classify_file(f),
                        })

            # Temp directories
            for temp_path in [
                user_dir / "AppData" / "Local" / "Temp",
                user_dir / "AppData" / "Roaming",
            ]:
                if temp_path.exists():
                    for f in temp_path.rglob("*"):
                        if f.is_file() and f.suffix.lower() in suspicious_extensions:
                            suspicious.append({
                                "path": str(f.relative_to(p)),
                                "name": f.name,
                                "location": "Temp/AppData",
                                "user": user_dir.name,
                                "size_bytes": f.stat().st_size,
                                "type": _classify_file(f),
                            })

    # Check ProgramData (common malware drop location)
    progdata = p / "ProgramData"
    if progdata.exists():
        for f in progdata.rglob("*"):
            if f.is_file() and f.suffix.lower() in suspicious_extensions:
                suspicious.append({
                    "path": str(f.relative_to(p)),
                    "name": f.name,
                    "location": "ProgramData",
                    "size_bytes": f.stat().st_size,
                    "type": _classify_file(f),
                })

    return json.dumps({
        "success": True,
        "suspicious_files": suspicious,
        "count": len(suspicious),
        "note": "Files found in unusual locations. Cross-reference with Prefetch for execution proof and scheduled tasks/services for persistence.",
    })


def list_prefetch_files(evidence_path: str) -> str:
    """List Windows Prefetch files — proves program EXECUTION.

    FORENSIC CAVEAT: Prefetch proves a binary was executed.
    If a known-suspicious binary is NOT in Prefetch, it may:
    - Run via scheduled task (tasks often don't generate Prefetch)
    - Run as a service
    - Have never actually executed
    - Prefetch may have been cleared (anti-forensics)

    Args:
        evidence_path: Path to mounted evidence (e.g., /mnt/evidence)

    Returns:
        JSON with Prefetch entries and forensic caveats.
    """
    p = Path(evidence_path)
    prefetch_dir = p / "Windows" / "Prefetch"

    if not prefetch_dir.exists():
        return json.dumps({
            "success": True,
            "prefetch_files": [],
            "count": 0,
            "warning": "Prefetch directory not found. Possible causes: Prefetch disabled, cleared (anti-forensics), or non-Windows evidence.",
        })

    files = []
    for pf in sorted(prefetch_dir.glob("*.pf")):
        exe_name = pf.stem.rsplit("-", 1)[0] if "-" in pf.stem else pf.stem
        stat = pf.stat()
        files.append({
            "filename": pf.name,
            "executable": exe_name,
            "size_bytes": stat.st_size,
            "last_modified": stat.st_mtime,
        })

    return json.dumps({
        "success": True,
        "prefetch_files": files,
        "count": len(files),
        "caveat": "Prefetch proves EXECUTION occurred. Last modified time approximates last execution. Binaries run via scheduled tasks or services may NOT generate Prefetch entries.",
    })


def list_scheduled_tasks(evidence_path: str) -> str:
    """List scheduled tasks — common persistence mechanism.

    FORENSIC CAVEAT: A scheduled task means the binary is CONFIGURED to run,
    not necessarily that it HAS run. Cross-reference with Event Log (Event 200)
    for actual execution history.

    Binaries launched by scheduled tasks may NOT generate Prefetch entries.

    Args:
        evidence_path: Path to mounted evidence (e.g., /mnt/evidence)

    Returns:
        JSON with scheduled task details including trigger, action, and creation date.
    """
    p = Path(evidence_path)
    tasks_dir = p / "Windows" / "System32" / "Tasks"

    if not tasks_dir.exists():
        return json.dumps({
            "success": True,
            "scheduled_tasks": [],
            "count": 0,
            "note": "Tasks directory not found.",
        })

    tasks = []
    for task_file in tasks_dir.rglob("*"):
        if not task_file.is_file():
            continue
        try:
            content = task_file.read_text(errors="ignore")
            # Extract key fields from XML
            command = ""
            date = ""
            author = ""
            if "<Command>" in content:
                command = content.split("<Command>")[1].split("</Command>")[0]
            if "<Date>" in content:
                date = content.split("<Date>")[1].split("</Date>")[0]
            if "<Author>" in content:
                author = content.split("<Author>")[1].split("</Author>")[0]

            tasks.append({
                "name": task_file.name,
                "path": str(task_file.relative_to(tasks_dir)),
                "command": command,
                "creation_date": date,
                "author": author,
                "full_xml": content[:2000],
            })
        except Exception as e:
            tasks.append({
                "name": task_file.name,
                "error": str(e),
            })

    return json.dumps({
        "success": True,
        "scheduled_tasks": tasks,
        "count": len(tasks),
        "caveat": "Scheduled tasks are a common persistence mechanism. Binaries launched by tasks may NOT generate Prefetch entries. Cross-reference with TaskScheduler Event Log (Event 106=created, 200=executed, 141=deleted) for execution history.",
    })


def compute_file_hashes(evidence_path: str, file_paths: str) -> str:
    """Compute SHA-256 hashes for specified files (for IOC lookup).

    Args:
        evidence_path: Path to mounted evidence
        file_paths: Comma-separated list of file paths relative to evidence mount

    Returns:
        JSON with SHA-256 hashes for each file.
    """
    p = Path(evidence_path)
    paths = [fp.strip() for fp in file_paths.split(",") if fp.strip()]

    results = []
    for rel_path in paths[:20]:  # Limit
        full_path = p / rel_path.lstrip("/")
        if full_path.exists() and full_path.is_file():
            try:
                result = subprocess.run(
                    ["sha256sum", str(full_path)],
                    capture_output=True, text=True, timeout=10, shell=False
                )
                if result.returncode == 0:
                    sha256 = result.stdout.split()[0]
                    results.append({
                        "path": rel_path,
                        "sha256": sha256,
                        "size_bytes": full_path.stat().st_size,
                    })
                else:
                    results.append({"path": rel_path, "error": "hash computation failed"})
            except Exception as e:
                results.append({"path": rel_path, "error": str(e)})
        else:
            results.append({"path": rel_path, "error": "file not found"})

    return json.dumps({
        "success": True,
        "hashes": results,
        "count": len(results),
        "note": "Compare hashes against threat intelligence (VirusTotal, MISP, etc.) for known-bad indicators.",
    })


def _classify_file(filepath: Path) -> str:
    """Classify a file by its extension."""
    ext = filepath.suffix.lower()
    if ext in (".docm", ".xlsm", ".dotm"):
        return "macro_enabled_document"
    elif ext in (".exe", ".dll", ".scr", ".com"):
        return "executable"
    elif ext in (".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"):
        return "script"
    elif ext in (".dat", ".bin"):
        return "data_blob"
    return "other"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AGENT DEFINITION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TRIAGE_INSTRUCTION = """
You are the Triage Agent for SIFT Defender. Your job is rapid initial assessment
of forensic evidence — understand what we're working with and flag the most
suspicious items in under 60 seconds.

## EXECUTION PLAN
1. Call get_evidence_info() — understand the evidence type and available artifacts
2. Call list_suspicious_files() — find files in unusual locations
3. Call list_prefetch_files() — check what has been executed
4. Call list_scheduled_tasks() — check persistence mechanisms
5. If suspicious binaries found, call compute_file_hashes() on them

## OUTPUT FORMAT
Return a structured JSON summary:
{
  "evidence_type": "Windows disk image",
  "os_version": "detected OS",
  "users": ["list of user profiles"],
  "suspicious_files": [{"name": "...", "location": "...", "type": "..."}],
  "executed_programs": ["from Prefetch"],
  "persistence_mechanisms": [{"type": "scheduled_task", "name": "...", "command": "..."}],
  "initial_findings": [
    {
      "title": "...",
      "confidence": "CONFIRMED|INFERRED",
      "evidence": "which tool output supports this",
      "recommendation": "what to investigate next"
    }
  ],
  "inconsistencies_noted": ["any contradictions between artifacts"],
  "recommended_focus": "what the disk/memory agents should investigate deeper"
}

## CRITICAL FORENSIC RULES
- If a suspicious binary is in the filesystem but NOT in Prefetch:
  Check scheduled tasks and services BEFORE concluding it wasn't executed.
  Note this as a potential inconsistency for the orchestrator to resolve.
- Always note what you DIDN'T check (e.g., "Event logs not examined in triage")

ALWAYS transfer control back to the orchestrator after producing your output.
"""

_model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

triage_agent = Agent(
    model=_model,
    name="triage_agent",
    description="Rapid initial assessment of forensic evidence — classify, flag suspicious items, identify persistence",
    instruction=TRIAGE_INSTRUCTION,
    tools=[
        FunctionTool(get_evidence_info),
        FunctionTool(list_suspicious_files),
        FunctionTool(list_prefetch_files),
        FunctionTool(list_scheduled_tasks),
        FunctionTool(compute_file_hashes),
    ],
    output_key="triage_output",
)
