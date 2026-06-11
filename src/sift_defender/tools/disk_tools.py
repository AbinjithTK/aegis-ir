"""Disk analysis tools — Sleuthkit, RegRipper, EVTX parsing.

These tools wrap SIFT Workstation forensic utilities as type-safe 
Python functions. Each function:
- Validates inputs
- Runs the tool via subprocess (shell=False)
- Parses raw output into structured JSON
- Includes forensic caveats
- Generates audit trail entries
"""

import json
from pathlib import Path

from sift_defender.tools.base import (
    format_tool_response,
    generate_audit_id,
    paginate_results,
    run_forensic_tool,
    validate_evidence_path,
)


def parse_mft(mount_point: str, path: str = "/", time_range: str = "") -> str:
    """Parse MFT entries from a mounted NTFS volume.
    
    Args:
        mount_point: Path to mounted evidence.
        path: Directory path to filter (relative to mount).
        time_range: ISO time range filter "2025-09-15T08:00/2025-09-15T09:00".
    
    Returns: JSON with MFT entries (filename, timestamps, size, parent).
    """
    audit_id = generate_audit_id("parse_mft")
    # TODO: Implement using analyzeMFT or fls with MFT parsing
    return format_tool_response(
        audit_id=audit_id,
        tool_name="parse_mft",
        data={"status": "not_yet_implemented"},
        caveats=[
            "MFT contains 4 timestamps per entry: Created, Modified, Accessed, Entry-Modified.",
            "Timestamps CAN be manipulated by attackers (timestomping).",
            "Cross-reference with USN Journal for more reliable change records.",
        ],
    )


def parse_amcache(mount_point: str, time_range: str = "") -> str:
    """Parse Amcache entries (application compatibility cache).
    
    CAVEAT: Amcache proves a file was PRESENT on the system.
    It does NOT prove the file was EXECUTED.
    Cross-reference with Prefetch for execution confirmation.
    
    Args:
        mount_point: Path to mounted evidence.
        time_range: Optional ISO time range filter.
    
    Returns: JSON with Amcache entries.
    """
    audit_id = generate_audit_id("parse_amcache")
    
    try:
        validated_path = validate_evidence_path(mount_point)
    except ValueError as e:
        return json.dumps({
            "success": False, "audit_id": audit_id,
            "error": str(e), "error_type": "path_validation_failed",
        })
    
    amcache_path = validated_path / "Windows" / "appcompat" / "Programs" / "Amcache.hve"
    
    if not amcache_path.exists():
        return json.dumps({
            "success": False, "audit_id": audit_id,
            "tool": "parse_amcache",
            "error": "Amcache.hve not found at expected path",
            "error_type": "artifact_not_found",
            "suggestion": "Check if evidence is Windows and properly mounted",
        })
    
    result = run_forensic_tool(
        cmd=["rip.pl", "-r", str(amcache_path), "-p", "amcache"],
        tool_name="regripper_amcache",
        audit_id=audit_id,
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    entries = _parse_amcache_output(result["raw_output"])
    paginated = paginate_results(entries)
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="parse_amcache",
        data=paginated,
        caveats=[
            "⚠️ Amcache proves file PRESENCE, NOT EXECUTION.",
            "First-seen timestamps indicate when the file was first noticed by the system.",
            "Cross-reference with Prefetch for execution confirmation.",
            "Cross-reference with Shimcache for additional presence corroboration.",
        ],
        suggested_next=[
            "parse_prefetch() — confirm execution of files found here",
            "parse_shimcache() — additional presence corroboration",
            "parse_evtx(Security, [4688]) — process creation events",
        ],
        total_count=len(entries),
    )


def parse_prefetch(mount_point: str, binary_name: str = "") -> str:
    """Parse Windows Prefetch files (execution evidence).
    
    Prefetch files prove a binary was EXECUTED. Each file records:
    - Last 8 execution times
    - Total execution count
    - Files/directories accessed during execution
    
    Args:
        mount_point: Path to mounted evidence.
        binary_name: Optional filter — only show entries matching this name.
    
    Returns: JSON with Prefetch entries.
    """
    audit_id = generate_audit_id("parse_prefetch")
    
    try:
        validated_path = validate_evidence_path(mount_point)
    except ValueError as e:
        return json.dumps({
            "success": False, "audit_id": audit_id,
            "error": str(e), "error_type": "path_validation_failed",
        })
    
    prefetch_dir = validated_path / "Windows" / "Prefetch"
    
    if not prefetch_dir.exists():
        return json.dumps({
            "success": False, "audit_id": audit_id,
            "tool": "parse_prefetch",
            "error": "Prefetch directory not found",
            "error_type": "artifact_not_found",
            "suggestion": "Prefetch may be disabled or cleared (anti-forensics indicator)",
        })
    
    # List .pf files
    pf_files = list(prefetch_dir.glob("*.pf"))
    
    entries = []
    for pf in pf_files:
        name = pf.stem  # e.g., "POWERSHELL.EXE-1A2B3C4D"
        exe_name = name.rsplit("-", 1)[0] if "-" in name else name
        
        if binary_name and binary_name.upper() not in exe_name.upper():
            continue
        
        entries.append({
            "filename": pf.name,
            "executable": exe_name,
            "size_bytes": pf.stat().st_size,
            "last_modified": pf.stat().st_mtime,
        })
    
    if binary_name and not entries:
        return format_tool_response(
            audit_id=audit_id,
            tool_name="parse_prefetch",
            data=[],
            caveats=[
                f"⚠️ NO Prefetch entry found for '{binary_name}'.",
                "This means the binary was likely NEVER EXECUTED interactively.",
                "However: scheduled tasks and services may not generate Prefetch.",
                "Check scheduled tasks and services before concluding 'not executed'.",
            ],
            suggested_next=[
                "get_scheduled_tasks() — binary may run via task scheduler",
                "get_services() — binary may run as a service",
                "parse_evtx(Security, [4688]) — check process creation events",
            ],
            total_count=0,
        )
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="parse_prefetch",
        data=entries,
        caveats=[
            "Prefetch proves EXECUTION occurred.",
            "Last modified time ≈ last execution time.",
            "Windows keeps max 1024 Prefetch files (oldest may be rotated out).",
        ],
        suggested_next=[
            "parse_evtx(Security, [4688]) — get command line for the execution",
            "parse_amcache() — corroborate with application cache",
        ],
        total_count=len(entries),
    )


def parse_shimcache(mount_point: str) -> str:
    """Parse Shimcache (AppCompatCache) entries.
    
    CAVEAT: Shimcache proves PRESENCE, not execution.
    
    Args:
        mount_point: Path to mounted evidence.
    
    Returns: JSON with Shimcache entries.
    """
    audit_id = generate_audit_id("parse_shimcache")
    # TODO: Implement using RegRipper appcompatcache plugin
    return format_tool_response(
        audit_id=audit_id,
        tool_name="parse_shimcache",
        data={"status": "not_yet_implemented"},
        caveats=[
            "⚠️ Shimcache proves file PRESENCE, NOT EXECUTION.",
            "Entries are ordered (most recent first) but order ≠ execution order.",
        ],
    )


def parse_usn_journal(mount_point: str, time_range: str = "") -> str:
    """Parse USN Journal (filesystem change journal).
    
    Args:
        mount_point: Path to mounted evidence.
        time_range: Optional ISO time range filter.
    
    Returns: JSON with USN Journal entries.
    """
    audit_id = generate_audit_id("parse_usn_journal")
    # TODO: Implement using usnjrnl parsing tool
    return format_tool_response(
        audit_id=audit_id,
        tool_name="parse_usn_journal",
        data={"status": "not_yet_implemented"},
        caveats=[
            "USN Journal records all NTFS changes (create, delete, rename, etc.).",
            "More reliable than MFT timestamps for detecting changes.",
            "Journal has a size limit — oldest entries may be lost.",
        ],
    )


def parse_registry(mount_point: str, hive: str, plugin: str) -> str:
    """Parse Windows registry using RegRipper.
    
    Args:
        mount_point: Path to mounted evidence.
        hive: Registry hive name (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER, UsrClass).
        plugin: RegRipper plugin name (e.g., "services", "soft_run", "userassist").
    
    Returns: JSON with parsed registry data.
    """
    audit_id = generate_audit_id("parse_registry")
    
    try:
        validated_path = validate_evidence_path(mount_point)
    except ValueError as e:
        return json.dumps({
            "success": False, "audit_id": audit_id,
            "error": str(e), "error_type": "path_validation_failed",
        })
    
    # Map hive name to file path
    hive_paths = {
        "SYSTEM": validated_path / "Windows" / "System32" / "config" / "SYSTEM",
        "SOFTWARE": validated_path / "Windows" / "System32" / "config" / "SOFTWARE",
        "SAM": validated_path / "Windows" / "System32" / "config" / "SAM",
        "SECURITY": validated_path / "Windows" / "System32" / "config" / "SECURITY",
    }
    
    hive_path = hive_paths.get(hive.upper())
    if not hive_path:
        # Try NTUSER.DAT for user hives
        if hive.upper() == "NTUSER":
            # Find user NTUSER.DAT files
            users_dir = validated_path / "Users"
            if users_dir.exists():
                for user_dir in users_dir.iterdir():
                    ntuser = user_dir / "NTUSER.DAT"
                    if ntuser.exists():
                        hive_path = ntuser
                        break
    
    if not hive_path or not hive_path.exists():
        return json.dumps({
            "success": False, "audit_id": audit_id,
            "tool": "parse_registry",
            "error": f"Registry hive '{hive}' not found",
            "error_type": "artifact_not_found",
        })
    
    result = run_forensic_tool(
        cmd=["rip.pl", "-r", str(hive_path), "-p", plugin],
        tool_name=f"regripper_{plugin}",
        audit_id=audit_id,
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="parse_registry",
        data={"hive": hive, "plugin": plugin, "output": result["raw_output"][:5000]},
        caveats=[
            "Registry data reflects the state at time of imaging.",
            "Deleted keys may still be recoverable from unallocated hive space.",
            "Timestamps on keys indicate last modification time.",
        ],
    )


def parse_evtx(
    mount_point: str,
    log_name: str,
    event_ids: list[int] | None = None,
    time_range: str = "",
) -> str:
    """Parse Windows Event Logs (.evtx files).
    
    Args:
        mount_point: Path to mounted evidence.
        log_name: Event log name (Security, System, Application, TaskScheduler, PowerShell).
        event_ids: Optional list of event IDs to filter.
        time_range: Optional ISO time range filter.
    
    Returns: JSON with parsed event log entries.
    """
    audit_id = generate_audit_id("parse_evtx")
    
    try:
        validated_path = validate_evidence_path(mount_point)
    except ValueError as e:
        return json.dumps({
            "success": False, "audit_id": audit_id,
            "error": str(e), "error_type": "path_validation_failed",
        })
    
    # Map log names to file paths
    evtx_dir = validated_path / "Windows" / "System32" / "winevt" / "Logs"
    log_file_map = {
        "Security": "Security.evtx",
        "System": "System.evtx",
        "Application": "Application.evtx",
        "PowerShell": "Microsoft-Windows-PowerShell%4Operational.evtx",
        "TaskScheduler": "Microsoft-Windows-TaskScheduler%4Operational.evtx",
        "Sysmon": "Microsoft-Windows-Sysmon%4Operational.evtx",
    }
    
    log_filename = log_file_map.get(log_name, f"{log_name}.evtx")
    evtx_path = evtx_dir / log_filename
    
    if not evtx_path.exists():
        return json.dumps({
            "success": False, "audit_id": audit_id,
            "tool": "parse_evtx",
            "error": f"Event log not found: {log_filename}",
            "error_type": "artifact_not_found",
            "suggestion": f"Available logs: {[f.name for f in evtx_dir.glob('*.evtx')][:10]}" if evtx_dir.exists() else "Event log directory not found",
        })
    
    # Use evtx_dump to parse
    cmd = ["evtx_dump", "-o", "jsonl", str(evtx_path)]
    
    result = run_forensic_tool(
        cmd=cmd,
        tool_name="evtx_dump",
        audit_id=audit_id,
        timeout=180,
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    # Parse JSONL output and filter
    entries = _parse_evtx_output(result["raw_output"], event_ids, time_range)
    paginated = paginate_results(entries)
    
    event_id_str = f" (filtered: {event_ids})" if event_ids else ""
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="parse_evtx",
        data=paginated,
        caveats=[
            f"Parsed {log_name} event log{event_id_str}.",
            "Event logs CAN be cleared by attackers (absence ≠ non-occurrence).",
            "Timestamps are from the system clock (could be manipulated).",
            "Event 4688 requires 'Audit Process Creation' policy to include command lines.",
        ],
        suggested_next=[
            "Cross-reference timestamps with MFT and Prefetch",
            "Check for log clearing events (Event 1102 in Security, 104 in System)",
        ],
        total_count=len(entries),
    )


def get_scheduled_tasks(mount_point: str) -> str:
    """Extract scheduled tasks from the evidence.
    
    Args:
        mount_point: Path to mounted evidence.
    
    Returns: JSON with scheduled task definitions.
    """
    audit_id = generate_audit_id("scheduled_tasks")
    
    try:
        validated_path = validate_evidence_path(mount_point)
    except ValueError as e:
        return json.dumps({
            "success": False, "audit_id": audit_id,
            "error": str(e), "error_type": "path_validation_failed",
        })
    
    tasks_dir = validated_path / "Windows" / "System32" / "Tasks"
    
    if not tasks_dir.exists():
        return json.dumps({
            "success": False, "audit_id": audit_id,
            "tool": "get_scheduled_tasks",
            "error": "Tasks directory not found",
            "error_type": "artifact_not_found",
        })
    
    tasks = []
    for task_file in tasks_dir.rglob("*"):
        if task_file.is_file():
            try:
                content = task_file.read_text(errors="ignore")
                tasks.append({
                    "name": task_file.name,
                    "path": str(task_file.relative_to(tasks_dir)),
                    "size_bytes": task_file.stat().st_size,
                    "content_preview": content[:500],
                })
            except OSError:
                tasks.append({
                    "name": task_file.name,
                    "path": str(task_file.relative_to(tasks_dir)),
                    "error": "Could not read file",
                })
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="get_scheduled_tasks",
        data=tasks,
        caveats=[
            "Scheduled tasks are a common persistence mechanism.",
            "Task XML files show: trigger, action, user context, creation date.",
            "A binary executing via scheduled task may NOT generate Prefetch.",
        ],
        suggested_next=[
            "parse_evtx(TaskScheduler, [106, 141]) — task creation/deletion events",
            "parse_amcache() — check if task binary appears in application cache",
        ],
        total_count=len(tasks),
    )


def get_services(mount_point: str) -> str:
    """Extract installed services from registry.
    
    Args:
        mount_point: Path to mounted evidence.
    
    Returns: JSON with service definitions.
    """
    audit_id = generate_audit_id("get_services")
    return parse_registry(mount_point, "SYSTEM", "services")


def recover_deleted_files(mount_point: str, path: str = "/") -> str:
    """Attempt to recover deleted files from unallocated space.
    
    Args:
        mount_point: Path to mounted evidence.
        path: Directory to recover from.
    
    Returns: JSON with recovered file metadata.
    """
    audit_id = generate_audit_id("recover_deleted")
    # TODO: Implement using tsk_recover
    return format_tool_response(
        audit_id=audit_id,
        tool_name="recover_deleted_files",
        data={"status": "not_yet_implemented"},
        caveats=[
            "Deleted file recovery depends on whether space has been overwritten.",
            "Only metadata may be recoverable if data blocks are reused.",
        ],
    )


def _parse_amcache_output(raw: str) -> list[dict]:
    """Parse RegRipper amcache plugin output into structured entries."""
    entries = []
    current_entry = {}
    
    for line in raw.split("\n"):
        line = line.strip()
        if not line:
            if current_entry:
                entries.append(current_entry)
                current_entry = {}
            continue
        
        if ":" in line:
            key, _, value = line.partition(":")
            current_entry[key.strip().lower().replace(" ", "_")] = value.strip()
    
    if current_entry:
        entries.append(current_entry)
    
    return entries


def _parse_evtx_output(
    raw: str, event_ids: list[int] | None, time_range: str
) -> list[dict]:
    """Parse evtx_dump JSONL output with optional filtering."""
    entries = []
    
    for line in raw.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            
            # Filter by event ID if specified
            if event_ids:
                eid = event.get("Event", {}).get("System", {}).get("EventID")
                if isinstance(eid, dict):
                    eid = eid.get("#text")
                try:
                    if int(eid) not in event_ids:
                        continue
                except (TypeError, ValueError):
                    continue
            
            entries.append(event)
        except json.JSONDecodeError:
            continue
    
    return entries[:500]  # Paginate
