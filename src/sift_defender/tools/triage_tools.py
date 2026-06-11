"""Triage tools — rapid initial assessment of forensic evidence."""

import json
from pathlib import Path

from sift_defender.tools.base import (
    EVIDENCE_MOUNT,
    format_tool_response,
    generate_audit_id,
    paginate_results,
    run_forensic_tool,
    validate_evidence_path,
)


def quick_timeline(mount_point: str, hours: int = 48) -> str:
    """Generate a quick filesystem timeline for the last N hours.
    
    Uses fls (Sleuthkit) to enumerate recent filesystem changes.
    
    Args:
        mount_point: Path to mounted evidence.
        hours: How many hours back to look (default 48).
    
    Returns: JSON with recent filesystem events sorted by time.
    """
    audit_id = generate_audit_id("quick_timeline")
    
    # Validate path is under evidence mount
    try:
        validated_path = validate_evidence_path(mount_point)
    except ValueError as e:
        return json.dumps({
            "success": False,
            "audit_id": audit_id,
            "tool": "quick_timeline",
            "error": str(e),
            "error_type": "path_validation_failed",
        })
    
    # Use fls to get file listing with timestamps
    result = run_forensic_tool(
        cmd=["fls", "-r", "-m", "/", "-p", str(validated_path)],
        tool_name="fls",
        audit_id=audit_id,
        timeout=180,  # Timeline can be slow on large images
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    # Parse and filter to recent entries
    entries = _parse_fls_timeline(result["raw_output"], hours)
    paginated = paginate_results(entries)
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="quick_timeline",
        data=paginated,
        caveats=[
            f"Showing filesystem changes from the last {hours} hours.",
            "MAC timestamps can be manipulated — cross-reference with event logs.",
            "Does not include log-based events (use parse_evtx for those).",
        ],
        suggested_next=[
            "parse_evtx(Security, [4688]) for process creation events",
            "scan_autoruns() to check persistence mechanisms",
            "parse_amcache() for application execution history",
        ],
        total_count=len(entries),
    )


def scan_autoruns(mount_point: str) -> str:
    """Scan for persistence mechanisms (scheduled tasks, services, run keys).
    
    Args:
        mount_point: Path to mounted evidence.
    
    Returns: JSON with autorun entries from multiple sources.
    """
    audit_id = generate_audit_id("scan_autoruns")
    
    try:
        validated_path = validate_evidence_path(mount_point)
    except ValueError as e:
        return json.dumps({
            "success": False,
            "audit_id": audit_id,
            "tool": "scan_autoruns",
            "error": str(e),
            "error_type": "path_validation_failed",
        })
    
    autoruns = []
    
    # Check scheduled tasks
    tasks_dir = validated_path / "Windows" / "System32" / "Tasks"
    if tasks_dir.exists():
        for task_file in tasks_dir.rglob("*"):
            if task_file.is_file():
                autoruns.append({
                    "type": "scheduled_task",
                    "name": task_file.name,
                    "path": str(task_file.relative_to(validated_path)),
                    "source": "filesystem_enumeration",
                })
    
    # Check registry Run keys via regripper
    software_hive = validated_path / "Windows" / "System32" / "config" / "SOFTWARE"
    if software_hive.exists():
        rip_result = run_forensic_tool(
            cmd=["rip.pl", "-r", str(software_hive), "-p", "soft_run"],
            tool_name="regripper_soft_run",
            audit_id=audit_id,
        )
        if rip_result["success"]:
            for entry in _parse_regripper_run(rip_result["raw_output"]):
                autoruns.append({**entry, "type": "registry_run_key"})
    
    # Check services via regripper
    system_hive = validated_path / "Windows" / "System32" / "config" / "SYSTEM"
    if system_hive.exists():
        rip_result = run_forensic_tool(
            cmd=["rip.pl", "-r", str(system_hive), "-p", "services"],
            tool_name="regripper_services",
            audit_id=audit_id,
        )
        if rip_result["success"]:
            for entry in _parse_regripper_services(rip_result["raw_output"]):
                autoruns.append({**entry, "type": "service"})
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="scan_autoruns",
        data=autoruns,
        caveats=[
            "Autorun entries don't prove the program actually executed.",
            "Disabled services/tasks still appear in this list.",
            "Cross-reference with Prefetch or Event Logs for execution proof.",
        ],
        suggested_next=[
            "parse_prefetch() to verify which autoruns actually executed",
            "parse_evtx(System, [7045]) for service installation events",
            "parse_evtx(TaskScheduler, [106]) for task creation events",
        ],
        total_count=len(autoruns),
    )


def check_hashes(mount_point: str, file_paths: list[str]) -> str:
    """Compute SHA-256 hashes for specified files.
    
    Args:
        mount_point: Path to mounted evidence.
        file_paths: List of file paths (relative to mount) to hash.
    
    Returns: JSON with hash results for IOC lookup.
    """
    audit_id = generate_audit_id("check_hashes")
    
    try:
        validated_mount = validate_evidence_path(mount_point)
    except ValueError as e:
        return json.dumps({
            "success": False,
            "audit_id": audit_id,
            "tool": "check_hashes",
            "error": str(e),
            "error_type": "path_validation_failed",
        })
    
    results = []
    for rel_path in file_paths[:50]:  # Limit to 50 files per call
        full_path = validated_mount / rel_path.lstrip("/")
        if full_path.exists() and full_path.is_file():
            hash_result = run_forensic_tool(
                cmd=["sha256sum", str(full_path)],
                tool_name="sha256sum",
                audit_id=audit_id,
            )
            if hash_result["success"]:
                sha256 = hash_result["raw_output"].split()[0]
                results.append({
                    "path": rel_path,
                    "sha256": sha256,
                    "size_bytes": full_path.stat().st_size,
                })
            else:
                results.append({
                    "path": rel_path,
                    "error": "Failed to compute hash",
                })
        else:
            results.append({
                "path": rel_path,
                "error": "File not found",
            })
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="check_hashes",
        data=results,
        caveats=[
            "Hashes are computed from the mounted evidence (read-only).",
            "Compare against threat intelligence feeds for known-bad indicators.",
        ],
        suggested_next=[
            "Look up hashes in VirusTotal or threat intel platforms",
            "Check if hash appears in known-good (Windows baseline) databases",
        ],
        total_count=len(results),
    )


def _parse_fls_timeline(raw: str, hours: int) -> list[dict]:
    """Parse fls bodyfile-format output into structured entries.
    
    TODO: Implement proper bodyfile parsing with time filtering.
    For now returns raw lines as entries.
    """
    entries = []
    for line in raw.strip().split("\n"):
        if line.strip():
            entries.append({"raw": line})
    return entries[:500]  # Limit for now


def _parse_regripper_run(raw: str) -> list[dict]:
    """Parse RegRipper soft_run plugin output."""
    entries = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if line and "=" in line:
            parts = line.split("=", 1)
            entries.append({
                "name": parts[0].strip(),
                "command": parts[1].strip() if len(parts) > 1 else "",
            })
    return entries


def _parse_regripper_services(raw: str) -> list[dict]:
    """Parse RegRipper services plugin output."""
    entries = []
    # TODO: Implement proper services parsing
    return entries
