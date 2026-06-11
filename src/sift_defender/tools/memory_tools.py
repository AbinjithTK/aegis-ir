"""Memory analysis tools — Volatility 3 wrappers.

All memory tools use Volatility 3 (vol.py) via subprocess.
"""

import json
from sift_defender.tools.base import (
    format_tool_response,
    generate_audit_id,
    paginate_results,
    run_forensic_tool,
)


def vol_pslist(dump_path: str) -> str:
    """List running processes from memory dump.
    
    Args:
        dump_path: Path to memory dump file (.lime, .mem, .dmp, .raw).
    
    Returns: JSON with process list (PID, PPID, name, create time).
    """
    audit_id = generate_audit_id("vol_pslist")
    
    result = run_forensic_tool(
        cmd=["vol.py", "-f", dump_path, "windows.pslist", "--output", "json"],
        tool_name="volatility_pslist",
        audit_id=audit_id,
        timeout=300,
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    processes = _parse_vol_json(result["raw_output"])
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="vol_pslist",
        data=paginate_results(processes),
        caveats=[
            "Process list reflects state at time of memory capture.",
            "Processes may have started/stopped between disk and memory imaging.",
            "Hidden processes (DKOM) may not appear — use psscan for detection.",
        ],
        suggested_next=[
            "vol_pstree() — see parent-child process relationships",
            "vol_cmdline() — get command line arguments",
            "vol_netscan() — see network connections per process",
        ],
        total_count=len(processes),
    )


def vol_pstree(dump_path: str) -> str:
    """Show process tree (parent-child relationships).
    
    Args:
        dump_path: Path to memory dump file.
    
    Returns: JSON with process tree.
    """
    audit_id = generate_audit_id("vol_pstree")
    
    result = run_forensic_tool(
        cmd=["vol.py", "-f", dump_path, "windows.pstree", "--output", "json"],
        tool_name="volatility_pstree",
        audit_id=audit_id,
        timeout=300,
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    tree = _parse_vol_json(result["raw_output"])
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="vol_pstree",
        data=tree,
        caveats=[
            "Process tree shows parent-child execution relationships.",
            "Unusual parent-child combos (e.g., Word → PowerShell) are suspicious.",
            "Parent process may have terminated (orphaned children show PPID of dead process).",
        ],
    )


def vol_netscan(dump_path: str) -> str:
    """Scan for network connections in memory.
    
    Args:
        dump_path: Path to memory dump file.
    
    Returns: JSON with network connections (local/remote addr, state, PID).
    """
    audit_id = generate_audit_id("vol_netscan")
    
    result = run_forensic_tool(
        cmd=["vol.py", "-f", dump_path, "windows.netscan", "--output", "json"],
        tool_name="volatility_netscan",
        audit_id=audit_id,
        timeout=300,
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    connections = _parse_vol_json(result["raw_output"])
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="vol_netscan",
        data=paginate_results(connections),
        caveats=[
            "Network connections were ACTIVE at time of memory capture.",
            "Closed connections may still appear as residual artifacts.",
            "Compare remote IPs against threat intelligence.",
        ],
        suggested_next=[
            "Look up remote IPs in threat intelligence",
            "Cross-reference PIDs with vol_pslist() to identify connecting processes",
        ],
        total_count=len(connections),
    )


def vol_malfind(dump_path: str) -> str:
    """Detect injected or suspicious memory regions.
    
    Args:
        dump_path: Path to memory dump file.
    
    Returns: JSON with suspicious memory regions.
    """
    audit_id = generate_audit_id("vol_malfind")
    
    result = run_forensic_tool(
        cmd=["vol.py", "-f", dump_path, "windows.malfind", "--output", "json"],
        tool_name="volatility_malfind",
        audit_id=audit_id,
        timeout=600,  # Malfind can be slow
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    findings = _parse_vol_json(result["raw_output"])
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="vol_malfind",
        data=paginate_results(findings),
        caveats=[
            "⚠️ Malfind detects SUSPICIOUS memory regions — NOT definitive malware.",
            "False positives are common (JIT compilers, .NET, browser engines).",
            "Look for: executable memory without a file backing, suspicious process context.",
            "Cross-reference with process tree — a legitimate browser has RWX regions.",
        ],
        suggested_next=[
            "vol_dlllist() on flagged PIDs — check loaded DLLs",
            "vol_handles() on flagged PIDs — check open handles",
            "Cross-reference flagged PID with disk artifacts",
        ],
        total_count=len(findings),
    )


def vol_cmdline(dump_path: str) -> str:
    """Get command line arguments for all processes.
    
    Args:
        dump_path: Path to memory dump file.
    
    Returns: JSON with process command lines.
    """
    audit_id = generate_audit_id("vol_cmdline")
    
    result = run_forensic_tool(
        cmd=["vol.py", "-f", dump_path, "windows.cmdline", "--output", "json"],
        tool_name="volatility_cmdline",
        audit_id=audit_id,
        timeout=300,
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    cmdlines = _parse_vol_json(result["raw_output"])
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="vol_cmdline",
        data=paginate_results(cmdlines),
        caveats=[
            "Command lines show exactly how processes were launched.",
            "Encoded commands (base64, -enc) are highly suspicious.",
            "Empty command lines may indicate rootkit-hidden processes.",
        ],
        total_count=len(cmdlines),
    )


def vol_dlllist(dump_path: str, pid: int) -> str:
    """List DLLs loaded by a specific process.
    
    Args:
        dump_path: Path to memory dump file.
        pid: Process ID to inspect.
    
    Returns: JSON with loaded DLLs.
    """
    audit_id = generate_audit_id("vol_dlllist")
    
    result = run_forensic_tool(
        cmd=["vol.py", "-f", dump_path, "windows.dlllist", "--pid", str(pid), "--output", "json"],
        tool_name="volatility_dlllist",
        audit_id=audit_id,
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    dlls = _parse_vol_json(result["raw_output"])
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="vol_dlllist",
        data=dlls,
        caveats=[
            "DLL list shows libraries loaded into process address space.",
            "Unusual DLLs (loaded from temp dirs, user folders) are suspicious.",
            "DLL side-loading uses legitimate paths with malicious content.",
        ],
    )


def vol_handles(dump_path: str, pid: int) -> str:
    """List open handles for a specific process.
    
    Args:
        dump_path: Path to memory dump file.
        pid: Process ID to inspect.
    
    Returns: JSON with open handles (files, registry, mutexes, etc.).
    """
    audit_id = generate_audit_id("vol_handles")
    
    result = run_forensic_tool(
        cmd=["vol.py", "-f", dump_path, "windows.handles", "--pid", str(pid), "--output", "json"],
        tool_name="volatility_handles",
        audit_id=audit_id,
        timeout=300,
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    handles = _parse_vol_json(result["raw_output"])
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="vol_handles",
        data=paginate_results(handles),
        caveats=[
            "Open handles show what resources a process is actively using.",
            "File handles indicate files being read/written.",
            "Registry handles indicate configuration being accessed.",
            "Mutexes may indicate known malware families (known mutex names).",
        ],
        total_count=len(handles),
    )


def vol_filescan(dump_path: str) -> str:
    """Scan for file objects in memory (includes deleted files).
    
    Args:
        dump_path: Path to memory dump file.
    
    Returns: JSON with file objects found in memory.
    """
    audit_id = generate_audit_id("vol_filescan")
    
    result = run_forensic_tool(
        cmd=["vol.py", "-f", dump_path, "windows.filescan", "--output", "json"],
        tool_name="volatility_filescan",
        audit_id=audit_id,
        timeout=600,
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    files = _parse_vol_json(result["raw_output"])
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="vol_filescan",
        data=paginate_results(files),
        caveats=[
            "File objects in memory include files that may have been deleted from disk.",
            "A file in memory but NOT on disk suggests deletion after opening.",
            "Use this for finding artifacts the attacker tried to remove.",
        ],
        total_count=len(files),
    )


def vol_timeliner(dump_path: str) -> str:
    """Generate timeline from memory artifacts.
    
    Args:
        dump_path: Path to memory dump file.
    
    Returns: JSON with timeline entries from memory.
    """
    audit_id = generate_audit_id("vol_timeliner")
    
    result = run_forensic_tool(
        cmd=["vol.py", "-f", dump_path, "timeliner.Timeliner", "--output", "json"],
        tool_name="volatility_timeliner",
        audit_id=audit_id,
        timeout=600,
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    timeline = _parse_vol_json(result["raw_output"])
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="vol_timeliner",
        data=paginate_results(timeline),
        caveats=[
            "Memory timeline combines timestamps from processes, modules, and network.",
            "Cross-reference with disk timeline for complete picture.",
        ],
        total_count=len(timeline),
    )


def _parse_vol_json(raw: str) -> list[dict]:
    """Parse Volatility JSON output."""
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("results", data.get("rows", [data]))
    except json.JSONDecodeError:
        # Fall back to line-by-line JSONL
        entries = []
        for line in raw.split("\n"):
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries
    return []
