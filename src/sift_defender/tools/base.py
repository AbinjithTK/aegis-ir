"""Base tool infrastructure — shared across all forensic tools.

Provides:
- Audit ID generation
- Path validation (prevent traversal)
- Subprocess execution (shell=False, timeout, denylist)
- Output parsing and pagination
- Forensic caveat injection
- Structured response format
"""

import hashlib
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# Evidence mount point — all paths must be under this
EVIDENCE_MOUNT = Path(os.environ.get("SIFT_EVIDENCE_MOUNT", "/mnt/evidence"))

# Case output directory
CASE_DIR = Path(os.environ.get("SIFT_CASE_DIR", "/cases/active"))

# Maximum entries returned per tool call (prevent context overflow)
MAX_PAGE_SIZE = 500

# Default tool timeout in seconds
DEFAULT_TIMEOUT = 120

# Commands that are NEVER allowed
DENYLIST = frozenset([
    "rm", "rmdir", "mkfs", "dd", "fdisk", "gdisk", "parted",
    "shutdown", "reboot", "halt", "poweroff",
    "mount",  # Only our mount_evidence function can mount
    "umount",
    "chmod", "chown",  # Don't modify evidence permissions
    "shred", "wipe",
    "nc", "ncat", "netcat",  # No network tools on evidence
])


class ToolError:
    """Structured error response from a forensic tool."""

    def __init__(self, tool: str, error_type: str, message: str, suggestion: str = ""):
        self.tool = tool
        self.error_type = error_type
        self.message = message
        self.suggestion = suggestion

    def to_json(self) -> str:
        return json.dumps({
            "success": False,
            "tool": self.tool,
            "error_type": self.error_type,
            "error": self.message,
            "suggestion": self.suggestion,
        })


def generate_audit_id(tool_name: str) -> str:
    """Generate unique audit ID for tracing findings back to tool executions."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_uuid = uuid.uuid4().hex[:8]
    return f"{tool_name}-{ts}-{short_uuid}"


def validate_evidence_path(path: str) -> Path:
    """Validate that path is under the evidence mount point.
    
    Prevents path traversal attacks (../../etc/passwd).
    """
    resolved = Path(path).resolve()
    evidence_resolved = EVIDENCE_MOUNT.resolve()

    if not str(resolved).startswith(str(evidence_resolved)):
        raise ValueError(
            f"Path traversal blocked: {path} resolves outside evidence mount "
            f"({evidence_resolved})"
        )
    return resolved


def run_forensic_tool(
    cmd: list[str],
    tool_name: str,
    timeout: int = DEFAULT_TIMEOUT,
    audit_id: str | None = None,
) -> dict:
    """Execute a forensic tool safely.
    
    - shell=False (ALWAYS)
    - Validates command against denylist
    - Captures stdout/stderr
    - Logs execution to audit trail
    - Returns structured result
    """
    if not audit_id:
        audit_id = generate_audit_id(tool_name)

    # Denylist check
    binary = Path(cmd[0]).name.lower()
    if binary in DENYLIST:
        return {
            "success": False,
            "audit_id": audit_id,
            "tool": tool_name,
            "error": f"Blocked: '{binary}' is on the denylist",
            "error_type": "denylist_blocked",
        }

    # Log the execution (audit trail)
    _log_execution(audit_id, tool_name, cmd)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # NEVER True
        )

        if result.returncode != 0:
            return {
                "success": False,
                "audit_id": audit_id,
                "tool": tool_name,
                "error": result.stderr[:500] if result.stderr else "Non-zero exit code",
                "error_type": "tool_failure",
                "exit_code": result.returncode,
            }

        return {
            "success": True,
            "audit_id": audit_id,
            "tool": tool_name,
            "raw_output": result.stdout,
            "output_length": len(result.stdout),
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "audit_id": audit_id,
            "tool": tool_name,
            "error": f"Tool timed out after {timeout}s",
            "error_type": "timeout",
            "suggestion": "Evidence may be very large or corrupted",
        }
    except FileNotFoundError:
        return {
            "success": False,
            "audit_id": audit_id,
            "tool": tool_name,
            "error": f"Tool binary not found: {cmd[0]}",
            "error_type": "binary_not_found",
            "suggestion": "Ensure SIFT Workstation tools are installed",
        }
    except Exception as e:
        return {
            "success": False,
            "audit_id": audit_id,
            "tool": tool_name,
            "error": str(e)[:500],
            "error_type": "unexpected_error",
        }


def paginate_results(items: list, page: int = 1, page_size: int = MAX_PAGE_SIZE) -> dict:
    """Paginate large result sets to prevent context overflow."""
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    page_items = items[start:end]

    return {
        "data": page_items,
        "total_count": total,
        "page": page,
        "page_size": page_size,
        "has_more": end < total,
    }


def format_tool_response(
    audit_id: str,
    tool_name: str,
    data: Any,
    caveats: list[str] | None = None,
    suggested_next: list[str] | None = None,
    total_count: int | None = None,
) -> str:
    """Format a successful tool response as JSON string for the agent."""
    response = {
        "success": True,
        "audit_id": audit_id,
        "tool": tool_name,
        "data": data,
    }
    if total_count is not None:
        response["total_count"] = total_count
    if caveats:
        response["caveats"] = caveats
    if suggested_next:
        response["suggested_next"] = suggested_next

    return json.dumps(response, default=str)


def _log_execution(audit_id: str, tool_name: str, cmd: list[str]) -> None:
    """Append execution record to audit JSONL log."""
    audit_dir = CASE_DIR / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    log_file = audit_dir / "execution.jsonl"

    entry = {
        "audit_id": audit_id,
        "tool": tool_name,
        "command": cmd,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence_mount": str(EVIDENCE_MOUNT),
    }

    try:
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        logger.warning("Failed to write audit log", audit_id=audit_id)
