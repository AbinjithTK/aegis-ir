"""Evidence management tools — mounting, partition listing, hash verification."""

import json
import os
from pathlib import Path

from sift_defender.tools.base import (
    EVIDENCE_MOUNT,
    format_tool_response,
    generate_audit_id,
    run_forensic_tool,
    validate_evidence_path,
)


def get_evidence_info(evidence_path: str) -> str:
    """Get metadata about the evidence (format, size, OS, filesystem).
    
    Args:
        evidence_path: Path to evidence image or mount point.
    
    Returns: JSON with evidence metadata.
    """
    audit_id = generate_audit_id("evidence_info")
    
    path = Path(evidence_path)
    
    # If it's already mounted, inspect the mount
    if path.is_dir():
        # Check for Windows filesystem indicators
        has_windows = (path / "Windows").exists()
        has_users = (path / "Users").exists()
        has_etc = (path / "etc").exists()
        
        os_type = "Unknown"
        if has_windows:
            os_type = "Windows"
            # Try to determine version from registry or build info
            build_file = path / "Windows" / "System32" / "ntoskrnl.exe"
            if build_file.exists():
                os_type = "Windows (version TBD from registry)"
        elif has_etc:
            os_type = "Linux"
        
        info = {
            "path": str(path),
            "type": "mounted_filesystem",
            "os_detected": os_type,
            "has_windows_dir": has_windows,
            "has_users_dir": has_users,
            "has_etc_dir": has_etc,
        }
        
        return format_tool_response(
            audit_id=audit_id,
            tool_name="get_evidence_info",
            data=info,
            suggested_next=[
                "list_partitions() if working with raw image",
                "quick_timeline() to see recent activity",
                "scan_autoruns() to check persistence",
            ],
        )
    
    # If it's an image file, get file info
    if path.is_file():
        stat = path.stat()
        suffix = path.suffix.lower()
        
        format_map = {
            ".e01": "Expert Witness (EnCase)",
            ".raw": "Raw dd image",
            ".dd": "Raw dd image",
            ".img": "Raw disk image",
            ".aff": "Advanced Forensic Format",
            ".vmdk": "VMware Virtual Disk",
            ".vhd": "Virtual Hard Disk",
            ".vhdx": "Virtual Hard Disk (extended)",
            ".qcow2": "QEMU Copy-on-Write",
            ".lime": "Linux Memory (LiME)",
            ".mem": "Memory dump",
            ".dmp": "Memory dump",
        }
        
        evidence_format = format_map.get(suffix, f"Unknown ({suffix})")
        
        info = {
            "path": str(path),
            "filename": path.name,
            "format": evidence_format,
            "size_bytes": stat.st_size,
            "size_human": _human_size(stat.st_size),
            "type": "memory_dump" if suffix in (".lime", ".mem", ".dmp") else "disk_image",
        }
        
        return format_tool_response(
            audit_id=audit_id,
            tool_name="get_evidence_info",
            data=info,
            suggested_next=[
                "mount_evidence() to mount the image read-only",
                "list_partitions() to see partition layout",
            ],
        )
    
    return json.dumps({
        "success": False,
        "audit_id": audit_id,
        "tool": "get_evidence_info",
        "error": f"Path does not exist: {evidence_path}",
        "error_type": "path_not_found",
    })


def list_partitions(image_path: str) -> str:
    """List partitions in a disk image using mmls (Sleuthkit).
    
    Args:
        image_path: Path to disk image file.
    
    Returns: JSON with partition table entries.
    """
    audit_id = generate_audit_id("list_partitions")
    
    result = run_forensic_tool(
        cmd=["mmls", image_path],
        tool_name="mmls",
        audit_id=audit_id,
    )
    
    if not result["success"]:
        return json.dumps(result)
    
    # Parse mmls output
    partitions = _parse_mmls_output(result["raw_output"])
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="list_partitions",
        data=partitions,
        caveats=[
            "Partition offsets are in sectors (typically 512 bytes each).",
            "Use the offset to mount specific partitions.",
        ],
        suggested_next=[
            "Mount the NTFS partition for Windows analysis",
            "Check for hidden/unallocated space between partitions",
        ],
    )


def _parse_mmls_output(raw: str) -> list[dict]:
    """Parse mmls output into structured partition entries."""
    partitions = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("DOS") or line.startswith("Units"):
            continue
        # mmls format: Slot  Start      End        Length     Description
        parts = line.split(None, 5)
        if len(parts) >= 5:
            try:
                partitions.append({
                    "slot": parts[0],
                    "start_sector": int(parts[1]),
                    "end_sector": int(parts[2]),
                    "length_sectors": int(parts[3]),
                    "description": parts[4] if len(parts) > 4 else "",
                })
            except (ValueError, IndexError):
                continue
    return partitions


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human-readable size."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"
