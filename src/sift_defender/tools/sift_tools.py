"""Real SIFT Tool Wrappers — Every function calls an actual forensic binary.

NO MOCKING. NO PYTHON FILE READS PRETENDING TO BE FORENSICS.
Every tool here runs a real binary via subprocess.run(shell=False).

Available tools on this SIFT installation:
- Sleuthkit: fls, icat, mmls, img_stat, tsk_recover, blkstat, mactime
- Volatility 3: /opt/volatility3/bin/vol
- RegRipper: /usr/bin/regripper  
- Event Logs: evtxexport
- Malware: clamscan, yara
- Carving: bulk_extractor, foremost
- Hashing: sha256sum, md5sum
- Strings: strings
- Mounting: ewfmount, affuse
"""

import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TOOL EXECUTION INFRASTRUCTURE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DENYLIST = {"rm", "dd", "mkfs", "fdisk", "shutdown", "reboot", "halt", "shred", "wipe"}
MAX_OUTPUT = 50000  # Max chars to return to LLM (prevent context overflow)

# Auto-detect: on Windows, route SIFT commands through WSL
IS_WINDOWS = platform.system() == "Windows"
SIFT_MODE = os.environ.get("SIFT_MODE", "local")  # "local" or "cloud"

# Binaries that are Linux-only forensic tools (need WSL on Windows)
LINUX_TOOLS = {
    "fls", "mmls", "icat", "img_stat", "mactime", "tsk_recover",
    "vol", "regripper", "evtxexport", "clamscan", "yara",
    "bulk_extractor", "foremost", "strings", "sha256sum", "md5sum",
    "ewfmount", "affuse", "mount", "find",
}


def _run(cmd: list[str], timeout: int = 120) -> dict:
    """Execute a command safely. Routes through WSL on Windows."""
    # Security: check denylist
    binary = Path(cmd[0]).name
    if binary in DENYLIST:
        return {"success": False, "error": f"BLOCKED: {binary} is on the denylist"}
    
    # On Windows, route Linux forensic tools through WSL
    if IS_WINDOWS and binary in LINUX_TOOLS:
        cmd = ["wsl"] + cmd
    
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=False
        )
        output = result.stdout
        # Truncate if too large
        if len(output) > MAX_OUTPUT:
            output = output[:MAX_OUTPUT] + f"\n\n[TRUNCATED: {len(result.stdout)} chars total, showing first {MAX_OUTPUT}]"
        
        return {
            "success": result.returncode == 0,
            "output": output,
            "stderr": result.stderr[:2000] if result.stderr else "",
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timeout after {timeout}s"}
    except FileNotFoundError:
        return {"success": False, "error": f"Binary not found: {cmd[0]}"}
    except Exception as e:
        return {"success": False, "error": str(e)[:500]}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SLEUTHKIT TOOLS (Filesystem forensics)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def sleuthkit_fls(image_or_mount: str, directory: str = "/", recursive: bool = True) -> str:
    """List files and directories using Sleuthkit's fls.
    
    fls lists file and directory names in a disk image or mounted filesystem.
    Use on raw/E01 images OR mounted paths.
    
    Args:
        image_or_mount: Path to disk image or mounted evidence directory
        directory: Directory to list (use inode number for images)
        recursive: Whether to recurse into subdirectories
    
    Returns:
        JSON with file listing including deleted files marked with '*'
    """
    cmd = ["fls"]
    if recursive:
        cmd.append("-r")
    cmd.extend(["-p", image_or_mount])
    
    result = _run(cmd, timeout=60)
    if not result["success"]:
        # Check if it's a directory (fls only works on raw images)
        # On Windows+WSL, we can't use Path.is_dir() for Linux paths
        error_msg = result.get("error", "") + result.get("stderr", "")
        is_directory = "is a directory" in error_msg or "not a regular file" in error_msg
        
        if is_directory or image_or_mount.startswith("/mnt/"):
            # Use 'find' to list files in the mounted directory
            find_result = _run(["find", image_or_mount, "-maxdepth", "4", "-type", "f"], timeout=30)
            if find_result["success"] and find_result["output"].strip():
                files = [f.strip() for f in find_result["output"].strip().split("\n") if f.strip()]
                return json.dumps({
                    "success": True,
                    "note": "Path is a mounted directory (not a raw disk image). Listing files directly.",
                    "tool": "find (directory listing)",
                    "entries_count": len(files),
                    "entries": files[:200],
                    "suggestion": "Use these file paths with extract_strings, compute_hash, or clamav_scan for analysis.",
                })
            else:
                return json.dumps({
                    "success": True,
                    "note": "Path is a mounted directory but no files found or 'find' not available.",
                    "tool": "find",
                    "entries_count": 0,
                    "entries": [],
                    "error_detail": find_result.get("error", ""),
                })
        return json.dumps(result)
    
    # Parse fls output into structured data
    entries = []
    for line in result["output"].split("\n"):
        if not line.strip():
            continue
        entries.append(line.strip())
    
    return json.dumps({
        "success": True,
        "tool": "fls (Sleuthkit)",
        "entries_count": len(entries),
        "entries": entries[:200],  # Limit for LLM context
        "note": "Files marked with '*' are deleted. Use icat to extract file content.",
    })


def sleuthkit_mmls(image_path: str) -> str:
    """Display partition layout of a disk image using mmls.
    
    Args:
        image_path: Path to disk image (raw, E01, etc.)
    
    Returns:
        JSON with partition table (offsets, sizes, types)
    """
    result = _run(["mmls", image_path])
    return json.dumps({
        "success": result["success"],
        "tool": "mmls (Sleuthkit)",
        "output": result.get("output", ""),
        "error": result.get("error", ""),
        "note": "Use partition offset with fls/icat for specific partition analysis",
    })


def sleuthkit_icat(image_path: str, inode: str, output_file: str = "") -> str:
    """Extract a file from a disk image by inode number using icat.
    
    Args:
        image_path: Path to disk image
        inode: Inode number of the file to extract
        output_file: Where to save (default: temp file, returns path)
    
    Returns:
        JSON with extraction result and output path
    """
    if not output_file:
        output_file = f"/tmp/extracted_{inode}"
    
    cmd = ["icat", image_path, inode]
    result = subprocess.run(cmd, capture_output=True, timeout=60, shell=False)
    
    if result.returncode == 0:
        Path(output_file).write_bytes(result.stdout)
        return json.dumps({
            "success": True,
            "tool": "icat (Sleuthkit)",
            "output_path": output_file,
            "size_bytes": len(result.stdout),
            "note": "File extracted. Use strings/sha256sum/yara for further analysis.",
        })
    return json.dumps({"success": False, "error": result.stderr.decode()[:500]})


def sleuthkit_img_stat(image_path: str) -> str:
    """Get image metadata (format, sector size) using img_stat.
    
    Args:
        image_path: Path to disk image
    
    Returns:
        JSON with image properties
    """
    result = _run(["img_stat", image_path])
    return json.dumps({
        "success": result["success"],
        "tool": "img_stat (Sleuthkit)",
        "output": result.get("output", ""),
    })


def sleuthkit_mactime(bodyfile_path: str, start_date: str = "", end_date: str = "") -> str:
    """Generate timeline from a bodyfile using mactime.
    
    Create the bodyfile first with: fls -r -m "/" image > bodyfile.txt
    Then use mactime to generate a human-readable timeline.
    
    Args:
        bodyfile_path: Path to bodyfile created by fls
        start_date: Start date filter (YYYY-MM-DD)
        end_date: End date filter (YYYY-MM-DD)
    
    Returns:
        JSON with timeline entries
    """
    cmd = ["mactime", "-b", bodyfile_path]
    if start_date:
        cmd.extend(["-d", start_date])
    
    result = _run(cmd, timeout=120)
    return json.dumps({
        "success": result["success"],
        "tool": "mactime (Sleuthkit)",
        "output": result.get("output", "")[:MAX_OUTPUT],
        "note": "Timeline shows file creation/modification/access times. Cross-reference with event logs.",
    })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# VOLATILITY 3 (Memory forensics)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VOL_BIN = "/opt/volatility3/bin/vol"


def volatility_run(memory_dump: str, plugin: str, extra_args: str = "") -> str:
    """Run any Volatility 3 plugin against a memory dump.
    
    Common plugins: windows.pslist, windows.pstree, windows.netscan,
    windows.malfind, windows.cmdline, windows.dlllist, windows.handles,
    windows.filescan, timeliner.Timeliner
    
    Args:
        memory_dump: Path to memory dump file (.lime, .raw, .dmp)
        plugin: Volatility plugin name (e.g., 'windows.pslist')
        extra_args: Additional arguments (e.g., '--pid 1234')
    
    Returns:
        JSON with plugin output
    """
    cmd = [VOL_BIN, "-f", memory_dump, plugin]
    if extra_args:
        cmd.extend(extra_args.split())
    
    result = _run(cmd, timeout=300)
    return json.dumps({
        "success": result["success"],
        "tool": f"volatility3 {plugin}",
        "output": result.get("output", ""),
        "error": result.get("error", ""),
        "caveat": _vol_caveat(plugin),
    })


def _vol_caveat(plugin: str) -> str:
    """Return forensic caveat for a Volatility plugin."""
    caveats = {
        "windows.pslist": "Shows processes at time of capture. Hidden (DKOM) processes won't appear — use windows.psscan.",
        "windows.netscan": "Network connections at time of capture. Closed connections may show as residual.",
        "windows.malfind": "Detects suspicious memory regions. HIGH false positive rate (browsers, .NET). Check process context.",
        "windows.cmdline": "Command lines at time of capture. Encoded commands (-enc) are highly suspicious.",
        "windows.pstree": "Parent-child relationships. Unusual combos (Word→PowerShell) indicate compromise.",
    }
    return caveats.get(plugin, "Memory is volatile — reflects state at time of capture only.")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# REGRIPPER (Windows Registry analysis)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def regripper_run(hive_path: str, plugin: str = "") -> str:
    """Analyze a Windows registry hive using RegRipper.
    
    Common hives: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat
    Common plugins: services, soft_run, userassist, amcache, appcompatcache,
                    networklist, usbdevices, recentdocs, typedurls
    
    Args:
        hive_path: Path to registry hive file
        plugin: Specific plugin to run (empty = run all relevant plugins)
    
    Returns:
        JSON with registry analysis output
    """
    cmd = ["/usr/bin/regripper", "-r", hive_path]
    if plugin:
        cmd.extend(["-p", plugin])
    
    result = _run(cmd, timeout=60)
    
    caveat = ""
    if "amcache" in (plugin or "").lower():
        caveat = "⚠️ Amcache proves PRESENCE only, NOT execution."
    elif "appcompat" in (plugin or "").lower():
        caveat = "⚠️ Shimcache/AppCompatCache proves PRESENCE only, NOT execution."
    elif "services" in (plugin or "").lower():
        caveat = "Services list shows what IS configured, not what has recently RUN."
    
    return json.dumps({
        "success": result["success"],
        "tool": f"regripper {plugin or '(all)'}",
        "output": result.get("output", ""),
        "error": result.get("error", ""),
        "caveat": caveat,
    })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EVENT LOGS (Windows Event Log parsing)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def evtx_export(evtx_path: str) -> str:
    """Export Windows Event Log (.evtx) to text using evtxexport.
    
    Key event IDs to look for:
    - Security 4688: Process creation (with command line)
    - Security 4624: Logon (Type 3=network, Type 10=RDP)
    - Security 1102: Log cleared (anti-forensics!)
    - System 7045: Service installed
    - TaskScheduler 106: Task created
    
    Args:
        evtx_path: Path to .evtx file
    
    Returns:
        JSON with exported event log entries
    """
    result = _run(["evtxexport", evtx_path], timeout=120)
    return json.dumps({
        "success": result["success"],
        "tool": "evtxexport (libevtx)",
        "output": result.get("output", ""),
        "error": result.get("error", ""),
        "caveat": "Event logs CAN be cleared. Check Event 1102 (Security) or 104 (System) for evidence of clearing.",
    })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MALWARE ANALYSIS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def clamav_scan(path: str) -> str:
    """Scan file or directory with ClamAV antivirus.
    
    Args:
        path: File or directory to scan
    
    Returns:
        JSON with scan results (detections)
    """
    result = _run(["clamscan", "--no-summary", "-r", path], timeout=300)
    return json.dumps({
        "success": True,  # clamscan returns 1 if virus found
        "tool": "clamscan (ClamAV)",
        "output": result.get("output", ""),
        "detections": "FOUND" in result.get("output", ""),
    })


def yara_scan(rules_path: str, target_path: str) -> str:
    """Scan file with YARA rules.
    
    Args:
        rules_path: Path to YARA rules file
        target_path: File to scan
    
    Returns:
        JSON with YARA matches
    """
    result = _run(["yara", rules_path, target_path], timeout=60)
    return json.dumps({
        "success": result["success"],
        "tool": "yara",
        "output": result.get("output", ""),
        "matches_found": len(result.get("output", "").strip().split("\n")) if result.get("output", "").strip() else 0,
    })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STRING ANALYSIS & HASHING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def extract_strings(file_path: str, min_length: int = 6, encoding: str = "all") -> str:
    """Extract printable strings from a binary file.
    
    Useful for finding: URLs, IP addresses, file paths, commands, C2 domains.
    
    Args:
        file_path: Path to binary file
        min_length: Minimum string length (default 6)
        encoding: 'ascii', 'unicode', or 'all'
    
    Returns:
        JSON with extracted strings
    """
    cmd = ["strings", f"-n{min_length}"]
    if encoding == "unicode":
        cmd.append("-el")  # Little-endian 16-bit
    cmd.append(file_path)
    
    result = _run(cmd, timeout=60)
    
    # Extract interesting strings (IPs, URLs, paths)
    strings_list = result.get("output", "").split("\n")
    interesting = []
    for s in strings_list:
        s = s.strip()
        if any(indicator in s.lower() for indicator in [
            "http", "https", ".exe", ".dll", ".ps1", "cmd", "powershell",
            "\\\\", "c:\\", "/tmp/", "password", "admin", "token",
        ]):
            interesting.append(s)
    
    return json.dumps({
        "success": result["success"],
        "tool": "strings",
        "total_strings": len(strings_list),
        "interesting_strings": interesting[:100],
        "all_output": result.get("output", "")[:MAX_OUTPUT] if len(strings_list) < 500 else "[TOO LARGE - showing interesting only]",
    })


def compute_hash(file_path: str) -> str:
    """Compute SHA-256 and MD5 hashes of a file.
    
    Use for IOC matching against threat intelligence.
    
    Args:
        file_path: Path to file
    
    Returns:
        JSON with hashes
    """
    sha256_result = _run(["sha256sum", file_path])
    md5_result = _run(["md5sum", file_path])
    
    sha256 = sha256_result.get("output", "").split()[0] if sha256_result["success"] else "ERROR"
    md5 = md5_result.get("output", "").split()[0] if md5_result["success"] else "ERROR"
    
    return json.dumps({
        "success": True,
        "tool": "sha256sum + md5sum",
        "file": file_path,
        "sha256": sha256,
        "md5": md5,
        "note": "Compare against VirusTotal, MISP, or threat intel feeds.",
    })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BULK EXTRACTOR (Automated artifact extraction)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def bulk_extractor_run(image_path: str, output_dir: str = "/tmp/be_output") -> str:
    """Run bulk_extractor to automatically extract artifacts.
    
    Extracts: email addresses, URLs, credit card numbers, phone numbers,
    GPS coordinates, network packets, and more.
    
    Args:
        image_path: Path to disk image or file
        output_dir: Directory for output (default /tmp/be_output)
    
    Returns:
        JSON with summary of extracted artifacts
    """
    os.makedirs(output_dir, exist_ok=True)
    result = _run(["bulk_extractor", "-o", output_dir, image_path], timeout=600)
    
    # Summarize output files
    summary = {}
    output_path = Path(output_dir)
    if output_path.exists():
        for f in output_path.iterdir():
            if f.is_file() and f.stat().st_size > 0:
                line_count = sum(1 for _ in open(f, errors="ignore"))
                summary[f.name] = {"lines": line_count, "size": f.stat().st_size}
    
    return json.dumps({
        "success": result["success"],
        "tool": "bulk_extractor",
        "output_dir": output_dir,
        "artifacts_found": summary,
        "error": result.get("error", ""),
    })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EVIDENCE MOUNTING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def mount_evidence_image(image_path: str, mount_point: str = "/mnt/evidence", image_type: str = "auto") -> str:
    """Mount a forensic image read-only.
    
    Supports: raw/dd, E01 (via ewfmount), AFF (via affuse)
    ALWAYS mounts read-only with noexec,nosuid,nodev.
    
    Args:
        image_path: Path to evidence image
        mount_point: Where to mount
        image_type: 'raw', 'e01', 'aff', or 'auto' (detect from extension)
    
    Returns:
        JSON with mount result
    """
    ext = Path(image_path).suffix.lower()
    
    if image_type == "auto":
        if ext in (".e01", ".ex01"):
            image_type = "e01"
        elif ext in (".aff",):
            image_type = "aff"
        else:
            image_type = "raw"
    
    os.makedirs(mount_point, exist_ok=True)
    
    if image_type == "e01":
        # E01 → ewfmount → raw → loop mount
        ewf_mount = "/mnt/ewf_raw"
        os.makedirs(ewf_mount, exist_ok=True)
        result = _run(["ewfmount", image_path, ewf_mount])
        if not result["success"]:
            return json.dumps(result)
        # Now mount the raw image from ewfmount
        raw_path = f"{ewf_mount}/ewf1"
        result = _run(["mount", "-o", "ro,loop,noexec,nosuid,nodev", raw_path, mount_point])
    elif image_type == "aff":
        # AFF → affuse → raw → loop mount
        aff_mount = "/mnt/aff_raw"
        os.makedirs(aff_mount, exist_ok=True)
        result = _run(["affuse", image_path, aff_mount])
        if not result["success"]:
            return json.dumps(result)
        raw_path = f"{aff_mount}/{Path(image_path).stem}.raw"
        result = _run(["mount", "-o", "ro,loop,noexec,nosuid,nodev", raw_path, mount_point])
    else:
        # Raw image — direct loop mount
        result = _run(["mount", "-o", "ro,loop,noexec,nosuid,nodev", image_path, mount_point])
    
    return json.dumps({
        "success": result["success"],
        "tool": f"mount ({image_type})",
        "mount_point": mount_point,
        "read_only": True,
        "options": "ro,loop,noexec,nosuid,nodev",
        "error": result.get("error", ""),
    })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FILE CARVING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def foremost_carve(image_path: str, output_dir: str = "/tmp/carved") -> str:
    """Carve files from a disk image using foremost.
    
    Recovers deleted files based on file headers/footers.
    
    Args:
        image_path: Path to disk image
        output_dir: Where to put carved files
    
    Returns:
        JSON with carving results
    """
    os.makedirs(output_dir, exist_ok=True)
    result = _run(["foremost", "-o", output_dir, "-i", image_path], timeout=600)
    
    # Count carved files
    carved = {}
    output_path = Path(output_dir)
    for d in output_path.iterdir():
        if d.is_dir():
            files = list(d.iterdir())
            if files:
                carved[d.name] = len(files)
    
    return json.dumps({
        "success": result["success"],
        "tool": "foremost",
        "output_dir": output_dir,
        "carved_files": carved,
    })
