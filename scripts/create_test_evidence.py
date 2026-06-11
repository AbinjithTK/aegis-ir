"""Create synthetic forensic test evidence for development.

This creates a small NTFS disk image with planted artifacts that simulate
a phishing → macro → PowerShell → persistence attack chain.

The image can be analyzed by real SIFT tools (fls, icat, mmls, etc.)
"""

import os
import subprocess
import sys
from pathlib import Path


EVIDENCE_DIR = Path("/mnt/evidence")
IMAGE_PATH = Path("/tmp/test_evidence.raw")
IMAGE_SIZE_MB = 100  # Small image for testing


def create_raw_image():
    """Create a raw disk image with NTFS filesystem."""
    print("[*] Creating raw disk image...")
    
    # Create empty file
    subprocess.run(
        ["dd", "if=/dev/zero", f"of={IMAGE_PATH}", "bs=1M", f"count={IMAGE_SIZE_MB}"],
        check=True, capture_output=True
    )
    
    # Create NTFS filesystem
    subprocess.run(
        ["mkfs.ntfs", "-F", "-L", "EVIDENCE", str(IMAGE_PATH)],
        check=True, capture_output=True
    )
    print(f"  ✓ Created {IMAGE_SIZE_MB}MB NTFS image at {IMAGE_PATH}")


def mount_and_plant_evidence():
    """Mount the image and plant forensic artifacts."""
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    
    # Mount read-write temporarily to plant evidence
    subprocess.run(
        ["mount", "-o", "loop", str(IMAGE_PATH), str(EVIDENCE_DIR)],
        check=True, capture_output=True
    )
    print("  ✓ Mounted image")
    
    try:
        # Create Windows-like directory structure
        dirs = [
            EVIDENCE_DIR / "Windows" / "System32" / "config",
            EVIDENCE_DIR / "Windows" / "System32" / "Tasks",
            EVIDENCE_DIR / "Windows" / "System32" / "winevt" / "Logs",
            EVIDENCE_DIR / "Windows" / "Prefetch",
            EVIDENCE_DIR / "Windows" / "appcompat" / "Programs",
            EVIDENCE_DIR / "Users" / "m.chen" / "Downloads",
            EVIDENCE_DIR / "Users" / "m.chen" / "AppData" / "Local" / "Temp",
            EVIDENCE_DIR / "ProgramData",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
        
        # Plant suspicious files (the attack chain)
        
        # 1. Malicious document (initial access)
        doc_path = EVIDENCE_DIR / "Users" / "m.chen" / "Downloads" / "invoice-document-share.docm"
        doc_path.write_text("PK\x03\x04 [simulated macro-enabled document]")
        
        # 2. Dropped binary (stage 2)
        malware_path = EVIDENCE_DIR / "Users" / "m.chen" / "AppData" / "Local" / "Temp" / "update.dat"
        malware_path.write_bytes(b"\x4d\x5a" + b"\x00" * 100)  # MZ header stub
        
        # 3. Persistence binary
        svc_path = EVIDENCE_DIR / "ProgramData" / "svc_update.exe"
        svc_path.write_bytes(b"\x4d\x5a" + b"\x00" * 200)  # MZ header stub
        
        # 4. Scheduled task (persistence)
        task_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-09-15T08:07:28</Date>
    <Author>SYSTEM</Author>
    <Description>Windows Update Service</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>C:\\ProgramData\\svc_update.exe</Command>
    </Exec>
  </Actions>
</Task>"""
        task_path = EVIDENCE_DIR / "Windows" / "System32" / "Tasks" / "WindowsUpdate"
        task_path.write_text(task_xml)
        
        # 5. Fake Prefetch files (execution evidence)
        prefetch_dir = EVIDENCE_DIR / "Windows" / "Prefetch"
        (prefetch_dir / "POWERSHELL.EXE-A1B2C3D4.pf").write_bytes(b"\x00" * 50)
        (prefetch_dir / "WINWORD.EXE-E5F6A7B8.pf").write_bytes(b"\x00" * 50)
        (prefetch_dir / "OUTLOOK.EXE-C9D0E1F2.pf").write_bytes(b"\x00" * 50)
        (prefetch_dir / "RUNDLL32.EXE-A3B4C5D6.pf").write_bytes(b"\x00" * 50)
        # Notably: NO prefetch for svc_update.exe (triggers self-correction!)
        
        # 6. Fake registry hives (placeholders)
        (EVIDENCE_DIR / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"regf" + b"\x00" * 100)
        (EVIDENCE_DIR / "Windows" / "System32" / "config" / "SOFTWARE").write_bytes(b"regf" + b"\x00" * 100)
        
        print("  ✓ Planted attack chain artifacts:")
        print("    - invoice-document-share.docm (initial access)")
        print("    - update.dat (stage 2 payload)")
        print("    - svc_update.exe (persistence binary)")
        print("    - WindowsUpdate task (persistence mechanism)")
        print("    - Prefetch files (execution evidence)")
        print("    - NOTE: No prefetch for svc_update.exe (triggers self-correction)")
        
    finally:
        # Unmount
        subprocess.run(["umount", str(EVIDENCE_DIR)], capture_output=True)
    
    # Remount as read-only (like real evidence)
    subprocess.run(
        ["mount", "-o", "ro,loop,noexec,nosuid,nodev", str(IMAGE_PATH), str(EVIDENCE_DIR)],
        check=True, capture_output=True
    )
    print("  ✓ Remounted read-only at /mnt/evidence")


def verify_tools():
    """Verify SIFT tools can read the evidence."""
    print("\n[*] Verifying SIFT tools against evidence...")
    
    # Test fls
    result = subprocess.run(
        ["fls", "-r", str(EVIDENCE_DIR)],
        capture_output=True, text=True, timeout=10
    )
    file_count = len(result.stdout.strip().split("\n")) if result.stdout else 0
    print(f"  ✓ fls found {file_count} entries")
    
    # Show key files
    for line in result.stdout.split("\n"):
        if any(x in line for x in ["svc_update", "invoice", "update.dat", "WindowsUpdate"]):
            print(f"    {line.strip()}")


def main():
    if os.geteuid() != 0:
        print("ERROR: Must run as root (need mount permissions)")
        sys.exit(1)
    
    print("=" * 50)
    print("Creating Test Evidence")
    print("=" * 50)
    
    # Check for ntfs tools
    try:
        subprocess.run(["which", "mkfs.ntfs"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Installing ntfs-3g...")
        subprocess.run(["apt-get", "install", "-y", "ntfs-3g"], check=True, capture_output=True)
    
    create_raw_image()
    mount_and_plant_evidence()
    verify_tools()
    
    print("\n" + "=" * 50)
    print("Evidence ready at /mnt/evidence")
    print("Run the agent: python -m sift_defender.main 'Investigate /mnt/evidence'")
    print("=" * 50)


if __name__ == "__main__":
    main()
