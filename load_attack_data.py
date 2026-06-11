"""Load ransomware attack scenario into Splunk for demo."""
import csv
import json
import os
import time
import urllib3
import requests

urllib3.disable_warnings()

SPLUNK_HOST = "https://localhost:8089"
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN", "")

headers = {"Authorization": f"Bearer {SPLUNK_TOKEN}"}

# Verify connection
r = requests.get(f"{SPLUNK_HOST}/services/server/info", headers=headers, verify=False, timeout=5)
print(f"Splunk connection: {r.status_code}")

# Load attack events
with open("sample_data/ransomware_attack.csv", "r") as f:
    reader = csv.DictReader(f)
    events = list(reader)

print(f"Loading {len(events)} ransomware attack events into Splunk...")

# Push events one by one via Splunk REST API
for i, event in enumerate(events):
    # Format as raw event for Splunk
    event_text = json.dumps(event)
    
    data = {
        "index": "main",
        "sourcetype": event.get("sourcetype", "csv"),
        "host": event.get("host", "unknown"),
        "event": event_text,
    }
    
    try:
        r = requests.post(
            f"{SPLUNK_HOST}/services/receivers/simple",
            headers={**headers, "Content-Type": "application/json"},
            params={"index": "main", "sourcetype": "csv", "host": event.get("host", "unknown")},
            data=event_text,
            verify=False,
            timeout=5,
        )
        if r.status_code not in (200, 201):
            print(f"  Event {i}: {r.status_code} - {r.text[:100]}")
    except Exception as e:
        print(f"  Event {i} error: {e}")

print(f"\n✅ Loaded {len(events)} events into Splunk index=main")
print("Attack scenario: LockBit ransomware via brute-force → credential dump → lateral movement → encryption")
print("\nATTACK TIMELINE:")
print("  02:00 - Brute force login on dc-01 from 185.220.101.45")
print("  02:01 - Reconnaissance (whoami, net user, net group)")  
print("  02:01 - PowerShell downloads payload from C2")
print("  02:02 - Mimikatz dropped and executed (credential dump)")
print("  02:03 - PsExec lateral movement to file-server-01")
print("  02:03 - Shadow copies deleted, backups wiped, recovery disabled")
print("  02:04 - LockBit3 ransomware executed, files encrypted")
print("  02:04 - Data exfiltrated to C2 (500MB)")
print("  02:05 - Backdoor user created in Domain Admins")
print("\nNow start an investigation in AEGIS-IR to detect this!")
