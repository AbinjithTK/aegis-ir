"""Correlation tools — cross-source verification and IOC extraction."""

import json
import re
from typing import Any

from sift_defender.tools.base import format_tool_response, generate_audit_id


def cross_reference_findings(disk_findings: str, memory_findings: str) -> str:
    """Cross-reference disk and memory findings for corroboration.
    
    Args:
        disk_findings: JSON string of disk analysis findings.
        memory_findings: JSON string of memory analysis findings.
    
    Returns: JSON with corroborated findings and discrepancies.
    """
    audit_id = generate_audit_id("cross_reference")
    
    # Parse inputs
    try:
        disk = json.loads(disk_findings) if isinstance(disk_findings, str) else disk_findings
        memory = json.loads(memory_findings) if isinstance(memory_findings, str) else memory_findings
    except json.JSONDecodeError:
        return json.dumps({
            "success": False, "audit_id": audit_id,
            "error": "Could not parse findings JSON",
        })
    
    # TODO: Implement real cross-referencing logic
    return format_tool_response(
        audit_id=audit_id,
        tool_name="cross_reference_findings",
        data={
            "corroborated": [],
            "disk_only": [],
            "memory_only": [],
            "contradictions": [],
        },
        caveats=[
            "Disk and memory may reflect different points in time.",
            "A process in memory but not on disk = possibly deleted.",
            "A binary on disk but not in memory = may have terminated.",
        ],
    )


def extract_iocs(findings: str) -> str:
    """Extract indicators of compromise from investigation findings.
    
    Extracts: IP addresses, domains, file hashes, filenames, registry keys.
    
    Args:
        findings: JSON string of investigation findings.
    
    Returns: JSON with extracted IOCs categorized by type.
    """
    audit_id = generate_audit_id("extract_iocs")
    
    text = findings if isinstance(findings, str) else json.dumps(findings)
    
    iocs = {
        "ip_addresses": list(set(re.findall(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
            text
        ))),
        "domains": list(set(re.findall(
            r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|xyz|top|io|cc)\b',
            text, re.IGNORECASE
        ))),
        "sha256_hashes": list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', text))),
        "md5_hashes": list(set(re.findall(r'\b[a-fA-F0-9]{32}\b', text))),
        "filenames": list(set(re.findall(
            r'\b[\w.-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr|com|pif|msi|docm|xlsm)\b',
            text, re.IGNORECASE
        ))),
    }
    
    # Filter out known-good IPs
    known_good = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
    iocs["ip_addresses"] = [ip for ip in iocs["ip_addresses"] if ip not in known_good]
    
    total_iocs = sum(len(v) for v in iocs.values())
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="extract_iocs",
        data=iocs,
        caveats=[
            "IOCs are extracted via pattern matching — may include false positives.",
            "Internal IPs (10.x, 172.16-31.x, 192.168.x) are included but may be benign.",
            "Validate IOCs against threat intelligence before blocking.",
        ],
        total_count=total_iocs,
    )


def map_mitre_attack(findings: str) -> str:
    """Map investigation findings to MITRE ATT&CK techniques.
    
    Args:
        findings: JSON string of investigation findings.
    
    Returns: JSON with MITRE ATT&CK mapping.
    """
    audit_id = generate_audit_id("mitre_mapping")
    
    # Pattern-based MITRE mapping
    mappings = []
    text = findings.lower() if isinstance(findings, str) else json.dumps(findings).lower()
    
    technique_patterns = {
        "T1566.001": ("Spearphishing Attachment", ["docm", "xlsm", "macro", "phishing", "email attachment"]),
        "T1059.001": ("PowerShell", ["powershell", "powershell.exe", "-enc", "-encodedcommand"]),
        "T1053.005": ("Scheduled Task", ["scheduled task", "schtasks", "task scheduler"]),
        "T1543.003": ("Windows Service", ["service install", "sc create", "new-service"]),
        "T1071.001": ("Web Protocols", ["http", "https", "c2", "beacon", "download"]),
        "T1105": ("Ingress Tool Transfer", ["download", "wget", "curl", "invoke-webrequest"]),
        "T1027": ("Obfuscated Files", ["encoded", "base64", "obfuscated", "-enc"]),
        "T1055": ("Process Injection", ["malfind", "inject", "hollowing"]),
        "T1078": ("Valid Accounts", ["logon type 3", "logon type 10", "lateral movement"]),
        "T1021.001": ("Remote Desktop", ["rdp", "mstsc", "logon type 10"]),
        "T1003": ("Credential Dumping", ["mimikatz", "lsass", "credential"]),
        "T1547.001": ("Registry Run Keys", ["run key", "autorun", "hkcu\\software\\microsoft\\windows\\currentversion\\run"]),
    }
    
    for technique_id, (name, keywords) in technique_patterns.items():
        for keyword in keywords:
            if keyword in text:
                mappings.append({
                    "technique_id": technique_id,
                    "technique_name": name,
                    "tactic": _get_tactic(technique_id),
                    "matched_keyword": keyword,
                })
                break
    
    return format_tool_response(
        audit_id=audit_id,
        tool_name="map_mitre_attack",
        data=mappings,
        caveats=[
            "MITRE mapping is based on keyword matching — may be imprecise.",
            "Confirm technique applicability based on full attack context.",
        ],
        total_count=len(mappings),
    )


def check_consistency(findings: str) -> str:
    """Check findings for internal consistency and contradictions.
    
    Rules checked:
    - Binary in Amcache + NO Prefetch = investigate scheduled tasks/services
    - Service install event + NO binary on disk = possible anti-forensics
    - Process in memory + NO disk artifact = deleted or fileless
    - Timestamps out of order in same attack chain = possible manipulation
    
    Args:
        findings: JSON string of all findings so far.
    
    Returns: JSON with consistency results and contradictions.
    """
    audit_id = generate_audit_id("check_consistency")
    
    # TODO: Implement rule-based consistency checking
    return format_tool_response(
        audit_id=audit_id,
        tool_name="check_consistency",
        data={
            "consistent": True,
            "contradictions": [],
            "warnings": [],
            "suggestions": [],
        },
    )


def detect_gaps(findings: str, tools_run: str) -> str:
    """Identify investigation gaps — what hasn't been checked.
    
    Args:
        findings: JSON string of all findings so far.
        tools_run: JSON list of tools already executed.
    
    Returns: JSON with identified gaps and recommended next steps.
    """
    audit_id = generate_audit_id("detect_gaps")
    
    # TODO: Implement gap detection based on findings vs tools run
    return format_tool_response(
        audit_id=audit_id,
        tool_name="detect_gaps",
        data={
            "gaps": [],
            "recommended_next_steps": [],
            "coverage_percent": 0,
        },
    )


def _get_tactic(technique_id: str) -> str:
    """Map technique ID to tactic."""
    tactic_map = {
        "T1566": "Initial Access",
        "T1059": "Execution",
        "T1053": "Persistence",
        "T1543": "Persistence",
        "T1547": "Persistence",
        "T1071": "Command and Control",
        "T1105": "Command and Control",
        "T1027": "Defense Evasion",
        "T1055": "Defense Evasion",
        "T1078": "Privilege Escalation",
        "T1021": "Lateral Movement",
        "T1003": "Credential Access",
    }
    prefix = technique_id.split(".")[0]
    return tactic_map.get(prefix, "Unknown")
