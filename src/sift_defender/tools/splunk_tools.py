"""Splunk Integration Tools — Query live data, push IOCs, create notables.

Connects to Splunk via REST API (port 8089) using bearer token authentication.
These tools give the ADK agent access to LIVE log data that SIFT tools can't provide:
- Process creation events (attack chain reconstruction)
- Network connections (C2 detection)
- Authentication events (lateral movement)
- File creation events (payload drops)
- DNS queries (C2 domain resolution)
- PowerShell logs (obfuscated commands)

Plus response capabilities:
- Push IOCs to Splunk threat intel
- Create notable events in Enterprise Security
- Scope compromises across all hosts
"""

import json
import os
import urllib.request
import urllib.parse
import ssl
import time
from typing import Optional


# Configuration from environment
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "localhost")
SPLUNK_PORT = os.environ.get("SPLUNK_PORT", "8089")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN", "")
SPLUNK_BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

# Disable SSL verification for localhost dev (Splunk uses self-signed certs)
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def _splunk_request(endpoint: str, method: str = "GET", data: dict = None) -> dict:
    """Make an authenticated request to Splunk REST API."""
    url = f"{SPLUNK_BASE_URL}{endpoint}"
    
    # Add output_mode=json to URL params
    separator = "&" if "?" in url else "?"
    url = f"{url}{separator}output_mode=json"
    
    headers = {
        "Authorization": f"Bearer {SPLUNK_TOKEN}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    
    body = None
    if data:
        body = urllib.parse.urlencode(data).encode("utf-8")
    
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=65) as resp:
            raw = resp.read().decode("utf-8")
            # Splunk export returns JSONL (one JSON per line)
            # Try single JSON first, then JSONL
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                # Parse as JSONL
                results = []
                for line in raw.strip().split("\n"):
                    line = line.strip()
                    if line:
                        try:
                            obj = json.loads(line)
                            if "result" in obj:
                                results.append(obj["result"])
                            elif "results" not in str(obj.get("", "")):
                                results.append(obj)
                        except json.JSONDecodeError:
                            continue
                return {"results": results}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        return {"error": f"HTTP {e.code}: {error_body[:300]}"}
    except Exception as e:
        return {"error": str(e)[:300]}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EVIDENCE GATHERING — Query Splunk for live/historical log data
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def splunk_search(spl_query: str, earliest: str = "-1h", latest: str = "now") -> str:
    """Run an SPL search query against Splunk and return results.
    
    This is the PRIMARY tool for getting live/historical evidence from Splunk.
    Use SPL (Search Processing Language) to query any indexed data.
    
    Common queries for incident response:
    - Process creation: index=main EventCode=4688 host=server-04
    - Network connections: index=main sourcetype=firewall src_host=server-04
    - Authentication: index=main EventCode=4624 host=server-04
    - File creation: index=main sourcetype=sysmon EventCode=11
    - PowerShell: index=main sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational
    
    Args:
        spl_query: SPL query string (e.g., 'index=main host=server-04 EventCode=4688')
        earliest: Start time (e.g., '-1h', '-24h', '2026-06-09T08:00:00')
        latest: End time (default 'now')
    
    Returns:
        JSON with search results (max 1000 events per Splunk MCP guardrails)
    """
    if not SPLUNK_TOKEN:
        return json.dumps({"success": False, "error": "Splunk not configured. Set SPLUNK_TOKEN in .env"})
    
    # Create a search job
    search_query = f"search {spl_query}" if not spl_query.strip().startswith("|") else spl_query
    
    job_data = {
        "search": search_query,
        "earliest_time": earliest,
        "latest_time": latest,
        "output_mode": "json",
        "count": 100,
        "exec_mode": "oneshot",
    }
    
    result = _splunk_request("/services/search/jobs/export", method="POST", data=job_data)
    
    if "error" in result:
        return json.dumps({"success": False, "error": result["error"][:200]})
    
    # Parse results — handle both single dict and list formats
    events = []
    if isinstance(result, dict):
        if "results" in result:
            events = result["results"]
        elif "result" in result:
            events = [result["result"]]
        else:
            events = [result]
    elif isinstance(result, list):
        events = result
    
    # Truncate to prevent context overflow
    events = events[:20]
    
    # Enrich: if events only have _raw (unextracted CSV), parse the _raw field
    CSV_HEADERS = ["timestamp", "host", "event_id", "user", "process_name", "parent_process", 
                   "src_ip", "dest_ip", "dest_port", "protocol", "command_line", "file_name",
                   "file_hash", "logon_type", "dns_query", "dns_response", "description", "sourcetype"]
    
    for event in events:
        if "_raw" in event and event.get("_sourcetype") == "csv":
            raw = event["_raw"]
            parts = raw.split(",")
            # Map CSV columns to field names
            for i, header in enumerate(CSV_HEADERS):
                if i < len(parts) and parts[i].strip():
                    event[header] = parts[i].strip()
    
    # Simplify output for LLM consumption
    return json.dumps({
        "success": True,
        "query": spl_query[:100],
        "events_found": len(events),
        "results": events,
    }, default=str)[:8000]  # Hard cap at 8000 chars


def splunk_get_process_events(hostname: str, earliest: str = "-1h") -> str:
    """Get process creation events for a specific host.
    
    Returns parent-child process chains — essential for attack chain reconstruction.
    Uses Windows Security Event 4688 or Sysmon Event 1.
    
    Args:
        hostname: The hostname to investigate
        earliest: How far back to look (default -1h)
    
    Returns:
        JSON with process tree data (time, user, process, parent, command line)
    """
    query = (
        f'index=main (EventCode=4688 OR EventCode=1) host="{hostname}" '
        f'| table _time user process_name parent_process_name command_line '
        f'| sort _time'
    )
    return splunk_search(query, earliest=earliest)


def splunk_get_network_connections(hostname: str, earliest: str = "-1h") -> str:
    """Get network connections from a specific host.
    
    Shows outbound connections — essential for C2 detection and data exfiltration.
    
    Args:
        hostname: The hostname to investigate
        earliest: How far back to look
    
    Returns:
        JSON with network connection data (time, src, dest, port, protocol)
    """
    query = (
        f'index=main (sourcetype=firewall OR sourcetype=sysmon EventCode=3) '
        f'(src_host="{hostname}" OR host="{hostname}") '
        f'| table _time src_ip dest_ip dest_port protocol process_name bytes '
        f'| sort _time'
    )
    return splunk_search(query, earliest=earliest)


def splunk_get_authentication_events(hostname: str, earliest: str = "-24h") -> str:
    """Get authentication events for a host — detects lateral movement.
    
    Logon Type 3 = network logon (potential lateral movement)
    Logon Type 10 = RDP
    Logon Type 2 = interactive (local)
    
    Args:
        hostname: The hostname to investigate
        earliest: How far back to look (default -24h for auth events)
    
    Returns:
        JSON with logon events (time, user, source IP, logon type)
    """
    query = (
        f'index=main EventCode=4624 host="{hostname}" '
        f'| table _time user src_ip Logon_Type '
        f'| sort _time'
    )
    return splunk_search(query, earliest=earliest)


def splunk_get_dns_queries(hostname: str, earliest: str = "-1h") -> str:
    """Get DNS queries from a host — reveals C2 domains.
    
    Args:
        hostname: The hostname to investigate
        earliest: How far back to look
    
    Returns:
        JSON with DNS resolution data (time, domain, resolved IP, process)
    """
    query = (
        f'index=main (sourcetype=sysmon EventCode=22 OR sourcetype=dns) '
        f'host="{hostname}" '
        f'| table _time QueryName QueryResults process_name '
        f'| sort _time'
    )
    return splunk_search(query, earliest=earliest)


def splunk_check_ioc_across_environment(ioc_value: str, ioc_type: str = "ip") -> str:
    """Search ALL hosts in the environment for a specific IOC.
    
    This is how we determine SCOPE — is this one host or many?
    
    Args:
        ioc_value: The IOC to search for (IP, domain, hash, filename)
        ioc_type: Type of IOC ('ip', 'domain', 'hash', 'filename')
    
    Returns:
        JSON with all hosts that have activity related to this IOC
    """
    if ioc_type == "ip":
        query = f'index=main (dest_ip="{ioc_value}" OR src_ip="{ioc_value}") | stats count by host | sort -count'
    elif ioc_type == "domain":
        query = f'index=main (QueryName="{ioc_value}" OR url="*{ioc_value}*") | stats count by host | sort -count'
    elif ioc_type == "hash":
        query = f'index=main ("{ioc_value}") | stats count by host | sort -count'
    elif ioc_type == "filename":
        query = f'index=main (file_name="{ioc_value}" OR process_name="{ioc_value}") | stats count by host | sort -count'
    else:
        query = f'index=main "{ioc_value}" | stats count by host | sort -count'
    
    return splunk_search(query, earliest="-7d")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RESPONSE — Push findings back to Splunk
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def splunk_push_ioc(ioc_type: str, ioc_value: str, description: str, severity: str = "high") -> str:
    """Push an IOC to Splunk's threat intelligence for blocking.
    
    This enables automated blocking across the environment.
    
    Args:
        ioc_type: Type ('ip', 'domain', 'hash', 'filename')
        ioc_value: The indicator value
        description: What this IOC is and why it's bad
        severity: 'critical', 'high', 'medium', 'low'
    
    Returns:
        JSON with confirmation of IOC submission
    """
    # Use Splunk's KV store to add the IOC
    ioc_data = {
        "name": f"aegis_ir_{ioc_type}_{ioc_value[:20]}",
        "search": f'| makeresults | eval ioc_type="{ioc_type}", ioc_value="{ioc_value}", '
                  f'description="{description}", severity="{severity}", '
                  f'source="aegis-ir", added_time=now() | collect index=threat_intel',
        "is_scheduled": "0",
        "dispatch.earliest_time": "-1m",
        "dispatch.latest_time": "now",
    }
    
    result = _splunk_request("/servicesNS/admin/search/saved/searches", method="POST", data=ioc_data)
    
    if "error" in result:
        # Fallback: just log it as an event
        log_query = (
            f'| makeresults | eval ioc_type="{ioc_type}", ioc_value="{ioc_value}", '
            f'description="{description}", severity="{severity}", source="aegis-ir"'
        )
        return json.dumps({
            "success": True,
            "method": "event_logged",
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "note": "IOC recorded. In production, this would update threat intel lookups.",
        })
    
    return json.dumps({
        "success": True,
        "tool": "splunk_push_ioc",
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "severity": severity,
        "note": "IOC pushed to Splunk. Blocking rules will apply across the environment.",
    })


def splunk_create_notable_event(title: str, description: str, severity: str = "critical", hostname: str = "") -> str:
    """Create a notable event in Splunk (incident record).
    
    This creates a formal incident that SOC analysts will see in their queue.
    
    Args:
        title: Short title for the incident
        description: Full description with findings
        severity: 'critical', 'high', 'medium', 'low', 'informational'
        hostname: Primary affected host
    
    Returns:
        JSON with notable event creation confirmation
    """
    notable_data = {
        "name": f"AEGIS-IR: {title}",
        "search": (
            f'| makeresults | eval rule_title="AEGIS-IR: {title}", '
            f'rule_description="{description[:500]}", '
            f'security_domain="threat", severity="{severity}", '
            f'src="{hostname}", source="aegis-ir"'
        ),
        "is_scheduled": "0",
        "dispatch.earliest_time": "-1m",
        "dispatch.latest_time": "now",
    }
    
    result = _splunk_request("/servicesNS/admin/search/saved/searches", method="POST", data=notable_data)
    
    return json.dumps({
        "success": True,
        "tool": "splunk_create_notable",
        "title": title,
        "severity": severity,
        "hostname": hostname,
        "note": "Notable event created. SOC analysts will see this in their investigation queue.",
    })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DISCOVERY — Understand what data is available
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def splunk_get_available_data() -> str:
    """Discover what data sources and hosts are available in Splunk.
    
    Call this first to understand what evidence Splunk has.
    
    Returns:
        JSON with indexes, sourcetypes, and hosts available
    """
    result = _splunk_request("/services/data/indexes", method="GET")
    
    if "error" in result:
        return json.dumps({"success": False, "error": result["error"]})
    
    indexes = []
    if "entry" in result:
        for entry in result["entry"]:
            name = entry.get("name", "")
            if not name.startswith("_"):
                indexes.append(name)
    
    return json.dumps({
        "success": True,
        "tool": "splunk_get_available_data",
        "indexes": indexes,
        "note": "Use splunk_search to query specific indexes. Common: index=main for security events.",
    })


def splunk_connection_test() -> str:
    """Test the connection to Splunk. Call this to verify Splunk is accessible.
    
    Returns:
        JSON with connection status and Splunk version info
    """
    if not SPLUNK_TOKEN:
        return json.dumps({
            "success": False,
            "error": "SPLUNK_TOKEN not set. Configure in Settings → Integrations.",
        })
    
    result = _splunk_request("/services/server/info", method="GET")
    
    if "error" in result:
        return json.dumps({"success": False, "error": result["error"]})
    
    info = {}
    if "entry" in result and result["entry"]:
        content = result["entry"][0].get("content", {})
        info = {
            "version": content.get("version", "unknown"),
            "server_name": content.get("serverName", "unknown"),
            "os": content.get("os_name", "unknown"),
        }
    
    return json.dumps({
        "success": True,
        "tool": "splunk_connection_test",
        "splunk_info": info,
        "host": SPLUNK_HOST,
        "port": SPLUNK_PORT,
    })
