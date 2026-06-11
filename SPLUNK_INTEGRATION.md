# AEGIS-IR — Splunk Integration Plan

## Approach: Official Splunk MCP Server

We use the **official Splunk MCP Server app** (from Splunkbase) which provides
standardized MCP tools our ADK agent can call directly.

## Setup Required

1. Install Splunk Enterprise (localhost:8000 / API on :8089)
2. Install Splunk MCP Server app from Splunkbase (app ID: 7931)
3. Enable token authentication
4. Create API token for AEGIS-IR
5. (Optional) Install Splunk AI Assistant for SPL (enables saia_* tools)

## Official MCP Server Tools We Use

### Core Tools (splunk_ prefix)
| Tool | Purpose in AEGIS-IR |
|------|---------------------|
| `splunk_run_query` | Query process events, network logs, auth events, file changes |
| `splunk_get_indexes` | Discover what data sources are available |
| `splunk_get_metadata` | Find hosts, sources, sourcetypes in environment |
| `splunk_get_kv_store_collections` | Store/retrieve IOCs for blocking |
| `splunk_get_knowledge_objects` | Get existing detection rules + saved searches |

### AI Assistant Tools (saia_ prefix) — Optional but powerful
| Tool | Purpose in AEGIS-IR |
|------|---------------------|
| `saia_generate_spl` | Agent describes what it needs in English → gets correct SPL |
| `saia_explain_spl` | Explain complex queries to the user in the report |
| `saia_optimize_spl` | Make queries faster for large datasets |

## Evidence Queries Our Agent Runs

```spl
# Process creation (attack chain reconstruction)
index=main sourcetype=WinEventLog:Security EventCode=4688 host={hostname} 
| table _time user process_name parent_process_name command_line

# Network connections (C2 detection)
index=main sourcetype=firewall src_host={hostname}
| table _time src_ip dest_ip dest_port protocol bytes

# Authentication (lateral movement)
index=main sourcetype=WinEventLog:Security EventCode=4624 host={hostname}
| table _time user src_ip logon_type

# File creation (payload drops)
index=main sourcetype=sysmon EventCode=11 host={hostname}
| table _time file_name file_path process_name

# PowerShell (obfuscated commands)
index=main sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational host={hostname}
| table _time ScriptBlockText

# DNS (C2 domain resolution)
index=main sourcetype=sysmon EventCode=22 host={hostname}
| table _time QueryName QueryResults process_name
```

## Response Actions (Push back to Splunk)

```spl
# Add IOC to threat intel KV store
| inputlookup threat_intel.csv | append [| makeresults | eval ip="198.51.100.42", 
  description="C2 Server identified by AEGIS-IR", source="aegis-ir"]
| outputlookup threat_intel.csv

# Create notable event in Enterprise Security
| sendalert notable param.rule_title="AEGIS-IR: Confirmed Compromise"
  param.security_domain="threat" param.severity="critical"
```

## Connection Configuration

```json
// In AEGIS-IR .env:
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_TOKEN=<token-from-splunk-settings>
SPLUNK_MCP_ENABLED=true
```

## Alternative: Community MCP Server (pip install)

If the official Splunkbase app doesn't work for our setup, we can use:
```bash
pip install mcp-server-for-splunk
```
This provides 20+ tools and can run as a standalone MCP server.
GitHub: https://github.com/deslicer/mcp-for-splunk

## Integration Architecture

```
AEGIS-IR (ADK Agent)
    │
    ├── SIFT Tools (subprocess) → Forensic analysis on static evidence
    │
    ├── Splunk MCP Server → Live log data + historical search
    │     ├── splunk_run_query → Get process/network/auth events
    │     ├── saia_generate_spl → Agent asks for queries in English
    │     └── splunk_get_kv_store → Push/get IOCs
    │
    ├── Phoenix (OpenTelemetry) → Trace all decisions
    │
    └── Self-Correction + Guardrails → Verify findings from BOTH sources
```
