# AEGIS-IR

**Autonomous Evidence-Guided Investigation System for Incident Response**

An AI-powered incident response agent that combines SIFT Workstation forensic tools with live Splunk SIEM data, featuring architectural anti-hallucination guardrails powered by Arize Phoenix.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  AEGIS-IR Dashboard (FastAPI + WebSocket)                │
│  http://localhost:8080                                    │
├──────────────────────────────────────────────────────────┤
│  Investigation Runner                                    │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ ADK Agent │→│ Guardrail    │→│ Improvement Loop  │  │
│  │ (Gemini)  │  │ Pipeline     │  │ (Self-Learning)   │  │
│  └─────┬────┘  └──────────────┘  └───────────────────┘  │
│        │                                                 │
│  ┌─────┴──────────────────────────────────────────────┐  │
│  │ 28 Real Tools                                       │  │
│  │ ┌──────────────┐ ┌────────────┐ ┌───────────────┐  │  │
│  │ │ 15 SIFT      │ │ 10 Splunk  │ │ 2 QC + YARA   │  │  │
│  │ │ (WSL binary) │ │ (REST API) │ │ (Phoenix)     │  │  │
│  │ └──────────────┘ └────────────┘ └───────────────┘  │  │
│  └────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────┤
│  Phoenix Tracing (localhost:6006)                         │
│  Every tool call, finding, and decision traced           │
└──────────────────────────────────────────────────────────┘
```

## Key Features

1. **Dual Data Sources** — Splunk (live logs) + SIFT (disk forensics) working together
2. **Anti-Hallucination Guardrails** — Architectural gate: no finding reaches user without passing deterministic checks
3. **Self-Improvement Loop** — Agent learns from past investigations (what it got wrong, recurring patterns)
4. **Automated Alert Response** — Splunk webhook triggers autonomous investigation
5. **Real-Time Dashboard** — WebSocket live feed of agent tool calls, thinking, and findings
6. **MITRE ATT&CK Mapping** — Every finding mapped to technique IDs
7. **Confidence Scoring** — CONFIRMED / INFERRED / BLOCKED (never guesses)

## Quick Start

```bash
# Prerequisites: Splunk on localhost:8089, Phoenix on localhost:6006, gcloud auth

# Start Phoenix (separate terminal)
python -m phoenix.server.main serve

# Start AEGIS-IR
cd aegis-ir
python start_server.py
# → http://localhost:8080
```

## Splunk Alert Integration

Configure in Splunk: **Settings → Alerts → Add Action → Webhook**
```
URL: http://localhost:8080/api/splunk-alert
```

When an alert fires, AEGIS-IR automatically:
1. Queries Splunk for full context on the affected host
2. Runs SIFT forensic tools against mounted evidence
3. Cross-references both data sources
4. Produces MITRE-mapped findings (with guardrails)
5. Pushes IOCs back to Splunk for blocking

## Hackathon Submissions

Built for three hackathons from one product:
- **SANS "Find Evil!" 2026** — Autonomous DFIR agent ($22K prizes)
- **Splunk Agentic Ops** — Security track with Splunk MCP ($20K prizes)
- **Google/Arize** — Phoenix self-improvement loop ($5K per track)

## License

MIT
