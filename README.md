# AEGIS-IR — Autonomous Incident Response with Anti-Hallucination Guardrails

> **Rapid Agent Hackathon — Arize Track**
>
> 🔗 **Live Demo:** [aegis-ir-872369929690.us-central1.run.app](https://aegis-ir-872369929690.us-central1.run.app)  
> 📦 **Repo:** [github.com/AbinjithTK/aegis-ir](https://github.com/AbinjithTK/aegis-ir)

---

## What is AEGIS-IR?

AEGIS-IR is an **autonomous AI agent** that investigates security incidents without human intervention. When an attack is detected, it:

1. **Receives the alert** from Splunk (SIEM)
2. **Investigates autonomously** using 31 forensic tools
3. **Validates every finding** through an anti-hallucination guardrail
4. **Reports results** with MITRE ATT&CK mapping for the analyst to approve/reject

The entire process is traced through **Arize Phoenix** for full observability and self-improvement.

---

## Why This Matters

| Problem | AEGIS-IR Solution |
|---------|-------------------|
| Attacks happen in seconds, manual investigation takes days | Autonomous agent responds in under 60 seconds |
| AI agents hallucinate (fabricate evidence) | Guardrail pipeline blocks hallucinated findings |
| No visibility into AI decision-making | Every step traced via Phoenix (tool calls, reasoning, evaluations) |
| AI doesn't learn from mistakes | Self-improvement loop adjusts behavior from past blocked findings |

---

## How the Components Work Together

```
┌──────────────────────────────────────────────────────────────┐
│                        AEGIS-IR System                        │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   SPLUNK (SIEM)          ADK AGENT (Brain)       SIFT (Forensics) │
│   ┌─────────────┐       ┌──────────────┐       ┌────────────┐│
│   │ Detects     │──────▶│ Gemini 2.5   │──────▶│ Disk/Memory││
│   │ attacks in  │       │ Flash thinks │       │ analysis   ││
│   │ network logs│◀──────│ & decides    │◀──────│ tools      ││
│   └─────────────┘       └──────┬───────┘       └────────────┘│
│                                │                              │
│                    ┌───────────▼────────────┐                 │
│                    │  GUARDRAIL PIPELINE    │                 │
│                    │  (Anti-Hallucination)  │                 │
│                    │                        │                 │
│                    │  ✅ APPROVE (factual)  │                 │
│                    │  ⚠️ FLAG (needs review)│                 │
│                    │  🚫 BLOCK (fabricated) │                 │
│                    └───────────┬────────────┘                 │
│                                │                              │
│                    ┌───────────▼────────────┐                 │
│                    │   ARIZE PHOENIX        │                 │
│                    │   (Observability)      │                 │
│                    │                        │                 │
│                    │   • Traces every step  │                 │
│                    │   • Accuracy metrics   │                 │
│                    │   • Self-improvement   │                 │
│                    └────────────────────────┘                 │
└──────────────────────────────────────────────────────────────┘
```

---

## What Each Component Does

### 🔍 Splunk (SIEM — Security Information & Event Management)

**What it is:** Splunk collects and indexes security logs from all systems in an organization (firewalls, servers, endpoints). It detects attacks by searching for suspicious patterns.

**How AEGIS-IR uses it:**
- Splunk fires a webhook alert → AEGIS-IR auto-starts an investigation
- The agent queries Splunk for attack events (process creation, network connections, login failures)
- The agent pushes IOCs (Indicators of Compromise) back to Splunk for blocking

**10 Splunk tools:** `splunk_search`, `splunk_get_process_events`, `splunk_get_network_connections`, `splunk_get_login_events`, `splunk_get_file_events`, `splunk_get_registry_events`, `splunk_query_ioc`, `splunk_push_ioc`, `splunk_notable_event`, `splunk_connection_test`

---

### 🔬 SANS SIFT (Digital Forensics)

**What it is:** SIFT (SANS Investigative Forensics Toolkit) is a collection of forensic tools for analyzing disk images, memory dumps, and file systems. Used by law enforcement and incident responders worldwide.

**How AEGIS-IR uses it:**
- Runs disk forensics tools on evidence (mounted disk images)
- Extracts file metadata, searches for malware artifacts
- Analyzes deleted files, prefetch data, registry hives
- Computes file hashes for IOC matching

**15 SIFT tools:** `sleuthkit_fls` (list files), `sleuthkit_icat` (extract file), `strings_analysis`, `sha256sum`, `find_executables`, `check_prefetch`, `analyze_registry`, `volatility_pslist` (memory), `volatility_netscan`, `disk_timeline`, `yara_scan`, `log2timeline`, `bulk_extractor`, `exiftool`, `autopsy_search`

---

### 📡 Arize Phoenix (AI Observability)

**What it is:** Phoenix is an open-source platform by Arize AI for tracing, evaluating, and monitoring AI applications. It captures every LLM call, tool invocation, and decision as OpenTelemetry spans.

**How AEGIS-IR uses it:**
- **Tracing:** Every agent action (tool calls, LLM reasoning, guardrail evaluations) is captured as spans
- **Evaluation:** Guardrail decisions are logged as evaluation spans with scores (0.0-1.0)
- **Accuracy Monitoring:** 30-day rolling metrics show if the agent is getting better or worse
- **Self-Improvement:** When the guardrail blocks a hallucination, Phoenix annotations trigger the agent to learn from the mistake
- **Tool Effectiveness:** Phoenix analytics show which tools produce reliable findings vs which correlate with hallucinations

**Phoenix integration points:**
- `openinference-instrumentation-google-adk` — auto-instruments all ADK agent calls
- `arize-phoenix-evals` — LLM-as-judge hallucination detection
- `phoenix.Client` — query traces for accuracy trends and tool analytics

---

### 🤖 Google ADK Agent (The Brain)

**What it is:** Google's Agent Development Kit (ADK) is a framework for building multi-tool AI agents powered by Gemini. The agent reasons about what to do, selects tools, interprets results, and draws conclusions.

**How AEGIS-IR uses it:**
- **Orchestrator Agent** — coordinates the investigation workflow
- **Triage Agent** — classifies alert severity and determines investigation scope
- **Disk Agent** — executes SIFT forensic tools and interprets results
- **Correlation Agent** — cross-references Splunk logs with disk findings
- **Reporting Agent** — produces findings with confidence levels and MITRE ATT&CK mapping

**Model:** Gemini 2.5 Flash via Vertex AI (fast, cost-effective reasoning)

---

## Quick Start: Try the Live Demo (No Setup Required)

Open **https://aegis-ir-872369929690.us-central1.run.app** in your browser and follow along:

### Step 1: Dashboard (Home Page)

When you open the link, you'll see the AEGIS-IR dashboard with:
- **Accuracy** — guardrail pass rate (how often the agent produces factual results)
- **Cases** — number of investigations completed
- **Blocked** — hallucinations caught and prevented by the guardrail
- **Tools** — 31 forensic tools available to the agent

### Step 2: Start an Investigation

1. Click the **"Splunk Logs"** button (blue, center of page)
2. A modal opens — leave the defaults and click **"Start"**
3. You're taken to the **Investigation View** where the agent works in real-time

**What happens behind the scenes:**
- Gemini 2.5 Flash starts reasoning about what to investigate
- The agent calls Splunk tools to search for attack events
- Each finding passes through the anti-hallucination guardrail
- Results appear in the **Findings** panel on the right

> Note: On the cloud version, Splunk is not locally accessible so the agent may complete quickly with no findings. For the full demo with attack data, use the local setup below.

### Step 3: View Cases

Click **"Cases"** in the left sidebar to see all investigations with:
- Case ID and status (running / complete)
- Number of findings and blocked hallucinations
- Investigation duration

Click any case to re-open its live feed and findings.

### Step 4: Check Accuracy

Click **"Accuracy"** in the sidebar. This page shows:
- **Approved** — findings that were backed by real evidence
- **Flagged** — findings that need human review
- **Blocked** — fabricated findings caught by the guardrail

It also explains how the guardrail pipeline works (APPROVE / FLAG / BLOCK).

### Step 5: View Live Traces

Click **"Live Traces"** in the sidebar. This shows:
- Phoenix observability mode and project name
- Explanation of what gets traced (tool calls, LLM reasoning, evaluations)

In the full local setup, you'd see an actual Phoenix UI at `localhost:6006` with every span visualized.

### Step 6: Configure Integrations

Click **"Integrations"** in the sidebar. You'll see settings for:
- **Splunk SIEM** — Host, port, authentication token
- **Phoenix** — Mode (local/cloud/memory), endpoint, project
- **Gemini / Vertex AI** — GCP project, region, model selection
- **SIFT Forensic Tools** — Mode (local/cloud), evidence path, gRPC endpoint

These save immediately and the agent uses the new config on the next investigation.

### Step 7: Test the API

Visit **https://aegis-ir-872369929690.us-central1.run.app/api/docs** for interactive Swagger documentation. You can test all 18 endpoints directly from the browser:

- `GET /api/health` — server health check
- `GET /api/metrics` — accuracy, cases, blocked count
- `GET /api/status` — connection status of all integrations
- `POST /api/investigate` — start a new investigation
- `GET /api/cases` — list all cases
- `POST /api/splunk-alert` — simulate a Splunk alert webhook
- `GET /api/observability/accuracy-trend` — 30-day guardrail metrics (requires auth)
- `GET /api/observability/traces/{case_id}` — live trace spans (requires auth)

### What the Sidebar Status Dots Mean

At the bottom of the sidebar, you'll see connection status:
- 🟢 **Green dot** = connected and working
- 🔴 **Red dot** = not reachable from this deployment

On Cloud Run: Gemini shows green (connected via Vertex AI). Splunk and Phoenix may show red since they're configured for localhost.

---

## Setup Guide (For Judges & Testers)

### Prerequisites

- Python 3.10+ 
- Google Cloud account with Vertex AI enabled
- Docker (for Splunk)

### Step 1: Clone & Install

```bash
git clone https://github.com/AbinjithTK/aegis-ir.git
cd aegis-ir
pip install -e .
```

### Step 2: Set Up Splunk (receives attack data)

```bash
# Run Splunk in Docker (free dev license, takes 2 min to start)
docker run -d -p 8000:8000 -p 8089:8089 \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_PASSWORD=changeme123 \
  --name splunk splunk/splunk:latest

# Wait 2 minutes, then open http://localhost:8000
# Login: admin / changeme123
# Go to: Settings → Data Inputs → HTTP Event Collector → Enable
# Create a new HEC token for AEGIS-IR
```

**Load test attack data:**
```bash
# Upload the included ransomware scenario to Splunk
# Go to: http://localhost:8000 → Settings → Add Data → Upload
# Select: sample_data/ransomware_attack.csv
# Set sourcetype: csv, index: main
```

### Step 3: Set Up Phoenix (traces & observability)

```bash
# Install and start Phoenix (open-source, runs locally)
pip install arize-phoenix
phoenix serve --port 6006

# Open http://localhost:6006 — this is where you see all agent traces
```

### Step 4: Configure Google Cloud (for Gemini)

```bash
# Authenticate with Google Cloud
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID

# Enable Vertex AI
gcloud services enable aiplatform.googleapis.com
```

### Step 5: Configure Environment

```bash
# Copy the example config
cp .env.example .env

# Edit .env with your values:
GOOGLE_GENAI_USE_VERTEXAI=1
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_CLOUD_LOCATION=us-central1
GEMINI_MODEL=gemini-2.5-flash

SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_TOKEN=your-hec-token-from-step-2

PHOENIX_MODE=local
PHOENIX_LOCAL_ENDPOINT=http://localhost:6006
PHOENIX_PROJECT_NAME=aegis-ir

SIFT_MODE=local
SIFT_EVIDENCE_MOUNT=/mnt/evidence
```

### Step 6: Start AEGIS-IR

```bash
python start_server.py
```

You'll see:
```
============================================================
  AEGIS-IR — Autonomous Incident Response
============================================================

  Dashboard:  http://localhost:8080
  Phoenix:    http://localhost:6006
  Splunk:     http://localhost:8000

  Integrations:
    Gemini:  gemini-2.5-flash via Vertex AI
    Splunk:  Connected
    Phoenix: local
    SIFT:    local
============================================================
```

### Step 7: Run an Investigation

1. Open **http://localhost:8080** (AEGIS-IR Dashboard)
2. Click **"Splunk Logs"** button
3. Click **"Start"**
4. Watch the agent work in the **Live Feed** panel

### Step 8: Verify in Phoenix

1. Open **http://localhost:6006** (Phoenix)
2. Click the **"aegis-ir"** project
3. You'll see traces:
   - `splunk_search` — agent querying Splunk for attack events
   - `gemini-2.5-flash` — LLM reasoning about what it found
   - `guardrail_evaluation` — each finding being checked for hallucination
   - `self_improvement` — agent learning from blocked findings

---

## What Judges Will See

| Screen | What It Shows |
|--------|---------------|
| **Dashboard** (localhost:8080) | Metrics, investigation CTA, live feed, cases |
| **Investigation View** | Real-time agent tool calls, findings with approve/reject |
| **Phoenix** (localhost:6006) | Full trace timeline — proof the agent actually works |
| **Settings** | Configure all integrations at runtime |
| **Accuracy Page** | Guardrail pass/flag/block rates |

---

## Test Data Included

The repo includes `sample_data/ransomware_attack.csv` — a realistic LockBit ransomware scenario:

```
Timeline:
02:00 - Brute force login on domain controller (5 failed + 1 success)
02:01 - Reconnaissance (whoami, net user, net group)
02:01 - PowerShell downloads payload from C2 server
02:02 - Mimikatz credential dump
02:03 - Lateral movement via PsExec to file server
02:03 - Shadow copy deletion + backup wipe (ransomware prep)
02:04 - LockBit3 ransomware executed, files encrypted
02:04 - Data exfiltration (500MB to C2)
02:05 - Backdoor user created in Domain Admins
```

The agent will detect and map these to MITRE ATT&CK:
- T1110 (Brute Force), T1059.001 (PowerShell), T1003 (Credential Dump)
- T1021 (Lateral Movement), T1490 (Inhibit Recovery), T1486 (Ransomware)

---

## Running the Test Suite

```bash
# Full test suite (709 tests, ~30 seconds)
python -m pytest tests/enterprise/ -q

# Property-based correctness tests
python -m pytest tests/enterprise/test_pbt_rbac.py -v     # RBAC: no false positives/negatives
python -m pytest tests/enterprise/test_pbt_audit.py -v    # Audit: append-only chain integrity
python -m pytest tests/enterprise/test_pbt_accuracy.py -v # Accuracy: mathematical invariants
```

---

## Google Cloud Deployment

```bash
# Deploy to Cloud Run (single command)
gcloud run deploy aegis-ir \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 2Gi \
  --set-env-vars "GOOGLE_GENAI_USE_VERTEXAI=1,GOOGLE_CLOUD_PROJECT=your-project,PHOENIX_MODE=memory,JWT_SECRET=your-secret,GEMINI_MODEL=gemini-2.5-flash"
```

---

## Google Cloud Products Used

| Product | Usage |
|---------|-------|
| **Vertex AI** | Gemini 2.5 Flash — LLM reasoning for the agent |
| **Google ADK** | Agent Development Kit — multi-tool orchestration |
| **Cloud Run** | Hosts the application (stateless, auto-scaling) |
| **Cloud SQL** | PostgreSQL database for cases, audit, RBAC |
| **Cloud Build** | Container builds from source |
| **Artifact Registry** | Docker image storage |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Agent | Google ADK + Gemini 2.5 Flash |
| Observability | Arize Phoenix + OpenTelemetry |
| SIEM | Splunk Enterprise |
| Forensics | SANS SIFT Workstation (15 tools) |
| Backend | FastAPI + asyncpg + PostgreSQL |
| Auth | JWT + bcrypt + RBAC (16 permissions) |
| Frontend | HTML + Lucide Icons + WebSocket |
| Testing | pytest + Hypothesis (property-based) |
| Deployment | Google Cloud Run |

---

## License

MIT — see [LICENSE](LICENSE)

---

## The Vision

AEGIS-IR proves that **AI-powered security operations are possible today** — when you solve the hallucination problem. Arize Phoenix makes this possible by providing the observability layer that turns a black-box AI agent into a transparent, trustworthy, and self-improving system.

**Defense that moves at the speed of attack.**
