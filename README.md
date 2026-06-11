# AEGIS-IR — Autonomous Incident Response with Anti-Hallucination Guardrails

> **Rapid Agent Hackathon — Arize Track Submission**
>
> 🔴 **Live Demo:** [https://aegis-ir-872369929690.us-central1.run.app](https://aegis-ir-872369929690.us-central1.run.app)
>
> Built with **Google ADK + Gemini 2.5 Flash + Arize Phoenix**

---

## The Problem

Attackers now use AI to automate attacks that move faster than any human analyst can respond. The average time to detect a breach is still **197 days**. Automated attacks demand automated defense.

The industry has resisted giving AI full control over security operations because of one fundamental problem: **hallucination**. An AI agent that fabricates evidence or misidentifies threats is worse than no AI at all.

## Our Solution

AEGIS-IR is an **autonomous incident response agent** with a built-in **anti-hallucination guardrail pipeline**. It investigates threats in real-time using 31 forensic tools, and every single finding is evaluated for factual accuracy before reaching a human analyst.

**Why Arize Phoenix is the game-changer:** Phoenix provides the observability layer that makes trustworthy AI security agents possible. Without full trace visibility into every tool call, LLM reasoning step, and guardrail evaluation, you cannot verify that an AI agent is producing factual results. Phoenix gives us that verification layer — making the difference between "AI that we hope works" and "AI that we can prove works."

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  AEGIS-IR Agent (Google ADK + Gemini 2.5 Flash)         │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────────┐ │
│  │ 15 SIFT  │  │ 10 Splunk│  │ 4 Phoenix + 2 QC      │ │
│  │ Tools    │  │ Tools    │  │ Tools                  │ │
│  └──────────┘  └──────────┘  └───────────────────────┘ │
│                       │                                 │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Guardrail Pipeline (Anti-Hallucination)        │    │
│  │  ┌─────────┐  ┌────────────┐  ┌─────────────┐  │    │
│  │  │ APPROVE │  │ FLAG_REVIEW│  │   BLOCK     │  │    │
│  │  │ (factual│  │ (needs     │  │(hallucinated│  │    │
│  │  │  evidence)│ │  human)    │  │  blocked)   │  │    │
│  │  └─────────┘  └────────────┘  └─────────────┘  │    │
│  └─────────────────────────────────────────────────┘    │
│                       │                                 │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Self-Improvement Loop                          │    │
│  │  Learns from past mistakes → adjusts behavior   │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
            │                           │
    ┌───────┴───────┐          ┌───────┴────────┐
    │ Arize Phoenix │          │ Google Cloud   │
    │ - Traces      │          │ - Cloud Run    │
    │ - Evaluations │          │ - Vertex AI    │
    │ - Accuracy    │          │ - Gemini 2.5   │
    └───────────────┘          └────────────────┘
```

---

## Key Features

| Feature | Description |
|---------|-------------|
| **31 Forensic Tools** | SIFT disk analysis + Splunk SIEM + Phoenix observability |
| **Anti-Hallucination Guardrails** | Every finding evaluated: APPROVE / FLAG / BLOCK |
| **Self-Improvement Loop** | Agent learns from blocked hallucinations automatically |
| **Full Phoenix Observability** | Every tool call, LLM step, and evaluation traced |
| **Real-time WebSocket Feed** | Watch the agent investigate live in the dashboard |
| **Enterprise RBAC** | 3 roles (SOC Analyst, IR Lead, CISO), 16 permissions, JWT auth |
| **Tamper-Evident Audit Trail** | SHA-256 chain-hashed audit log for compliance |
| **MITRE ATT&CK Mapping** | Findings mapped to techniques automatically |
| **Splunk Alert Integration** | Webhook triggers autonomous investigation on alert |
| **709 Passing Tests** | Including property-based tests for correctness properties |

---

## How Arize Phoenix is Used

Phoenix is deeply integrated — not just for logging, but as the **trust verification layer**:

1. **Trace Every Agent Decision** — Every tool call, LLM reasoning step, and output is captured as OpenTelemetry spans flowing into Phoenix
2. **Guardrail Evaluation Spans** — Each finding passes through the guardrail pipeline, producing evaluation spans with scores (0.0-1.0), labels (factual/hallucinated), and actions (APPROVE/FLAG/BLOCK)
3. **Accuracy Trend Monitoring** — 30-day rolling accuracy metrics calculated from Phoenix span data, surfaced in the dashboard
4. **Self-Improvement Triggers** — When the guardrail blocks a hallucination, Phoenix annotations mark it as a learning event for the self-improvement loop
5. **Tool Effectiveness Ranking** — Phoenix trace analytics correlate which tools produce CONFIRMED findings vs which correlate with BLOCKED findings
6. **Embedded Observability** — No context-switching: traces, evaluations, and accuracy are embedded directly in the AEGIS-IR dashboard via Phoenix Client SDK

---

## Google Cloud Products Used

| Product | Usage |
|---------|-------|
| **Vertex AI (Gemini 2.5 Flash)** | LLM reasoning engine for the ADK agent |
| **Google ADK** | Agent Development Kit — orchestrates multi-tool forensic investigations |
| **Cloud Run** | Hosts the AEGIS-IR application (dashboard + API + agent) |
| **Cloud Storage** | Stores source code for Cloud Build |
| **Artifact Registry** | Docker container registry for deployment |
| **Cloud Build** | Builds the container image from source |

---

## Quick Start (For Judges)

### Option 1: Live Demo (Deployed on Cloud Run)

Visit: **https://aegis-ir-872369929690.us-central1.run.app**

- Dashboard with metrics, cases, and live investigation feed
- API docs at `/api/docs` (interactive Swagger UI)
- Start an investigation → watch the agent work in real-time

### Option 2: Run Locally

```bash
# Clone
git clone https://github.com/AbinjithTK/aegis-ir.git
cd aegis-ir

# Install
pip install -e .

# Set environment
export JWT_SECRET="demo-secret"
export GOOGLE_GENAI_USE_VERTEXAI=1
export GOOGLE_CLOUD_PROJECT=your-project-id
export PHOENIX_MODE=memory

# Run tests (709 passing)
python -m pytest tests/enterprise/ -q

# Start server
python start_server.py
# Open http://localhost:8080
```

### Option 3: Run the Test Suite

```bash
cd aegis-ir
pip install -e ".[dev]"
python -m pytest tests/enterprise/ -v
# 709 passed in ~30s
```

---

## Testing for Judges

### Verify Core Functionality

```bash
# Full enterprise test suite (709 tests)
python -m pytest tests/enterprise/ -q

# Endpoint smoke test (13 checks)
python test_demo.py

# Verify all endpoints work with RBAC
python verify_local.py
```

### What the Tests Cover

| Category | Tests | What it Proves |
|----------|-------|----------------|
| RBAC & Auth | 175 | JWT, permissions, role hierarchy, OIDC |
| Audit Trail | 136 | Chain hashing, append-only, tamper detection |
| Observability | 119 | Phoenix spans, accuracy trends, eval summaries |
| Migrations | 117 | Database schema, RLS, indexes |
| Property Tests | 19 | Mathematical correctness via Hypothesis |
| API Endpoints | 143 | RBAC enforcement, input validation, responses |

### Property-Based Tests (Formal Correctness)

```bash
# RBAC: No false positives or negatives (200 examples)
python -m pytest tests/enterprise/test_pbt_rbac.py -v

# Audit: Append-only invariant, chain integrity (100 examples)
python -m pytest tests/enterprise/test_pbt_audit.py -v

# Accuracy: count + rate invariants hold for any input (200 examples)
python -m pytest tests/enterprise/test_pbt_accuracy.py -v
```

---

## API Endpoints

| Endpoint | Description | Auth |
|----------|-------------|------|
| `POST /api/auth/login` | Authenticate, get JWT | Public |
| `POST /api/auth/refresh` | Refresh token | Refresh token |
| `POST /api/investigate` | Start autonomous investigation | Any role |
| `POST /api/splunk-alert` | Splunk webhook → auto-investigate | Public (webhook) |
| `GET /api/observability/accuracy-trend` | 30-day guardrail accuracy | IR Lead, CISO |
| `GET /api/observability/traces/{case_id}` | Live trace spans | Any role |
| `GET /api/observability/investigation/{id}/evals` | Per-finding evaluations | Any role |
| `GET /api/cases` | List investigations | Any role |
| `GET /api/metrics` | Dashboard metrics | Public |
| `GET /api/health` | Health check | Public |
| `WS /ws/live/{case_id}` | Real-time investigation feed | WebSocket |

---

## Deployment

### Cloud Run (Production)

```bash
gcloud run deploy aegis-ir \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 2Gi \
  --set-env-vars "GOOGLE_GENAI_USE_VERTEXAI=1,GOOGLE_CLOUD_PROJECT=projectl-488105,PHOENIX_MODE=memory,JWT_SECRET=your-secret,GEMINI_MODEL=gemini-2.5-flash"
```

### Agent Engine (Google ADK)

The agent uses Google ADK with:
- **Orchestrator Agent** — coordinates sub-agents for different forensic domains
- **Triage Agent** — initial alert classification and priority assessment  
- **Disk Agent** — SIFT forensic tool execution (15 tools)
- **Correlation Agent** — cross-references Splunk logs with disk artifacts
- **Reporting Agent** — generates findings with MITRE ATT&CK mapping

All agent traces flow to Phoenix via OpenTelemetry instrumentation provided by `openinference-instrumentation-google-adk`.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Agent Framework | Google ADK (Agent Development Kit) |
| LLM | Gemini 2.5 Flash via Vertex AI |
| Observability | Arize Phoenix + OpenTelemetry |
| Web Framework | FastAPI + HTMX + WebSocket |
| Database | PostgreSQL + asyncpg (enterprise module) |
| Auth | JWT (python-jose) + bcrypt + OIDC |
| Testing | pytest + Hypothesis (property-based) |
| Deployment | Google Cloud Run |
| SIEM | Splunk (alert webhook integration) |
| Forensics | SIFT Workstation (31 tools) |

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Team

Built for the **Rapid Agent Hackathon — Arize Track** by the AEGIS-IR team.

**The future of security operations is autonomous, observable, and trustworthy.** Phoenix makes that possible.
