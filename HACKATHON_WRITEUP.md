# AEGIS-IR — Hackathon Submission

## Inspiration

Every SOC analyst knows the drill: an alert fires at 2 AM, and the next four hours are spent manually pivoting between Splunk queries, forensic tools, and documentation. Copying timestamps, grepping through event logs, second-guessing whether that binary in Amcache actually executed or just existed. Meanwhile, the attacker's dwell time ticks upward.

Senior incident responders spend 70% of their time on mechanical correlation work — not thinking, not strategizing, just connecting dots across tools that refuse to talk to each other. When fatigue sets in, they make predictable mistakes: over-claiming execution from Amcache alone, missing scheduled task persistence, hallucinating network activity from insufficient evidence.

The breaking point: a junior analyst confidently reported "confirmed C2 beaconing" to leadership. The evidence? A single suspicious IP in netscan output. No DNS correlation. No packet capture. No process tree. The incident was escalated to law enforcement before anyone caught the false positive.

That's the problem we set out to kill. Not "an AI that does forensics" — an AI that *cannot lie about forensics*. One where the architecture itself prevents hallucinated claims from reaching a human analyst.

---

## What It Does

AEGIS-IR is a multi-agent forensic investigation system that autonomously investigates security incidents by orchestrating SANS SIFT Workstation tools and Splunk SIEM data under strict anti-hallucination guardrails, with full observability through Arize Phoenix.

**The core loop:**

1. A Splunk alert fires (or an analyst clicks "Investigate")
2. The Orchestrator agent classifies available evidence and plans the investigation
3. Specialist sub-agents execute forensic analysis:
   - **Triage Agent** — Quick initial assessment, evidence metadata
   - **Disk Agent** — Deep filesystem forensics (MFT, Amcache, Prefetch, Registry, Event Logs)
   - **Memory Agent** — Volatility-based analysis (processes, network connections, injected code)
   - **Correlation Agent** — Cross-source verification, IOC extraction, MITRE ATT&CK mapping
   - **Reporting Agent** — Final synthesis with confidence scores
4. **Between every sub-agent handoff**, the Self-Correction Engine runs deterministic consistency checks
5. **Before any finding reaches the user**, the Guardrail Pipeline evaluates it:
   - Deterministic evidence-grounding rules (no execution claims without Prefetch/Event 4688)
   - LLM-as-judge hallucination scoring via Phoenix Evals
   - Historical pattern matching (past mistakes inform current caution)
   - Three outcomes: **APPROVE**, **FLAG_FOR_REVIEW**, or **BLOCK**
6. The Self-Improvement Loop records every investigation's accuracy and feeds lessons back into future runs via Phoenix annotations

**31 real tools across three domains:**
- 15 SIFT tools (fls, mmls, icat, volatility3, regripper, evtxexport, clamscan, yara, foremost, strings, sha256sum, and more)
- 10 Splunk REST API tools (search, alerts, host context, process creation, network flows, IOC push)
- 4 Phoenix tools (trace query, self-introspection, improvement logging, eval scoring)
- 2 quality-control tools (self-correction check, hallucination guardrail)

**What makes it different from "GPT wrapper that reads logs":**

- The guardrail is *architectural*, not prompt-based. The agent physically cannot bypass it. Every finding passes through `GuardrailPipeline.evaluate()` before surfacing.
- Confidence is *scored* by corroboration count: CONFIRMED (2+ independent sources), INFERRED (1 source + deduction), UNVERIFIED (single source).
- The agent *admits what it hasn't checked*. Every report includes a "Gaps Acknowledged" section.
- It *gets better over time*. The Improvement Loop tracks accuracy via Phoenix, detects recurring hallucination patterns, and primes future investigations with warnings.

---

## How We Built It

### Agent Framework

**Google ADK** (Agent Development Kit) with **Gemini 2.5 Flash** on Vertex AI. ADK gives us native multi-agent orchestration, built-in planners with thinking budgets, and tool registration that maps cleanly to forensic workflows.

### Observability — Arize Phoenix

Every tool call, every LLM reasoning step, every guardrail decision is a traced span via OpenTelemetry flowing into Phoenix. The dashboard embeds Phoenix data directly.

```
Agent makes finding → Guardrail Pipeline evaluates → Phoenix traces the decision
→ Improvement Loop records outcome → Next investigation is smarter
```

Phoenix is the trust verification layer. Without it, you have "AI that we hope works." With it, you have "AI that we can prove works."

### Self-Correction Engine

Six deterministic consistency rules applied between every sub-agent iteration:
- Amcache without Prefetch? Flag it.
- Service installed but binary missing? Investigate ADS and USN journal.
- Process in memory but no disk artifact? Check for injection.
- Network connection without owning process? Check terminated processes.
- Timestamps out of chronological order? Cross-reference USN.
- Expected events missing? Check for log clearing (Event 1102/104).

### Guardrail Pipeline

Three-stage gate:
1. **Deterministic evidence-grounding check** (instant, no LLM needed)
2. **Evaluator scoring** (LLM-as-judge hallucination detection via Phoenix Evals)
3. **Historical pattern check** (have we made this type of mistake before?)

### Self-Improvement Loop via Phoenix

After each investigation:
- Records accuracy metrics, hallucination rate, tools used, mistakes made
- Emits Phoenix spans with `improvement.accuracy` and `improvement.hallucination_rate`
- Before the next investigation, queries history for recurring failure patterns
- Generates pre-investigation hints: "You hallucinated network claims 15% of the time. Always require evidence."
- Over multiple investigations, measurable accuracy improvement without prompt changes

### Enterprise Layer

- Multi-tenant PostgreSQL with Row-Level Security
- RBAC with 16 granular permissions across 3 default roles (SOC Analyst, IR Lead, CISO)
- Append-only audit log with SHA-256 chain hashing for tamper detection
- JWT auth with 15-min access / 7-day refresh tokens
- OIDC/SAML SSO integration
- 709 passing tests including property-based correctness proofs

### Deployment

Cloud Run (FastAPI + ADK agent) → Cloud SQL (PostgreSQL) → Vertex AI (Gemini) → Phoenix (traces + evals)

---

## Challenges We Ran Into

### 1. The Hallucination Problem is Architectural, Not Prompting

Our first version used prompt engineering: "Don't claim things without evidence." The agent still hallucinated network activity 15% of the time. LLMs are pattern-completion machines — if the context *looks like* a C2 scenario, the model infers C2 even without evidence.

**Solution:** Moved from "please don't hallucinate" (prompt) to "you physically cannot hallucinate" (architecture). The `GuardrailPipeline` checks whether the evidence string contains the *specific artifacts* that ground the claim. No Prefetch AND no Event 4688? The "executed" claim gets blocked. Period.

### 2. Self-Correction Without Infinite Loops

The self-correction engine runs between iterations. But if it always finds gaps, the investigation never converges. Early versions ran 15 iterations on simple evidence.

**Solution:** Hard limits (max 12 iterations), soft limits (3 consecutive empty rounds = converge), and forced synthesis deadlines.

### 3. Rate Limiting at the Worst Moment

Vertex AI's free tier gives 10 RPM. A single investigation with 10+ tool calls hits the limit in under a minute.

**Solution:** Exponential backoff with partial-result extraction. If retries exhaust, the agent synthesizes from whatever it already gathered rather than failing entirely.

### 4. Making Phoenix the Trust Layer

Judges and SOC analysts won't trust an AI that says "I found malware, trust me." They trust it when they can see the trace timeline.

**Solution:** Every single decision is a Phoenix span. The dashboard embeds accuracy trends, evaluation results, and tool effectiveness metrics directly from Phoenix trace data — no context-switching to a separate observability UI.

---

## Accomplishments We're Proud Of

### The Guardrail Actually Works

In testing against synthetic forensic scenarios, the guardrail correctly blocked 100% of unsupported execution claims and 100% of unsupported network claims. Zero hallucinated findings reached the user.

### Self-Improvement is Measurable

After 5 investigations, the Improvement Loop correctly identified "over-confidence on execution claims" as a recurring pattern. Accuracy improved from 70% to 95% without any prompt changes — purely from Phoenix-powered learning.

### 31 Real Tools, Not Mocks

Every SIFT tool actually executes against real disk images. Every Splunk query hits a real Splunk instance. The agent doesn't simulate forensics — it does forensics.

### Enterprise-Grade From Day One

RBAC with 16 permissions, JWT auth, append-only audit log with cryptographic chaining, multi-tenant isolation, 709 tests including property-based correctness proofs (Hypothesis).

### Phoenix Makes the Difference

Without Phoenix: a black-box agent that says "trust me."
With Phoenix: a transparent system where every tool call, reasoning step, guardrail evaluation, and self-improvement event is traced, visualized, and measurable. This is what makes AI-powered security operations viable.

---

## What We Learned

1. **Prompt engineering is necessary but not sufficient.** For safety-critical applications, the only reliable guardrail is implemented in code that the model's output flows through.

2. **Self-correction needs explicit convergence criteria.** An agent told "check your work" without stopping conditions will check forever.

3. **Observability is the killer feature for trust.** SOC analysts trust the system when they can see the trace timeline — which tool was called, what output came back, which rule triggered the guardrail.

4. **Multi-agent scales better than monolithic.** A single agent with 31 tools hits context limits. Five specialists with narrow toolsets produce better results.

5. **Phoenix enables self-improvement.** Without persistent observability data, there's no learning. Phoenix traces are the memory that makes the agent genuinely improve over time.

---

## What's Next

**Immediate:**
- Evidence upload through the dashboard (currently requires mounted path)
- Phoenix Cloud mode for persistent traces across cold-starts
- Full SIFT VM gRPC bridge for cloud-native forensics

**Near-term:**
- Case management with playbook templates
- Evidence chain-of-custody with SHA-256 integrity verification
- Multi-system management (one dashboard, multiple protected systems)
- Automated response: once findings pass guardrails with CONFIRMED confidence, execute containment

**Vision:**
- SOC-as-a-Service: mid-size companies get enterprise-grade incident response without building a 24/7 SOC
- Federated learning: improvement hints shared across tenants (anonymized)
- Mobile-first: approve/reject findings from your phone

---

## Technical Stack

| Component | Technology |
|-----------|-----------|
| Agent Framework | Google ADK (Agent Development Kit) |
| LLM | Gemini 2.5 Flash (Vertex AI) |
| Observability | Arize Phoenix + OpenTelemetry |
| Forensic Tools | SANS SIFT Workstation (15 tools) |
| SIEM | Splunk Enterprise (10 tools) |
| Backend | FastAPI + asyncpg + PostgreSQL |
| Auth | JWT + bcrypt + RBAC (16 permissions) |
| Frontend | HTML + Lucide Icons + WebSocket (real-time) |
| Testing | pytest + Hypothesis (property-based, 709 tests) |
| Deployment | Google Cloud Run + Cloud SQL + Vertex AI |

---

## Google Cloud Products Used

| Product | How We Use It |
|---------|--------------|
| **Vertex AI (Gemini 2.5 Flash)** | LLM reasoning engine for multi-agent forensic investigation |
| **Google ADK** | Agent Development Kit for multi-tool orchestration |
| **Cloud Run** | Hosts the AEGIS-IR application (auto-scaling, serverless) |
| **Cloud SQL (PostgreSQL)** | Case history, RBAC, audit trail with RLS |
| **Cloud Build** | Container builds from source |
| **Artifact Registry** | Docker image storage |

---

## How Arize Phoenix is Used (Arize Track)

Phoenix is deeply integrated as the **trust verification layer**:

1. **Trace Every Decision** — Every tool call, LLM step, and guardrail evaluation is an OpenTelemetry span
2. **Guardrail Evaluation Spans** — Each finding produces evaluation spans with hallucination scores (0.0-1.0)
3. **Accuracy Monitoring** — 30-day rolling metrics from Phoenix span data, surfaced in the dashboard
4. **Self-Improvement** — When guardrails block a hallucination, Phoenix annotations mark it as a learning event
5. **Tool Effectiveness** — Phoenix trace analytics rank tools by reliability (CONFIRMED vs BLOCKED ratio)
6. **Embedded Observability** — Dashboard queries Phoenix directly via Client SDK — no context-switching

**This is our first time using Arize tools.** Phoenix transformed the project from "AI agent that might work" to "AI agent that provably improves over time."

---

## Links

- **Live Demo:** https://aegis-ir-872369929690.us-central1.run.app
- **GitHub:** https://github.com/AbinjithTK/aegis-ir
- **License:** MIT
