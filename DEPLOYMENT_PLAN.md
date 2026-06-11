# AEGIS-IR — Complete Engineering & Deployment Plan

## 1. RATE LIMITING (Fixed)

### Problem
Investigation hit `429 RESOURCE_EXHAUSTED` after ~12 LLM calls in 60 seconds.

### Root Cause
Vertex AI gemini-2.5-flash free tier = **10 RPM**. An investigation with 10+ tool calls = 10+ LLM round-trips = hits the limit.

### Solution Implemented: `src/sift_defender/utils/rate_limiter.py`

```
RetryWithBackoff(max_retries=5, initial_delay=3s, backoff_factor=2x)
```

| Retry | Delay | Total Wait |
|-------|-------|-----------|
| 1st   | 3s    | 3s        |
| 2nd   | 6s    | 9s        |
| 3rd   | 12s   | 21s       |
| 4th   | 24s   | 45s       |
| 5th   | 48s   | 93s       |

After 5 retries, the investigation completes with **partial results** (findings extracted from whatever the agent already produced).

### Recommended: Enable Paid Tier or DSQ

```bash
# Option A: Enable billing (Tier 1 = 200 RPM, $0.075/1M input tokens)
gcloud services enable aiplatform.googleapis.com --project=projectl-488105

# Option B: Enable Dynamic Shared Quota (no hard limit, best-effort)
# In Cloud Console → Vertex AI → Quotas → Enable DSQ for gemini-2.5-flash
```

With paid tier, rate limiting effectively disappears for our use case.

---

## 2. SIFT TOOLS IN LOCAL TESTING

### Problem
Python runs on Windows, SIFT tools (`fls`, `mmls`, `regripper`, etc.) are Linux-only (installed in WSL).

### Solution: Execute SIFT tools via WSL bridge

The SIFT tools in `sift_tools.py` use `subprocess.run(cmd, ...)`. On Windows, we need to prefix with `wsl` to execute inside WSL:

```python
# Current (fails on Windows):
subprocess.run(["fls", "-r", "/mnt/evidence"])

# Fixed (works on Windows via WSL):
subprocess.run(["wsl", "fls", "-r", "/mnt/evidence"])
```

### Implementation: WSL Auto-Detection

Already handled in `sift_tools.py` — the `_run()` function should detect Windows and prepend `wsl`:

```python
import platform

def _run(cmd: list[str], timeout: int = 120) -> dict:
    # Auto-detect Windows and route through WSL
    if platform.system() == "Windows":
        cmd = ["wsl"] + cmd
    # ... rest of execution
```

### How to test locally:
1. Ensure WSL is running: `wsl --status`
2. Evidence must be accessible from WSL: `/mnt/evidence` (maps to Windows path)
3. Test: `wsl fls -r /mnt/evidence` from PowerShell

### For the hackathon demo:
- Evidence image in WSL at `/mnt/evidence` (already set up)
- Tools called via WSL bridge from the Windows Python process
- OR run the entire server from inside WSL

---

## 3. GOOGLE CLOUD DEPLOYMENT ARCHITECTURE

### Target: Everything runs on GCP, accessible via public URL

```
┌─────────────────────────────────────────────────────────────────┐
│  Google Cloud (project: projectl-488105, region: us-central1)   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Cloud Run (AEGIS-IR Web + Agent)                        │   │
│  │  Container: aegis-ir:latest                              │   │
│  │  CPU: 4 vCPU, Memory: 8GB, Timeout: 3600s               │   │
│  │  Port: 8080                                              │   │
│  │                                                          │   │
│  │  ┌────────────┐  ┌──────────────┐  ┌────────────────┐   │   │
│  │  │ FastAPI    │  │ ADK Agent    │  │ Phoenix Client │   │   │
│  │  │ Dashboard  │  │ (Gemini 2.5) │  │ (traces)       │   │   │
│  │  └────────────┘  └──────────────┘  └────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
│           │                    │                    │            │
│           │                    ▼                    │            │
│           │          ┌──────────────────┐          │            │
│           │          │ Vertex AI API    │          │            │
│           │          │ gemini-2.5-flash │          │            │
│           │          └──────────────────┘          │            │
│           │                                        │            │
│           │                                        ▼            │
│           │                               ┌───────────────┐    │
│           │                               │ Phoenix Cloud │    │
│           │                               │ (Arize)       │    │
│           │                               └───────────────┘    │
│           ▼                                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  GCE VM (SIFT Workstation)                               │   │
│  │  Ubuntu 22.04 + SIFT tools                               │   │
│  │  Internal IP: 10.x.x.x                                   │   │
│  │                                                          │   │
│  │  Tools: fls, mmls, icat, volatility3, regripper,         │   │
│  │         evtxexport, clamscan, yara, foremost,            │   │
│  │         bulk_extractor, strings, sha256sum               │   │
│  │                                                          │   │
│  │  Evidence: /mnt/evidence (GCS FUSE or PD)                │   │
│  │  API: SSH tunnel or gRPC service on :50051               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Splunk Cloud (or GCE VM with Splunk)                    │   │
│  │  Port 8089 (REST API) — internal VPC only                │   │
│  │  Data: Security events, process logs, network logs       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Cloud Storage (GCS)                                     │   │
│  │  Bucket: aegis-ir-evidence                               │   │
│  │  Contains: disk images, memory dumps for investigation   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Deployment Steps

#### Step 1: Containerize AEGIS-IR

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
COPY start_server.py .

RUN pip install -e . --no-cache-dir

# Environment configured via Cloud Run env vars
ENV PORT=8080
EXPOSE 8080

CMD ["python", "start_server.py"]
```

#### Step 2: Deploy SIFT VM

```bash
# Create SIFT Workstation VM
gcloud compute instances create sift-workstation \
  --zone=us-central1-a \
  --machine-type=e2-standard-4 \
  --image-project=ubuntu-os-cloud \
  --image-family=ubuntu-2204-lts \
  --boot-disk-size=100GB \
  --tags=sift-internal

# Install SIFT tools
gcloud compute ssh sift-workstation -- 'sudo apt-get update && \
  sudo apt-get install -y sleuthkit volatility3 regripper \
  libevtx-utils clamav yara foremost bulk-extractor'

# Mount evidence from GCS
gcloud compute ssh sift-workstation -- 'sudo apt-get install -y gcsfuse && \
  sudo mkdir -p /mnt/evidence && \
  gcsfuse aegis-ir-evidence /mnt/evidence'
```

#### Step 3: SIFT Tools as gRPC Service

Instead of subprocess calls, the cloud version exposes SIFT tools via a lightweight gRPC server running on the SIFT VM:

```python
# On SIFT VM: sift_service.py (runs on port 50051)
# Accepts tool name + args, executes, returns output
# Cloud Run calls this via internal VPC networking
```

The `sift_tools.py` would have a cloud mode:

```python
SIFT_MODE = os.environ.get("SIFT_MODE", "local")  # "local" or "cloud"
SIFT_ENDPOINT = os.environ.get("SIFT_ENDPOINT", "10.x.x.x:50051")

def _run(cmd, timeout=120):
    if SIFT_MODE == "cloud":
        return _run_via_grpc(cmd, SIFT_ENDPOINT, timeout)
    elif platform.system() == "Windows":
        return _run_local(["wsl"] + cmd, timeout)
    else:
        return _run_local(cmd, timeout)
```

#### Step 4: Deploy to Cloud Run

```bash
# Build and push container
gcloud builds submit --tag gcr.io/projectl-488105/aegis-ir

# Deploy
gcloud run deploy aegis-ir \
  --image gcr.io/projectl-488105/aegis-ir \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --memory 8Gi \
  --cpu 4 \
  --timeout 3600 \
  --set-env-vars "GOOGLE_GENAI_USE_VERTEXAI=1,GOOGLE_CLOUD_PROJECT=projectl-488105,PHOENIX_MODE=cloud,SIFT_MODE=cloud,SIFT_ENDPOINT=10.x.x.x:50051"
```

#### Step 5: Splunk on Cloud

**Option A: Splunk Cloud Trial** (recommended for hackathon)
- Sign up at splunk.com → Get a cloud instance
- Configure HEC (HTTP Event Collector) for data ingestion
- Update `SPLUNK_HOST` to point to cloud instance

**Option B: Splunk on GCE**
```bash
gcloud compute instances create splunk-server \
  --zone=us-central1-a \
  --machine-type=e2-standard-4 \
  --boot-disk-size=50GB

# Install Splunk Enterprise (free dev license)
```

#### Step 6: Phoenix Cloud

```bash
# Switch from local to Arize Phoenix Cloud
# Sign up: https://app.phoenix.arize.com
# Get API key → set in Cloud Run env vars

PHOENIX_MODE=cloud
PHOENIX_API_KEY=px_live_xxxxx
PHOENIX_COLLECTOR_ENDPOINT=https://app.phoenix.arize.com
```

---

## 4. LOCAL TESTING WITH SIFT (Windows + WSL)

### Quick Fix: Add WSL bridge to sift_tools.py

Add this to the top of `sift_tools.py`:

```python
import platform

IS_WINDOWS = platform.system() == "Windows"
```

And modify `_run()`:

```python
def _run(cmd: list[str], timeout: int = 120) -> dict:
    # On Windows, route forensic tools through WSL
    if IS_WINDOWS and cmd[0] not in ["python", "python3"]:
        cmd = ["wsl"] + cmd
    
    # ... rest unchanged
```

### Test Flow (Local)
1. Start Phoenix: `python -m phoenix.server.main serve`
2. Start Splunk: (already running on localhost:8089)
3. Start AEGIS-IR: `python start_server.py`
4. Evidence in WSL: `/mnt/evidence` (create test artifacts there)
5. Open browser: `http://localhost:8080`
6. Click "+ New Investigation" → agent calls WSL tools + Splunk

---

## 5. ENVIRONMENT CONFIGURATIONS

### Local Development (.env)
```env
GOOGLE_GENAI_USE_VERTEXAI=1
GOOGLE_CLOUD_PROJECT=projectl-488105
GOOGLE_CLOUD_LOCATION=us-central1
GEMINI_MODEL=gemini-2.5-flash
PHOENIX_MODE=local
PHOENIX_LOCAL_ENDPOINT=http://localhost:6006
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_TOKEN=<your-token>
SIFT_MODE=local
```

### Cloud Production
```env
GOOGLE_GENAI_USE_VERTEXAI=1
GOOGLE_CLOUD_PROJECT=projectl-488105
GOOGLE_CLOUD_LOCATION=us-central1
GEMINI_MODEL=gemini-2.5-flash
PHOENIX_MODE=cloud
PHOENIX_API_KEY=px_live_xxxxx
PHOENIX_COLLECTOR_ENDPOINT=https://app.phoenix.arize.com
SPLUNK_HOST=<splunk-cloud-host>
SPLUNK_PORT=8089
SPLUNK_TOKEN=<splunk-cloud-token>
SIFT_MODE=cloud
SIFT_ENDPOINT=10.x.x.x:50051
```

---

## 6. IMMEDIATE NEXT STEPS (Priority Order)

### RIGHT NOW (fix rate limiting for local demo)
1. ✅ Rate limiter + retry implemented (`utils/rate_limiter.py`)
2. **Add WSL bridge to `sift_tools.py`** (so fls/mmls work from Windows)
3. **Run `gcloud auth application-default set-quota-project projectl-488105`** (fixes quota warnings)
4. **Consider switching to `gemini-2.5-flash-lite`** (15 RPM free, faster, cheaper)

### THIS WEEK (for hackathon submission)
5. Enable billing on `projectl-488105` (gets you 200 RPM, costs pennies)
6. Write Dockerfile
7. Deploy to Cloud Run
8. Set up SIFT VM with gRPC service
9. Switch Phoenix to cloud mode
10. Record demo video

### OPTIONAL (polish)
11. Add Splunk Cloud integration
12. Set up GCS for evidence storage
13. Add IAM for dashboard authentication
14. Custom domain (e.g., aegis-ir.app)
