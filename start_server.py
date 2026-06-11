"""Start AEGIS-IR — works on local dev AND Google Cloud Run.

Configuration priority:
1. Environment variables (set by Cloud Run, .env file, or command line)
2. Defaults (safe for local development)

Cloud Run sets: PORT, GOOGLE_CLOUD_PROJECT, K_SERVICE, K_REVISION
Local dev sets everything manually below.
"""
import os
import sys

sys.path.insert(0, "src")

# Detect if running on Cloud Run
IS_CLOUD_RUN = bool(os.environ.get("K_SERVICE"))

# --- Configure integrations (only set defaults if not already in env) ---

# Vertex AI / Gemini
os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "1")
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "projectl-488105")
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", "us-central1")
os.environ.setdefault("GOOGLE_CLOUD_QUOTA_PROJECT", os.environ.get("GOOGLE_CLOUD_PROJECT", "projectl-488105"))
os.environ.setdefault("GEMINI_MODEL", "gemini-2.5-flash")

# Phoenix
os.environ.setdefault("PHOENIX_MODE", "local" if not IS_CLOUD_RUN else "cloud")
os.environ.setdefault("PHOENIX_LOCAL_ENDPOINT", "http://localhost:6006")
os.environ.setdefault("PHOENIX_PROJECT_NAME", "aegis-ir")

# Splunk
os.environ.setdefault("SPLUNK_HOST", "localhost")
os.environ.setdefault("SPLUNK_PORT", "8089")
# Token from env or Secret Manager — NEVER hardcoded in production
if not os.environ.get("SPLUNK_TOKEN") and not IS_CLOUD_RUN:
    # Local dev fallback — read from .env or use test token
    from pathlib import Path
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        from dotenv import load_dotenv
        load_dotenv(env_file)

# SIFT
os.environ.setdefault("SIFT_MODE", "local")
os.environ.setdefault("SIFT_EVIDENCE_MOUNT", "/mnt/evidence")

# --- Initialize Phoenix tracing ---
import uvicorn
from sift_defender.web.app import create_app
from sift_defender.phoenix.tracer import PhoenixTracer

PhoenixTracer.reset()
phoenix = PhoenixTracer.get_instance().initialize()

# --- Create app ---
app = create_app()

# --- Startup banner ---
port = int(os.environ.get("PORT", "8080"))

if not IS_CLOUD_RUN:
    print()
    print("=" * 60)
    print("  AEGIS-IR — Autonomous Incident Response")
    print("=" * 60)
    print()
    print(f"  Dashboard:  http://localhost:{port}")
    print(f"  Phoenix:    {os.environ.get('PHOENIX_LOCAL_ENDPOINT', 'http://localhost:6006')}")
    print(f"  Splunk:     http://{os.environ.get('SPLUNK_HOST', 'localhost')}:8000")
    print()
    print("  Integrations:")
    print(f"    Gemini:  {os.environ.get('GEMINI_MODEL', 'gemini-2.5-flash')} via Vertex AI")
    print(f"    Splunk:  {'Connected' if os.environ.get('SPLUNK_TOKEN') else 'Not configured'}")
    print(f"    Phoenix: {phoenix.mode.value}")
    print(f"    SIFT:    {os.environ.get('SIFT_MODE', 'local')}")
    print()
    print(f"  Alert webhook: POST http://localhost:{port}/api/splunk-alert")
    print(f"  Health check:  GET  http://localhost:{port}/api/health")
    print("=" * 60)
    print()

uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning" if IS_CLOUD_RUN else "info")
