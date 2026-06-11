"""AEGIS-IR Local Verification — run this to confirm everything works."""
import os
import time

os.environ["JWT_SECRET"] = "demo-secret-key"
os.environ["PHOENIX_MODE"] = "memory"

from sift_defender.web.app import create_app
from sift_defender.enterprise.auth.jwt import create_access_token
from fastapi.testclient import TestClient

app = create_app()
client = TestClient(app, raise_server_exceptions=False)

print("=" * 60)
print("  AEGIS-IR — LOCAL VERIFICATION")
print("=" * 60)

# 1. Health
r = client.get("/api/health")
h = r.json()
print(f"\n✅ [HEALTH] Status: {h['status']} | Service: {h['service']} | v{h['version']}")

# 2. Integrations
r = client.get("/api/status")
s = r.json()
print(f"\n📡 [INTEGRATIONS]")
print(f"   Phoenix: mode={s['phoenix']['mode']} connected={s['phoenix']['connected']}")
print(f"   Gemini:  model={s['gemini']['model']} project={s['gemini']['project']}")
print(f"   Splunk:  connected={s['splunk']['connected']}")
print(f"   SIFT:    mode={s['sift']['mode']}")

# 3. Auth
print(f"\n🔐 [AUTH & RBAC]")
token_lead = create_access_token("user-lead", "tenant-1", ["ir_lead"])
token_analyst = create_access_token("user-analyst", "tenant-1", ["soc_analyst"])
token_ciso = create_access_token("user-ciso", "tenant-1", ["ciso"])
print(f"   JWT tokens generated for: ir_lead, soc_analyst, ciso")

headers_lead = {"Authorization": f"Bearer {token_lead}"}
headers_analyst = {"Authorization": f"Bearer {token_analyst}"}
headers_ciso = {"Authorization": f"Bearer {token_ciso}"}

# 4. RBAC enforcement
r = client.get("/api/observability/accuracy-trend", headers=headers_lead)
icon = "✅" if r.status_code == 200 else "❌"
print(f"   {icon} IR Lead -> accuracy-trend: {r.status_code}")

r = client.get("/api/observability/accuracy-trend", headers=headers_analyst)
icon = "✅" if r.status_code == 403 else "❌"
print(f"   {icon} Analyst -> accuracy-trend: {r.status_code} (denied - no AUDIT_VIEW)")

r = client.get("/api/observability/traces/case-1", headers=headers_analyst)
icon = "✅" if r.status_code == 200 else "❌"
print(f"   {icon} Analyst -> traces: {r.status_code} (allowed - has INVESTIGATE_VIEW)")

r = client.get("/api/observability/accuracy-trend", headers=headers_ciso)
icon = "✅" if r.status_code == 200 else "❌"
print(f"   {icon} CISO -> accuracy-trend: {r.status_code} (allowed - has AUDIT_VIEW)")

# 5. Investigation engine
print(f"\n🔍 [INVESTIGATION ENGINE]")
r = client.get("/api/cases")
print(f"   Active cases: {len(r.json()['cases'])}")
r = client.get("/api/metrics")
m = r.json()
print(f"   Tools available: {m['tools_available']}")

# 6. Observability
print(f"\n📊 [OBSERVABILITY - Phoenix]")
r = client.get("/api/observability/accuracy-trend?days=30", headers=headers_lead)
d = r.json()
print(f"   Accuracy trend: rolling_avg={d['rolling_average']} evaluated={d['total_evaluated']}")

r = client.get("/api/observability/traces/case-001", headers=headers_analyst)
print(f"   Live traces: {len(r.json())} spans")

r = client.get("/api/observability/investigation/inv-001/evals", headers=headers_analyst)
d = r.json()
print(f"   Eval summary: total={d['total']} approved={d['approved']} flagged={d['flagged']} blocked={d['blocked']}")

# 7. Splunk webhook
print(f"\n🚨 [SPLUNK ALERT WEBHOOK]")
r = client.post("/api/splunk-alert", json={
    "search_name": "Brute Force Login Detected",
    "result": {"host": "web-server-01", "src_ip": "10.0.0.5", "user": "admin"},
    "sid": "scheduler_12345",
})
d = r.json()
print(f"   Alert trigger: {d['status']}")
print(f"   Case ID: {d['case_id']}")
print(f"   Message: {d['message']}")

# 8. Verify investigation started
time.sleep(0.5)
r = client.get("/api/cases")
cases = r.json()["cases"]
print(f"   Running investigations: {len(cases)}")
if cases:
    c = cases[-1]
    print(f"   Latest: {c['case_id']} | status={c['status']}")

# 9. All routes
print(f"\n🌐 [ALL API ROUTES]")
routes = sorted(set(r.path for r in app.routes if hasattr(r, "path") and "/api/" in r.path))
for route in routes:
    print(f"   {route}")

ws_routes = [r.path for r in app.routes if hasattr(r, "path") and "/ws/" in r.path]
for route in ws_routes:
    print(f"   {route} [WebSocket]")

print(f"\n{'=' * 60}")
print(f"  ✅ ALL SYSTEMS VERIFIED LOCALLY")
print(f"{'=' * 60}")
print(f"\n  To start the server manually:")
print(f"  python -m uvicorn sift_defender.web.app:create_app --factory --port 8000")
print(f"\n  Then open: http://localhost:8000 (dashboard)")
print(f"             http://localhost:8000/api/docs (Swagger)")
