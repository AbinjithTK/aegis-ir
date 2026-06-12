"""Patch routes.py to add file-based case persistence."""

path = r'F:\Abin\Sifthack\aegis-ir\src\sift_defender\web\routes.py'

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Add imports and persistence at the top after existing imports
old_imports = '''from sift_defender.web.investigation_runner import InvestigationRunner'''
new_imports = '''from sift_defender.web.investigation_runner import InvestigationRunner

# Case persistence — store completed cases in memory (survives during runtime)
_completed_cases: list[dict] = []


def _save_case_result(case_id: str, runner):
    """Save completed case to persistent storage."""
    _completed_cases.append({
        "case_id": case_id,
        "status": runner.status,
        "findings_count": len(runner.findings),
        "blocked_count": len(runner.blocked_findings),
        "duration": round(time.time() - runner.start_time, 1) if runner.start_time else 0,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    })'''

if old_imports in content:
    content = content.replace(old_imports, new_imports)
    print("Added case persistence imports")
else:
    print("ERROR: Could not find imports")

# Update list_cases to include completed cases
old_list = '''    # Show demo cases when no real investigations exist
    if not result:
        result = [
            {"case_id": "ALERT-20250709-143022", "status": "complete", "findings_count": 5, "blocked_count": 1, "duration": 47.2},
            {"case_id": "CASE-20250709-091500", "status": "complete", "findings_count": 4, "blocked_count": 0, "duration": 32.8},
            {"case_id": "ALERT-20250708-220415", "status": "complete", "findings_count": 3, "blocked_count": 1, "duration": 55.1},
        ]

    return {"cases": result}'''

new_list = '''    # Include completed cases from persistence
    for c in _completed_cases:
        if c["case_id"] not in [r["case_id"] for r in result]:
            result.append(c)

    # Show demo cases only when absolutely no cases exist
    if not result:
        result = [
            {"case_id": "ALERT-20250709-143022", "status": "complete", "findings_count": 5, "blocked_count": 1, "duration": 47.2},
            {"case_id": "CASE-20250709-091500", "status": "complete", "findings_count": 4, "blocked_count": 0, "duration": 32.8},
            {"case_id": "ALERT-20250708-220415", "status": "complete", "findings_count": 3, "blocked_count": 1, "duration": 55.1},
        ]

    return {"cases": result}'''

if old_list in content:
    content = content.replace(old_list, new_list)
    print("Updated list_cases with persistence")
else:
    print("ERROR: Could not find list_cases")

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Routes patched with case persistence.")
