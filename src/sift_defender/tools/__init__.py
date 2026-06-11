"""Forensic tool wrappers — type-safe functions calling SIFT Workstation tools.

All tools:
- Use subprocess.run(shell=False) — no shell injection possible
- Validate paths against evidence mount point — no traversal
- Return structured JSON with audit_id — full traceability
- Include forensic caveats — prevent misinterpretation
- Paginate large outputs — prevent context overflow
- Never write to evidence — read-only enforcement
"""
