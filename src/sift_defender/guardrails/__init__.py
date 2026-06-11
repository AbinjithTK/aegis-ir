"""Arize-powered hallucination guardrails.

Every finding passes through this layer before being presented to the user.
The guardrail checks:
1. Is the finding grounded in actual tool output? (Hallucination evaluator)
2. Were the correct tools called with valid parameters? (Tool calling evaluator)
3. Does the finding cite a real audit_id? (Deterministic code check)
"""
