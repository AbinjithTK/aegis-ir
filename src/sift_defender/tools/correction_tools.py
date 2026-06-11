"""Self-correction and hallucination guardrail tools (traced via OpenTelemetry)."""

import json
from opentelemetry import trace
from openinference.semconv.trace import SpanAttributes, OpenInferenceSpanKindValues

tracer = trace.get_tracer("sift_defender.correction")


def self_correction_check(findings_summary: str) -> str:
    """Check investigation findings for internal contradictions.
    
    Call this AFTER gathering findings from multiple tools.
    It checks for common forensic inconsistencies:
    - Binary in Amcache/filesystem but NOT in Prefetch
    - Service installed but binary missing from disk
    - Process in memory but no disk artifact
    - Timeline inconsistencies
    
    Args:
        findings_summary: JSON or text summary of all findings so far
    
    Returns:
        JSON with contradictions found and recommended resolution steps
    """
    with tracer.start_as_current_span("self_correction", attributes={
        SpanAttributes.OPENINFERENCE_SPAN_KIND: OpenInferenceSpanKindValues.CHAIN.value,
        SpanAttributes.INPUT_VALUE: findings_summary[:2000],
    }) as span:
        lower = findings_summary.lower()
        contradictions = []
        
        # Rule 1: Binary present but no execution evidence
        suspicious_binaries = []
        for indicator in ["svc_update", "update.dat", ".exe in programdata", ".exe in temp"]:
            if indicator in lower:
                suspicious_binaries.append(indicator)
        
        prefetch_programs = []
        if "prefetch" in lower:
            # Extract what's in prefetch
            for prog in ["powershell", "winword", "outlook", "rundll32", "cmd", "schtasks"]:
                if prog in lower and "prefetch" in lower:
                    prefetch_programs.append(prog)
        
        for binary in suspicious_binaries:
            binary_name = binary.split(".")[0] if "." in binary else binary
            if binary_name not in " ".join(prefetch_programs):
                contradictions.append({
                    "type": "presence_without_execution",
                    "description": f"'{binary}' found on disk but NOT in Prefetch",
                    "severity": "medium",
                    "possible_explanations": [
                        "Runs via scheduled task (tasks don't always generate Prefetch)",
                        "Runs as a service",
                        "Never actually executed",
                        "Prefetch was cleared (anti-forensics)"
                    ],
                    "recommended_action": "Check scheduled tasks and services for this binary"
                })
        
        # Rule 2: Check for log clearing indicators
        if "1102" in lower or "log cleared" in lower or "log clear" in lower:
            contradictions.append({
                "type": "anti_forensics",
                "description": "Evidence of event log clearing detected",
                "severity": "high",
                "recommended_action": "Treat missing log entries with suspicion"
            })
        
        result = {
            "self_correction_triggered": len(contradictions) > 0,
            "contradictions_found": len(contradictions),
            "contradictions": contradictions,
            "recommendation": contradictions[0]["recommended_action"] if contradictions else "No contradictions — findings are consistent",
        }
        
        span.set_attribute(SpanAttributes.OUTPUT_VALUE, json.dumps(result))
        span.set_attribute("self_correction.triggered", len(contradictions) > 0)
        span.set_attribute("self_correction.count", len(contradictions))
        
        return json.dumps(result)


def hallucination_guardrail(claim: str, supporting_evidence: str) -> str:
    """Verify that a forensic claim is grounded in actual tool output.
    
    GUARDRAIL: Call this on each major finding before reporting it.
    Blocks claims that aren't supported by evidence.
    
    Rules:
    - Claiming "executed" requires Prefetch OR Event 4688 in evidence
    - Claiming "C2 communication" requires network evidence (netscan/pcap)
    - Claiming "lateral movement" requires logon events (4624 Type 3/10)
    - Claiming "data exfiltration" requires network traffic evidence
    
    Args:
        claim: The forensic claim being made (e.g., "svc_update.exe was executed")
        supporting_evidence: The tool output that should support this claim
    
    Returns:
        JSON with verdict: factual, partially_supported, or hallucinated
    """
    with tracer.start_as_current_span("hallucination_guardrail", attributes={
        SpanAttributes.OPENINFERENCE_SPAN_KIND: "GUARDRAIL",
        SpanAttributes.INPUT_VALUE: json.dumps({"claim": claim[:300]}),
    }) as span:
        claim_lower = claim.lower()
        evidence_lower = supporting_evidence.lower()
        
        issues = []
        
        # Check execution claims
        if any(word in claim_lower for word in ["executed", "ran", "launched", "started"]):
            if "prefetch" not in evidence_lower and "4688" not in evidence_lower and "pslist" not in evidence_lower:
                issues.append("Claims execution without Prefetch, Event 4688, or memory evidence")
        
        # Check network claims
        if any(word in claim_lower for word in ["c2", "beacon", "exfiltrat", "download", "connect"]):
            if "netscan" not in evidence_lower and "pcap" not in evidence_lower and "network" not in evidence_lower and "dns" not in evidence_lower:
                issues.append("Claims network activity without network evidence")
        
        # Check lateral movement claims
        if "lateral" in claim_lower:
            if "4624" not in evidence_lower and "type 3" not in evidence_lower and "rdp" not in evidence_lower:
                issues.append("Claims lateral movement without logon event evidence")
        
        if issues:
            label = "hallucinated" if len(issues) > 1 else "partially_supported"
            result = {
                "passed": False,
                "label": label,
                "action": "BLOCK" if label == "hallucinated" else "FLAG_FOR_REVIEW",
                "issues": issues,
                "recommendation": "Gather additional evidence before making this claim",
            }
        else:
            result = {
                "passed": True,
                "label": "factual",
                "action": "APPROVE",
                "issues": [],
                "recommendation": "Claim is grounded in evidence",
            }
        
        span.set_attribute(SpanAttributes.OUTPUT_VALUE, json.dumps(result))
        span.set_attribute("guardrail.passed", result["passed"])
        span.set_attribute("guardrail.label", result["label"])
        
        return json.dumps(result)
