"""Reporting tools — generate investigation reports."""

import json
from datetime import datetime, timezone

from sift_defender.tools.base import format_tool_response, generate_audit_id


def generate_executive_summary(findings: str, timeline: str) -> str:
    """Generate executive summary of the investigation.
    
    Args:
        findings: JSON string of confirmed findings.
        timeline: JSON string of attack timeline.
    
    Returns: Formatted executive summary.
    """
    audit_id = generate_audit_id("exec_summary")
    # The LLM will use this tool's output as the basis for the summary
    return format_tool_response(
        audit_id=audit_id,
        tool_name="generate_executive_summary",
        data={"template": "executive_summary", "findings": findings, "timeline": timeline},
    )


def generate_technical_report(findings: str, evidence_refs: str) -> str:
    """Generate detailed technical report with evidence references.
    
    Args:
        findings: JSON string of all findings with confidence scores.
        evidence_refs: JSON string of audit_ids mapping to tool outputs.
    
    Returns: Technical report data.
    """
    audit_id = generate_audit_id("tech_report")
    return format_tool_response(
        audit_id=audit_id,
        tool_name="generate_technical_report",
        data={"template": "technical_report", "findings": findings, "evidence_refs": evidence_refs},
    )


def generate_timeline_report(findings: str) -> str:
    """Generate chronological attack timeline.
    
    Args:
        findings: JSON string of findings with timestamps.
    
    Returns: Ordered timeline events.
    """
    audit_id = generate_audit_id("timeline_report")
    return format_tool_response(
        audit_id=audit_id,
        tool_name="generate_timeline_report",
        data={"template": "timeline_report", "findings": findings},
    )


def generate_ioc_report(iocs: str) -> str:
    """Generate actionable IOC report for blocking.
    
    Args:
        iocs: JSON string of extracted IOCs.
    
    Returns: Formatted IOC report ready for SOC/SIEM integration.
    """
    audit_id = generate_audit_id("ioc_report")
    return format_tool_response(
        audit_id=audit_id,
        tool_name="generate_ioc_report",
        data={"template": "ioc_report", "iocs": iocs},
    )
