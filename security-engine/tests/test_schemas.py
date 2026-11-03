import pytest
from engine.schemas import (
    SecurityFinding,
    Severity,
    FindingCategory,
    Verdict,
    AnalysisVerdictReport,
    ScanJobMessage,
    Ecosystem
)


def test_scan_job_message_deserialization():
    raw_payload = {
        "jobId": "123e4567-e89b-12d3-a456-426614174000",
        "ecosystem": "NPM",
        "name": "express",
        "version": "4.18.2",
        "scanDepth": "FAST"
    }
    msg = ScanJobMessage.model_validate(raw_payload)
    assert msg.job_id == "123e4567-e89b-12d3-a456-426614174000"
    assert msg.ecosystem == Ecosystem.NPM
    assert msg.name == "express"


def test_verdict_report_validation():
    finding = SecurityFinding(
        module="STATIC_ANALYSIS",
        rule_id="RULE_001",
        category=FindingCategory.STATIC_CODE,
        severity=Severity.HIGH,
        confidence=0.9,
        title="Suspicious eval call",
        description="Dynamic code execution detected."
    )
    report = AnalysisVerdictReport(
        job_id="123e4567-e89b-12d3-a456-426614174000",
        status="SUCCESS",
        verdict=Verdict.SUSPICIOUS,
        risk_score=42.5,
        confidence_score=0.9,
        summary_notes="Found dynamic execution patterns.",
        execution_duration_ms=120,
        findings=[finding]
    )
    assert report.verdict == Verdict.SUSPICIOUS
    assert len(report.findings) == 1
    assert report.findings[0].severity == Severity.HIGH

