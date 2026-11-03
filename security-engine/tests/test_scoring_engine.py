"""
Comprehensive unit tests for Module G: Risk Scoring Engine.
Tests all severity weights, asymptotic curves, verdict overrides, deduplication, and obfuscation ceilings.
"""

import pytest
from engine.schemas.finding import SecurityFinding, Severity, FindingCategory
from engine.schemas.verdict import Verdict
from engine.detection.scoring_engine import RiskScoringEngine, deduplicate_findings


def test_severity_weights_and_asymptotic_curve():
    scorer = RiskScoringEngine()

    # 1. Single LOW finding (W=3, conf=1.0 -> S_raw=3.0)
    f_low = SecurityFinding(
        module="TEST", rule_id="R_LOW", category=FindingCategory.METADATA,
        severity=Severity.LOW, confidence=1.0, title="Low", description="Low finding"
    )
    rep_low = scorer.compute_verdict("job-1", [f_low], {"METADATA": "COMPLETED"})
    # S_norm = 100 * (1 - e^(-3/45)) = 100 * (1 - 0.9355) = 6.4
    assert rep_low.risk_score == pytest.approx(6.4, 0.2)
    assert rep_low.verdict == Verdict.SAFE

    # 2. Single MEDIUM finding (W=10, conf=1.0 -> S_raw=10.0)
    f_med = SecurityFinding(
        module="TEST", rule_id="R_MED", category=FindingCategory.STATIC_CODE,
        severity=Severity.MEDIUM, confidence=1.0, title="Med", description="Med finding"
    )
    rep_med = scorer.compute_verdict("job-2", [f_med], {"STATIC_CODE": "COMPLETED"})
    # S_norm = 100 * (1 - e^(-10/45)) = 100 * (1 - 0.8007) = 19.9
    assert rep_med.risk_score == pytest.approx(19.9, 0.2)
    assert rep_med.verdict == Verdict.SAFE

    # 3. Single HIGH finding (W=25, conf=0.9 -> S_raw=22.5)
    f_high = SecurityFinding(
        module="TEST", rule_id="R_HIGH", category=FindingCategory.STATIC_CODE,
        severity=Severity.HIGH, confidence=0.9, title="High", description="High finding"
    )
    rep_high = scorer.compute_verdict("job-3", [f_high], {"STATIC_CODE": "COMPLETED"})
    # S_norm = 100 * (1 - e^(-22.5/45)) = 100 * (1 - e^(-0.5)) = 39.3
    assert rep_high.risk_score == pytest.approx(39.3, 0.2)
    assert rep_high.verdict == Verdict.SUSPICIOUS  # Score >= 30 threshold


def test_critical_finding_override():
    scorer = RiskScoringEngine()
    # A single CRITICAL finding with confidence 0.85 must trigger MALICIOUS even if S_norm is below 70
    f_crit = SecurityFinding(
        module="TEST", rule_id="R_CRIT", category=FindingCategory.DYNAMIC_EXECUTION,
        severity=Severity.CRITICAL, confidence=0.85, title="C2 Exfiltration", description="Exfiltration intercepted"
    )
    # S_raw = 50 * 0.85 = 42.5 -> S_norm = 100 * (1 - e^(-42.5/45)) = 61.1 (which is < 70)
    rep = scorer.compute_verdict("job-crit", [f_crit], {"DYNAMIC": "COMPLETED"})
    assert rep.risk_score == pytest.approx(61.1, 0.2)
    assert rep.verdict == Verdict.MALICIOUS  # Override triggered!
    assert any("Critical Override" in r for r in rep.verdict_reasons)


def test_multi_vector_independent_high_findings():
    scorer = RiskScoringEngine()
    # Two independent HIGH findings from distinct categories
    f1 = SecurityFinding(
        module="TYPOSQUATTING", rule_id="TYPO_DIST_1", category=FindingCategory.TYPOSQUATTING,
        severity=Severity.HIGH, confidence=0.85, title="Typosquat", description="Near lodash"
    )
    f2 = SecurityFinding(
        module="STATIC_AST", rule_id="PY_SUBPROCESS", category=FindingCategory.STATIC_CODE,
        severity=Severity.HIGH, confidence=0.85, title="Shell Exec", description="os.system"
    )
    # S_raw = (25 * 0.85) + (25 * 0.85) = 42.5 -> S_norm = 61.1 (< 70)
    # Multi-Vector rule triggers MALICIOUS!
    rep = scorer.compute_verdict("job-mv", [f1, f2], {"TYPO": "COMPLETED", "AST": "COMPLETED"})
    assert rep.verdict == Verdict.MALICIOUS
    assert any("Multi-Vector Threat" in r for r in rep.verdict_reasons)


def test_obfuscation_only_score_ceiling():
    scorer = RiskScoringEngine()
    # Accumulate 4 separate OBFUSCATION findings across different files to push S_norm >= 70
    f_obf1 = SecurityFinding(
        module="ENTROPY", rule_id="OBF_1", category=FindingCategory.OBFUSCATION,
        severity=Severity.HIGH, confidence=1.0, title="Entropy 1", description="File 1", affected_file="a.js"
    )
    f_obf2 = SecurityFinding(
        module="ENTROPY", rule_id="OBF_2", category=FindingCategory.OBFUSCATION,
        severity=Severity.HIGH, confidence=1.0, title="Entropy 2", description="File 2", affected_file="b.js"
    )
    f_obf3 = SecurityFinding(
        module="ENTROPY", rule_id="OBF_3", category=FindingCategory.OBFUSCATION,
        severity=Severity.HIGH, confidence=1.0, title="Entropy 3", description="File 3", affected_file="c.js"
    )
    # Total S_raw = 25 + 25 + 25 = 75.0 -> S_norm = 100 * (1 - e^(-75/45)) = 81.1
    rep = scorer.compute_verdict("job-obf", [f_obf1, f_obf2, f_obf3], {"ENTROPY": "COMPLETED"})
    assert rep.risk_score >= 70.0
    # Obfuscation ceiling prevents MALICIOUS verdict! Capped at SUSPICIOUS.
    assert rep.verdict == Verdict.SUSPICIOUS
    assert any("Obfuscation Ceiling Applied" in r for r in rep.verdict_reasons)


def test_finding_deduplication():
    # Two findings on the same file in the same category
    f_low = SecurityFinding(
        module="STATIC", rule_id="R_LOW", category=FindingCategory.STATIC_CODE,
        severity=Severity.LOW, confidence=0.5, title="Low finding", description="Low", affected_file="app.py"
    )
    f_high = SecurityFinding(
        module="STATIC", rule_id="R_HIGH", category=FindingCategory.STATIC_CODE,
        severity=Severity.HIGH, confidence=0.9, title="High finding", description="High", affected_file="app.py",
        evidence={"sensitive": "eval"}
    )
    deduped = deduplicate_findings([f_low, f_high])
    assert len(deduped) == 1
    # Preserves highest severity finding and its original evidence intact
    assert deduped[0].rule_id == "R_HIGH"
    assert deduped[0].evidence == {"sensitive": "eval"}
    assert deduped[0].confidence == 0.9


def test_empty_findings_and_incomplete_coverage():
    scorer = RiskScoringEngine()
    # Clean package with 100% complete coverage
    rep_clean = scorer.compute_verdict("job-clean", [], {"AST": "COMPLETED", "META": "COMPLETED"})
    assert rep_clean.verdict == Verdict.SAFE
    assert rep_clean.risk_score == 0.0
    assert rep_clean.confidence_score == 0.85  # Reflects analysis coverage, NOT false 1.0!

    # Clean package with a failed module
    rep_degraded = scorer.compute_verdict("job-fail", [], {"AST": "FAILED: SyntaxError", "META": "COMPLETED"})
    assert rep_degraded.verdict == Verdict.SAFE
    assert rep_degraded.confidence_score == 0.60  # Reduced due to incomplete coverage

