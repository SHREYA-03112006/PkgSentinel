"""
Module G — Explainable Risk Scoring Engine
Implements the v2.1 decoupled scoring model with explicit override rules,
deduplication, confidence weighting, and obfuscation-only ceiling.
"""

import math
from typing import List, Dict, Tuple, Set
from collections import defaultdict

from engine.schemas.finding import SecurityFinding, Severity, FindingCategory
from engine.schemas.verdict import Verdict, AnalysisVerdictReport

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 50.0,
    Severity.HIGH: 25.0,
    Severity.MEDIUM: 10.0,
    Severity.LOW: 3.0,
}

DIMINISHING_RETURNS = [1.0, 0.35, 0.15, 0.05, 0.02, 0.0]


def get_diminishing_multiplier(occurrence_index: int) -> float:
    """
    Returns non-linear diminishing factor based on repeat occurrences of the same rule.
    Prevents benign patterns replicated across many files from inflating risk score.
    Saturates after 5 occurrences to prevent unbounded accumulation.
    """
    if occurrence_index < len(DIMINISHING_RETURNS):
        return DIMINISHING_RETURNS[occurrence_index]
    return 0.0


def deduplicate_findings(findings: List[SecurityFinding]) -> List[SecurityFinding]:
    """
    Deduplicates findings by (category, affected_file).
    Preserves the finding with the highest severity weight (and highest confidence as tie-breaker)
    WITHOUT fabricating or merging fields from different records.
    """
    if not findings:
        return []

    clusters: Dict[Tuple[str, str], List[SecurityFinding]] = defaultdict(list)
    for f in findings:
        key = (f.category.value, f.affected_file or "global")
        clusters[key].append(f)

    deduped: List[SecurityFinding] = []
    for cluster in clusters.values():
        best_finding = max(
            cluster,
            key=lambda x: (SEVERITY_WEIGHTS[x.severity], x.confidence)
        )
        deduped.append(best_finding)

    # Sort deterministically by severity weight descending, then confidence descending
    deduped.sort(key=lambda x: (SEVERITY_WEIGHTS[x.severity], x.confidence), reverse=True)
    return deduped


class RiskScoringEngine:
    """
    Calculates deterministic risk scores, evaluates categorical verdicts,
    and produces explainable evidence attribution.
    """

    def compute_verdict(
        self,
        job_id: str,
        raw_findings: List[SecurityFinding],
        analysis_coverage: Dict[str, str],
        execution_duration_ms: int = 0,
    ) -> AnalysisVerdictReport:
        # 1. Deduplicate findings cleanly
        deduped = deduplicate_findings(raw_findings)

        # 2. Compute Raw and Normalized Scores with Rule-Level Diminishing Returns
        raw_score = 0.0
        total_weight = 0.0
        weighted_conf_sum = 0.0
        categories_present: Set[str] = set()
        rule_counts: Dict[str, int] = defaultdict(int)

        for f in deduped:
            idx = rule_counts[f.rule_id]
            rule_counts[f.rule_id] += 1
            multiplier = get_diminishing_multiplier(idx)

            effective_weight = SEVERITY_WEIGHTS[f.severity] * multiplier
            raw_score += effective_weight * f.confidence
            total_weight += effective_weight
            weighted_conf_sum += effective_weight * f.confidence
            categories_present.add(f.category.value)

        # Normalized asymptotic curve: S_norm = 100 * (1 - e^(-S_raw / 45))
        norm_score = round(100.0 * (1.0 - math.exp(-raw_score / 45.0)), 1) if raw_score > 0 else 0.0

        # 3. Overall Confidence Calculation
        if deduped:
            confidence = round(weighted_conf_sum / total_weight, 2)
        else:
            # When clean, confidence reflects analysis coverage rather than assuming 1.0
            failed_modules = [m for m, st in analysis_coverage.items() if st != "COMPLETED"]
            confidence = 0.85 if not failed_modules else 0.60

        # 4. Verdict Evaluation Matrix & Override Rules
        verdict = Verdict.SAFE
        verdict_reasons: List[str] = []

        # Rule 1: Confirmed CRITICAL override
        critical_overrides = [
            f for f in deduped if f.severity == Severity.CRITICAL and f.confidence >= 0.85
        ]
        if critical_overrides:
            verdict = Verdict.MALICIOUS
            for c in critical_overrides:
                verdict_reasons.append(f"Critical Override ({c.rule_id}): {c.title}")

        # Rule 2: Multi-Vector Independent HIGH findings (>=2 distinct categories with conf >= 0.70)
        high_findings = [
            f for f in deduped if f.severity == Severity.HIGH and f.confidence >= 0.70
        ]
        high_categories = {f.category.value for f in high_findings}
        if len(high_findings) >= 2 and len(high_categories) >= 2 and verdict != Verdict.MALICIOUS:
            verdict = Verdict.MALICIOUS
            verdict_reasons.append(
                f"Multi-Vector Threat: {len(high_findings)} independent HIGH severity findings across {len(high_categories)} categories ({', '.join(sorted(high_categories))})"
            )

        # Rule 3: Score >= 70 threshold with Obfuscation-Only and High-Confidence Threat Requirements
        if verdict != Verdict.MALICIOUS:
            if norm_score >= 70.0:
                is_obfuscation_only = bool(categories_present and categories_present.issubset({"OBFUSCATION"}))
                has_high_confidence_threat = any(
                    f.severity in (Severity.CRITICAL, Severity.HIGH) and f.confidence >= 0.75
                    for f in deduped
                )

                if is_obfuscation_only:
                    verdict = Verdict.SUSPICIOUS
                    verdict_reasons.append(
                        f"Obfuscation Ceiling Applied: Risk score is {norm_score}, but findings consist exclusively of obfuscation/entropy. Capped at SUSPICIOUS per safety rubric."
                    )
                elif not has_high_confidence_threat:
                    # Cumulative lower-severity findings without a confirmed HIGH/CRITICAL threat are capped at SUSPICIOUS
                    verdict = Verdict.SUSPICIOUS
                    verdict_reasons.append(
                        f"Threat Confidence Ceiling Applied: Risk score is {norm_score}, but findings lack a confirmed HIGH/CRITICAL threat. Capped at SUSPICIOUS."
                    )
                else:
                    verdict = Verdict.MALICIOUS
                    verdict_reasons.append(f"High Composite Risk: Normalized risk score ({norm_score}) exceeds threshold 70.0.")

            # Rule 4: Score >= 30 threshold
            elif norm_score >= 30.0:
                verdict = Verdict.SUSPICIOUS
                verdict_reasons.append(f"Elevated Risk: Normalized risk score ({norm_score}) exceeds threshold 30.0.")

            # Rule 5: Benign
            else:
                verdict = Verdict.SAFE
                verdict_reasons.append("Clean Bill of Health: No high-risk anomalies or malicious indicators detected.")

        summary_notes = " | ".join(verdict_reasons)

        return AnalysisVerdictReport(
            job_id=job_id,
            status="SUCCESS",
            verdict=verdict,
            risk_score=norm_score,
            raw_score=round(raw_score, 2),
            confidence_score=confidence,
            summary_notes=summary_notes,
            execution_duration_ms=execution_duration_ms,
            verdict_reasons=verdict_reasons,
            analysis_coverage=analysis_coverage,
            findings=deduped,
        )
