package com.pkgsentinel.dto;

import com.pkgsentinel.entity.enums.Severity;
import com.pkgsentinel.entity.enums.Verdict;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public record ScanCallbackRequest(
    UUID jobId,
    String status,
    String resolvedVersion,
    Verdict verdict,
    BigDecimal riskScore,
    BigDecimal rawScore,
    BigDecimal confidenceScore,
    String summaryNotes,
    Integer executionDurationMs,
    List<String> verdictReasons,
    Map<String, String> analysisCoverage,
    List<CallbackFinding> findings,
    String failureReason
) {
    public record CallbackFinding(
        String findingId,
        String module,
        String ruleId,
        String category,
        Severity severity,
        BigDecimal confidence,
        String title,
        String description,
        String affectedFile,
        Integer affectedLine,
        String detectionMethod,
        Map<String, Object> evidence
    ) {}
}
