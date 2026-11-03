package com.pkgsentinel.dto;

import com.pkgsentinel.entity.enums.ScanStatus;
import com.pkgsentinel.entity.enums.Verdict;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public record ScanReportResponse(
    UUID jobId,
    String ecosystem,
    String name,
    String version,
    ScanStatus status,
    Verdict verdict,
    BigDecimal riskScore,
    BigDecimal rawScore,
    BigDecimal confidenceScore,
    String summaryNotes,
    List<String> verdictReasons,
    Map<String, String> analysisCoverage,
    Instant analyzedAt,
    Instant createdAt,
    Instant completedAt,
    String failureReason,
    List<FindingItem> findings
) {
    public record FindingItem(
        String findingId,
        String moduleName,
        String ruleId,
        String category,
        String severity,
        BigDecimal confidence,
        String title,
        String description,
        String filePath,
        Integer lineNumber,
        String codeSnippet,
        String detectionMethod
    ) {}
}
