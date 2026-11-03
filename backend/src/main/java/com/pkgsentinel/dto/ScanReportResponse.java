package com.pkgsentinel.dto;

import com.pkgsentinel.entity.enums.ScanStatus;
import com.pkgsentinel.entity.enums.Verdict;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record ScanReportResponse(
    UUID jobId,
    String ecosystem,
    String name,
    String version,
    ScanStatus status,
    Verdict verdict,
    BigDecimal riskScore,
    BigDecimal confidenceScore,
    String summaryNotes,
    Instant analyzedAt,
    List<FindingItem> findings
) {
    public record FindingItem(
        String moduleName,
        String ruleId,
        String severity,
        BigDecimal confidence,
        String title,
        String description,
        String filePath,
        Integer lineNumber,
        String codeSnippet
    ) {}
}
