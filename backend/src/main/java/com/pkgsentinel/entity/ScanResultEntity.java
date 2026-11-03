package com.pkgsentinel.entity;

import com.pkgsentinel.entity.enums.Verdict;
import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "scan_results", uniqueConstraints = {
    @UniqueConstraint(name = "uq_scan_results_job", columnNames = {"scan_job_id"})
})
public class ScanResultEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_job_id", nullable = false)
    private ScanJobEntity scanJob;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private Verdict verdict;

    @Column(name = "risk_score", nullable = false, precision = 5, scale = 2)
    private BigDecimal riskScore;

    @Column(name = "raw_score", precision = 5, scale = 2)
    private BigDecimal rawScore = BigDecimal.ZERO;

    @Column(name = "confidence_score", nullable = false, precision = 4, scale = 3)
    private BigDecimal confidenceScore;

    @Column(name = "summary_notes", columnDefinition = "TEXT")
    private String summaryNotes;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "analysis_coverage", columnDefinition = "jsonb")
    private Map<String, String> analysisCoverage = new HashMap<>();

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "verdict_reasons", columnDefinition = "jsonb")
    private List<String> verdictReasons = new ArrayList<>();

    @Column(name = "analyzed_at", nullable = false, updatable = false)
    private Instant analyzedAt = Instant.now();

    @OneToMany(mappedBy = "scanResult", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ModuleFindingEntity> findings = new ArrayList<>();

    public ScanResultEntity() {}

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public ScanJobEntity getScanJob() { return scanJob; }
    public void setScanJob(ScanJobEntity scanJob) { this.scanJob = scanJob; }

    public Verdict getVerdict() { return verdict; }
    public void setVerdict(Verdict verdict) { this.verdict = verdict; }

    public BigDecimal getRiskScore() { return riskScore; }
    public void setRiskScore(BigDecimal riskScore) { this.riskScore = riskScore; }

    public BigDecimal getRawScore() { return rawScore; }
    public void setRawScore(BigDecimal rawScore) { this.rawScore = rawScore; }

    public BigDecimal getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(BigDecimal confidenceScore) { this.confidenceScore = confidenceScore; }

    public String getSummaryNotes() { return summaryNotes; }
    public void setSummaryNotes(String summaryNotes) { this.summaryNotes = summaryNotes; }

    public Map<String, String> getAnalysisCoverage() {
        return analysisCoverage != null ? analysisCoverage : new HashMap<>();
    }

    public void setAnalysisCoverage(Map<String, String> analysisCoverage) {
        this.analysisCoverage = analysisCoverage != null ? analysisCoverage : new HashMap<>();
    }

    public List<String> getVerdictReasons() {
        return verdictReasons != null ? verdictReasons : new ArrayList<>();
    }

    public void setVerdictReasons(List<String> verdictReasons) {
        this.verdictReasons = verdictReasons != null ? verdictReasons : new ArrayList<>();
    }

    public Instant getAnalyzedAt() { return analyzedAt; }
    public void setAnalyzedAt(Instant analyzedAt) { this.analyzedAt = analyzedAt; }

    public List<ModuleFindingEntity> getFindings() { return findings; }
    public void setFindings(List<ModuleFindingEntity> findings) { this.findings = findings; }
}
