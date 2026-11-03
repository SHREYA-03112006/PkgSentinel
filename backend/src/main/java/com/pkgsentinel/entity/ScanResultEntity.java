package com.pkgsentinel.entity;

import com.pkgsentinel.entity.enums.Verdict;
import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
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

    @Column(name = "confidence_score", nullable = false, precision = 4, scale = 3)
    private BigDecimal confidenceScore;

    @Column(name = "summary_notes", columnDefinition = "TEXT")
    private String summaryNotes;

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

    public BigDecimal getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(BigDecimal confidenceScore) { this.confidenceScore = confidenceScore; }

    public String getSummaryNotes() { return summaryNotes; }
    public void setSummaryNotes(String summaryNotes) { this.summaryNotes = summaryNotes; }

    public Instant getAnalyzedAt() { return analyzedAt; }
    public void setAnalyzedAt(Instant analyzedAt) { this.analyzedAt = analyzedAt; }

    public List<ModuleFindingEntity> getFindings() { return findings; }
    public void setFindings(List<ModuleFindingEntity> findings) { this.findings = findings; }
}
