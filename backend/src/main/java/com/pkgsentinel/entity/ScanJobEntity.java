package com.pkgsentinel.entity;

import com.pkgsentinel.entity.enums.Ecosystem;
import com.pkgsentinel.entity.enums.ScanDepth;
import com.pkgsentinel.entity.enums.ScanStatus;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "scan_jobs")
public class ScanJobEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "package_version_id")
    private PackageVersionEntity packageVersion;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private Ecosystem ecosystem;

    @Column(name = "package_name", nullable = false)
    private String packageName;

    @Column(name = "package_version", nullable = false, length = 128)
    private String version;

    @Enumerated(EnumType.STRING)
    @Column(name = "scan_depth", nullable = false, length = 32)
    private ScanDepth scanDepth = ScanDepth.FAST;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private ScanStatus status = ScanStatus.QUEUED;

    @Column(name = "triggered_by", nullable = false, length = 64)
    private String triggeredBy = "API";

    @Column(name = "retry_count", nullable = false)
    private int retryCount = 0;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "failure_reason", columnDefinition = "TEXT")
    private String failureReason;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public ScanJobEntity() {}

    public ScanJobEntity(Ecosystem ecosystem, String packageName, String version, ScanDepth scanDepth, String triggeredBy) {
        this.ecosystem = ecosystem;
        this.packageName = packageName;
        this.version = version;
        this.scanDepth = scanDepth;
        this.triggeredBy = triggeredBy;
        this.status = ScanStatus.QUEUED;
        this.createdAt = Instant.now();
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public PackageVersionEntity getPackageVersion() { return packageVersion; }
    public void setPackageVersion(PackageVersionEntity packageVersion) { this.packageVersion = packageVersion; }

    public Ecosystem getEcosystem() { return ecosystem; }
    public void setEcosystem(Ecosystem ecosystem) { this.ecosystem = ecosystem; }

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public ScanDepth getScanDepth() { return scanDepth; }
    public void setScanDepth(ScanDepth scanDepth) { this.scanDepth = scanDepth; }

    public ScanStatus getStatus() { return status; }
    public void setStatus(ScanStatus status) { this.status = status; }

    public String getTriggeredBy() { return triggeredBy; }
    public void setTriggeredBy(String triggeredBy) { this.triggeredBy = triggeredBy; }

    public int getRetryCount() { return retryCount; }
    public void setRetryCount(int retryCount) { this.retryCount = retryCount; }

    public Instant getStartedAt() { return startedAt; }
    public void setStartedAt(Instant startedAt) { this.startedAt = startedAt; }

    public Instant getCompletedAt() { return completedAt; }
    public void setCompletedAt(Instant completedAt) { this.completedAt = completedAt; }

    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String failureReason) { this.failureReason = failureReason; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
