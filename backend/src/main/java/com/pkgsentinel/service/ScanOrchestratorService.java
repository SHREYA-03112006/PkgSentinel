package com.pkgsentinel.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pkgsentinel.dto.ScanCallbackRequest;
import com.pkgsentinel.dto.ScanJobResponse;
import com.pkgsentinel.dto.ScanReportResponse;
import com.pkgsentinel.dto.ScanRequest;
import com.pkgsentinel.entity.*;
import com.pkgsentinel.entity.enums.ScanStatus;
import com.pkgsentinel.entity.enums.Verdict;
import com.pkgsentinel.repository.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.*;

@Service
public class ScanOrchestratorService {

    private static final Logger log = LoggerFactory.getLogger(ScanOrchestratorService.class);

    private final ScanJobRepository scanJobRepository;
    private final PackageRepository packageRepository;
    private final PackageVersionRepository packageVersionRepository;
    private final ScanResultRepository scanResultRepository;
    private final OutboxEventRepository outboxEventRepository;
    private final RegistryUrlValidator registryUrlValidator;
    private final ObjectMapper objectMapper;

    @Value("${pkgsentinel.internal-token:sentinel-internal-secure-token-2026}")
    private String expectedInternalToken;

    public ScanOrchestratorService(
        ScanJobRepository scanJobRepository,
        PackageRepository packageRepository,
        PackageVersionRepository packageVersionRepository,
        ScanResultRepository scanResultRepository,
        OutboxEventRepository outboxEventRepository,
        RegistryUrlValidator registryUrlValidator
    ) {
        this.scanJobRepository = scanJobRepository;
        this.packageRepository = packageRepository;
        this.packageVersionRepository = packageVersionRepository;
        this.scanResultRepository = scanResultRepository;
        this.outboxEventRepository = outboxEventRepository;
        this.registryUrlValidator = registryUrlValidator;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Submits a package scan request reliably using the Transactional Outbox pattern.
     * Idempotently reuses existing active scan jobs for the same package coordinates.
     */
    @Transactional
    public ScanJobResponse submitScan(ScanRequest request, String triggeredBy) {
        if (!registryUrlValidator.isValidPackageIdentifier(request.ecosystem(), request.name())) {
            throw new IllegalArgumentException("Rejected package name format: " + request.name());
        }

        String targetVersion = request.versionOrDefault();

        // Idempotency: check if an active scan already exists for this exact coordinate
        Optional<ScanJobEntity> existingActiveJob = scanJobRepository
            .findFirstByEcosystemAndPackageNameAndVersionOrderByCreatedAtDesc(
                request.ecosystem(), request.name(), targetVersion
            );

        if (existingActiveJob.isPresent()) {
            ScanJobEntity active = existingActiveJob.get();
            if (active.getStatus() == ScanStatus.QUEUED || active.getStatus() == ScanStatus.PROCESSING) {
                log.info("Reusing existing active scan job {} for {}@{}", active.getId(), request.name(), targetVersion);
                return new ScanJobResponse(
                    active.getId(),
                    active.getEcosystem().name(),
                    active.getPackageName(),
                    active.getVersion(),
                    active.getStatus(),
                    "/api/v1/scans/" + active.getId(),
                    active.getCreatedAt()
                );
            }
        }

        PackageEntity pkg = packageRepository
            .findByEcosystemAndName(request.ecosystem(), request.name())
            .orElseGet(() -> packageRepository.save(new PackageEntity(request.ecosystem(), request.name())));

        PackageVersionEntity versionEntity = packageVersionRepository
            .findByPackageEntityIdAndVersionString(pkg.getId(), targetVersion)
            .orElseGet(() -> packageVersionRepository.save(new PackageVersionEntity(pkg, targetVersion)));

        // 1. Create ScanJob record in PostgreSQL
        ScanJobEntity job = new ScanJobEntity(
            request.ecosystem(),
            request.name(),
            targetVersion,
            request.depthOrDefault(),
            triggeredBy
        );
        job.setPackageVersion(versionEntity);
        job.setStatus(ScanStatus.QUEUED);
        job = scanJobRepository.save(job);

        // 2. Create OutboxEvent in the same database transaction
        Map<String, String> streamPayload = new HashMap<>();
        streamPayload.put("jobId", job.getId().toString());
        streamPayload.put("ecosystem", job.getEcosystem().name());
        streamPayload.put("name", job.getPackageName());
        streamPayload.put("version", job.getVersion());
        streamPayload.put("scanDepth", job.getScanDepth().name());
        streamPayload.put("enqueuedAt", Instant.now().toString());

        try {
            String payloadJson = objectMapper.writeValueAsString(streamPayload);
            OutboxEventEntity outboxEvent = new OutboxEventEntity(
                "SCAN_JOB",
                job.getId(),
                "SCAN_REQUESTED",
                payloadJson
            );
            outboxEventRepository.save(outboxEvent);
            log.info("Persisted ScanJob {} and OutboxEvent {} in database transaction", job.getId(), outboxEvent.getId());
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize outbox event payload", e);
        }

        return new ScanJobResponse(
            job.getId(),
            job.getEcosystem().name(),
            job.getPackageName(),
            job.getVersion(),
            job.getStatus(),
            "/api/v1/scans/" + job.getId(),
            job.getCreatedAt()
        );
    }

    /**
     * Atomically processes authenticated worker callbacks.
     * Strictly idempotent: duplicate callbacks do not recreate findings or corrupt status.
     */
    @Transactional
    public boolean handleWorkerCallback(UUID jobId, String authHeaderToken, ScanCallbackRequest callback) {
        // Authenticate shared worker secret
        if (expectedInternalToken == null || !expectedInternalToken.equals(authHeaderToken)) {
            log.warn("Unauthorized worker callback rejected for job {}: token mismatch", jobId);
            throw new SecurityException("Unauthorized internal worker callback token.");
        }

        ScanJobEntity job = scanJobRepository.findById(jobId)
            .orElseThrow(() -> new IllegalArgumentException("Scan job not found: " + jobId));

        // Idempotency guard: ignore duplicate callbacks on already completed/failed scans
        if (job.getStatus() == ScanStatus.COMPLETED || job.getStatus() == ScanStatus.FAILED) {
            log.info("Ignoring duplicate callback for already finalized job {} (status: {})", jobId, job.getStatus());
            return true;
        }

        if ("FAILED".equalsIgnoreCase(callback.status())) {
            job.setStatus(ScanStatus.FAILED);
            job.setFailureReason(callback.failureReason() != null ? callback.failureReason() : "Analysis execution failed.");
            job.setCompletedAt(Instant.now());
            scanJobRepository.save(job);
            log.info("Job {} marked FAILED via worker callback: {}", jobId, job.getFailureReason());
            return true;
        }

        // Handle SUCCESS: Persist findings and final verdict atomically
        job.setStatus(ScanStatus.COMPLETED);
        job.setCompletedAt(Instant.now());

        if (callback.resolvedVersion() != null && !callback.resolvedVersion().isBlank()) {
            String resolved = callback.resolvedVersion().trim();
            if ("latest".equalsIgnoreCase(job.getVersion()) || job.getVersion() == null || job.getVersion().isBlank()) {
                job.setVersion(resolved);
                PackageEntity pkg = packageRepository
                    .findByEcosystemAndName(job.getEcosystem(), job.getPackageName())
                    .orElse(null);
                if (pkg != null) {
                    PackageVersionEntity versionEntity = packageVersionRepository
                        .findByPackageEntityIdAndVersionString(pkg.getId(), resolved)
                        .orElseGet(() -> packageVersionRepository.save(new PackageVersionEntity(pkg, resolved)));
                    job.setPackageVersion(versionEntity);
                }
            }
        }

        ScanResultEntity result = scanResultRepository.findByScanJobId(job.getId())
            .orElseGet(() -> {
                ScanResultEntity r = new ScanResultEntity();
                r.setScanJob(job);
                return r;
            });

        result.setVerdict(callback.verdict() != null ? callback.verdict() : Verdict.SAFE);
        result.setRiskScore(callback.riskScore() != null ? callback.riskScore() : BigDecimal.ZERO);
        result.setRawScore(callback.rawScore() != null ? callback.rawScore() : BigDecimal.ZERO);
        result.setConfidenceScore(callback.confidenceScore() != null ? callback.confidenceScore() : BigDecimal.ONE);
        result.setSummaryNotes(callback.summaryNotes());
        result.setAnalyzedAt(Instant.now());

        if (callback.verdictReasons() != null) {
            result.setVerdictReasons(callback.verdictReasons());
        }
        if (callback.analysisCoverage() != null) {
            result.setAnalysisCoverage(callback.analysisCoverage());
        }

        // Attach findings
        result.getFindings().clear();
        if (callback.findings() != null) {
            for (ScanCallbackRequest.CallbackFinding cf : callback.findings()) {
                ModuleFindingEntity finding = new ModuleFindingEntity();
                finding.setScanResult(result);
                finding.setModuleName(cf.module() != null ? cf.module() : "ENGINE");
                finding.setRuleId(cf.ruleId() != null ? cf.ruleId() : "RULE");
                finding.setSeverity(cf.severity() != null ? cf.severity() : com.pkgsentinel.entity.enums.Severity.LOW);
                finding.setConfidence(cf.confidence() != null ? cf.confidence() : BigDecimal.ONE);
                finding.setTitle(cf.title());
                finding.setDescription(cf.description());
                finding.setFilePath(cf.affectedFile());
                finding.setLineNumber(cf.affectedLine());
                result.getFindings().add(finding);
            }
        }

        scanResultRepository.save(result);
        scanJobRepository.save(job);
        log.info("Successfully persisted analysis results and marked job {} COMPLETED (Verdict: {})", jobId, result.getVerdict());
        return true;
    }

    @Transactional(readOnly = true)
    public Optional<ScanJobEntity> getScanJob(UUID jobId) {
        return scanJobRepository.findById(jobId);
    }

    @Transactional(readOnly = true)
    public Optional<ScanReportResponse> getScanReport(UUID jobId) {
        return scanJobRepository.findById(jobId).map(this::mapToReportResponse);
    }

    @Transactional(readOnly = true)
    public Page<ScanReportResponse> getRecentScans(int page, int size) {
        return scanJobRepository.findAllByOrderByCreatedAtDesc(PageRequest.of(page, size))
            .map(this::mapToReportResponse);
    }

    @Transactional(readOnly = true)
    public Page<ScanReportResponse> getUserRecentScans(String username, int page, int size) {
        String actor = "USER:" + username;
        return scanJobRepository.findByTriggeredByOrderByCreatedAtDesc(actor, PageRequest.of(page, size))
            .map(this::mapToReportResponse);
    }

    private ScanReportResponse mapToReportResponse(ScanJobEntity job) {
        Optional<ScanResultEntity> resultOpt = scanResultRepository.findByScanJobId(job.getId());

        List<ScanReportResponse.FindingItem> findings = resultOpt.map(result ->
            result.getFindings().stream().map(f -> new ScanReportResponse.FindingItem(
                f.getId() != null ? f.getId().toString() : "",
                f.getModuleName(),
                f.getRuleId(),
                "SECURITY",
                f.getSeverity().name(),
                f.getConfidence(),
                f.getTitle(),
                f.getDescription(),
                f.getFilePath(),
                f.getLineNumber(),
                f.getCodeSnippet(),
                "HEURISTIC_AST"
            )).toList()
        ).orElse(Collections.emptyList());

        List<String> reasons = resultOpt.map(ScanResultEntity::getVerdictReasons).orElse(Collections.emptyList());
        Map<String, String> coverage = resultOpt.map(ScanResultEntity::getAnalysisCoverage).orElse(Collections.emptyMap());
        if (reasons == null) reasons = Collections.emptyList();
        if (coverage == null) coverage = Collections.emptyMap();

        return new ScanReportResponse(
            job.getId(),
            job.getEcosystem().name(),
            job.getPackageName(),
            job.getVersion(),
            job.getStatus(),
            resultOpt.map(ScanResultEntity::getVerdict).orElse(null),
            resultOpt.map(ScanResultEntity::getRiskScore).orElse(null),
            resultOpt.map(ScanResultEntity::getRawScore).orElse(null),
            resultOpt.map(ScanResultEntity::getConfidenceScore).orElse(null),
            resultOpt.map(ScanResultEntity::getSummaryNotes).orElse(null),
            reasons,
            coverage,
            resultOpt.map(ScanResultEntity::getAnalyzedAt).orElse(null),
            job.getCreatedAt(),
            job.getCompletedAt(),
            job.getFailureReason(),
            findings
        );
    }
}
