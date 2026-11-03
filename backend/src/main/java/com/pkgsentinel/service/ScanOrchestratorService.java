package com.pkgsentinel.service;

import com.pkgsentinel.dto.ScanJobResponse;
import com.pkgsentinel.dto.ScanReportResponse;
import com.pkgsentinel.dto.ScanRequest;
import com.pkgsentinel.entity.PackageEntity;
import com.pkgsentinel.entity.PackageVersionEntity;
import com.pkgsentinel.entity.ScanJobEntity;
import com.pkgsentinel.entity.ScanResultEntity;
import com.pkgsentinel.entity.enums.ScanStatus;
import com.pkgsentinel.repository.PackageRepository;
import com.pkgsentinel.repository.PackageVersionRepository;
import com.pkgsentinel.repository.ScanJobRepository;
import com.pkgsentinel.repository.ScanResultRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.stream.RecordId;
import org.springframework.data.redis.connection.stream.StreamRecords;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

@Service
public class ScanOrchestratorService {

    private static final Logger log = LoggerFactory.getLogger(ScanOrchestratorService.class);
    private static final String SCAN_STREAM_KEY = "stream:scan-jobs";

    private final ScanJobRepository scanJobRepository;
    private final PackageRepository packageRepository;
    private final PackageVersionRepository packageVersionRepository;
    private final ScanResultRepository scanResultRepository;
    private final RegistryUrlValidator registryUrlValidator;
    private final StringRedisTemplate redisTemplate;

    public ScanOrchestratorService(
        ScanJobRepository scanJobRepository,
        PackageRepository packageRepository,
        PackageVersionRepository packageVersionRepository,
        ScanResultRepository scanResultRepository,
        RegistryUrlValidator registryUrlValidator,
        StringRedisTemplate redisTemplate
    ) {
        this.scanJobRepository = scanJobRepository;
        this.packageRepository = packageRepository;
        this.packageVersionRepository = packageVersionRepository;
        this.scanResultRepository = scanResultRepository;
        this.registryUrlValidator = registryUrlValidator;
        this.redisTemplate = redisTemplate;
    }

    @Transactional
    public ScanJobResponse submitScan(ScanRequest request, String triggeredBy) {
        if (!registryUrlValidator.isValidPackageIdentifier(request.ecosystem(), request.name())) {
            throw new IllegalArgumentException("Rejected package name format: " + request.name());
        }

        PackageEntity pkg = packageRepository
            .findByEcosystemAndName(request.ecosystem(), request.name())
            .orElseGet(() -> packageRepository.save(new PackageEntity(request.ecosystem(), request.name())));

        PackageVersionEntity versionEntity = packageVersionRepository
            .findByPackageEntityIdAndVersionString(pkg.getId(), request.version())
            .orElseGet(() -> packageVersionRepository.save(new PackageVersionEntity(pkg, request.version())));

        ScanJobEntity job = new ScanJobEntity(
            request.ecosystem(),
            request.name(),
            request.version(),
            request.depthOrDefault(),
            triggeredBy
        );
        job.setPackageVersion(versionEntity);
        job = scanJobRepository.save(job);

        // Publish to Redis Streams (stream:scan-jobs)
        try {
            Map<String, String> payload = new HashMap<>();
            payload.put("jobId", job.getId().toString());
            payload.put("ecosystem", job.getEcosystem().name());
            payload.put("name", job.getPackageName());
            payload.put("version", job.getVersion());
            payload.put("scanDepth", job.getScanDepth().name());
            payload.put("enqueuedAt", Instant.now().toString());

            RecordId recordId = redisTemplate.opsForStream().add(
                StreamRecords.newRecord().ofStrings(payload).withStreamKey(SCAN_STREAM_KEY)
            );
            log.info("Dispatched scan job {} to Redis stream {} with record ID {}", job.getId(), SCAN_STREAM_KEY, recordId);
        } catch (Exception e) {
            log.warn("Redis stream publication deferred or failed for job {}: {}", job.getId(), e.getMessage());
            // In development or when Redis is warming up, the job remains persisted in PostgreSQL as QUEUED
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

    @Transactional(readOnly = true)
    public Optional<ScanReportResponse> getScanReport(UUID jobId) {
        return scanJobRepository.findById(jobId).map(job -> {
            Optional<ScanResultEntity> resultOpt = scanResultRepository.findByScanJobId(job.getId());

            List<ScanReportResponse.FindingItem> findings = resultOpt.map(result ->
                result.getFindings().stream().map(f -> new ScanReportResponse.FindingItem(
                    f.getModuleName(),
                    f.getRuleId(),
                    f.getSeverity().name(),
                    f.getConfidence(),
                    f.getTitle(),
                    f.getDescription(),
                    f.getFilePath(),
                    f.getLineNumber(),
                    f.getCodeSnippet()
                )).toList()
            ).orElse(Collections.emptyList());

            return new ScanReportResponse(
                job.getId(),
                job.getEcosystem().name(),
                job.getPackageName(),
                job.getVersion(),
                job.getStatus(),
                resultOpt.map(ScanResultEntity::getVerdict).orElse(null),
                resultOpt.map(ScanResultEntity::getRiskScore).orElse(null),
                resultOpt.map(ScanResultEntity::getConfidenceScore).orElse(null),
                resultOpt.map(ScanResultEntity::getSummaryNotes).orElse(null),
                resultOpt.map(ScanResultEntity::getAnalyzedAt).orElse(null),
                findings
            );
        });
    }
}
