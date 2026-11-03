package com.pkgsentinel.controller;

import com.pkgsentinel.dto.ScanJobResponse;
import com.pkgsentinel.dto.ScanReportResponse;
import com.pkgsentinel.dto.ScanRequest;
import com.pkgsentinel.dto.UserSummary;
import com.pkgsentinel.entity.ScanJobEntity;
import com.pkgsentinel.service.AuthService;
import com.pkgsentinel.service.ScanOrchestratorService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/scans")
@CrossOrigin(origins = "*")
public class ScanController {

    private final ScanOrchestratorService scanOrchestratorService;
    private final AuthService authService;

    @Value("${pkgsentinel.internal-token:sentinel-internal-secure-token-2026}")
    private String expectedInternalToken;

    @Value("${pkgsentinel.cli-token:sentinel-cli-secure-token-2026}")
    private String expectedCliToken;

    public ScanController(
        ScanOrchestratorService scanOrchestratorService,
        AuthService authService
    ) {
        this.scanOrchestratorService = scanOrchestratorService;
        this.authService = authService;
    }

    /**
     * Submit a scan job.
     * Supports:
     * 1. Authenticated user (Authorization: Bearer <token>) -> tagged as USER:<username>
     * 2. CLI / Service client (X-Service-Token or X-CLI-Key) -> tagged as CLI/SERVICE
     * 3. Public web guest (X-Triggered-By: WEB or fallback)
     */
    @PostMapping
    public ResponseEntity<ScanJobResponse> triggerScan(
        @Valid @RequestBody ScanRequest request,
        @RequestHeader(value = "X-Triggered-By", defaultValue = "WEB") String triggeredBy,
        @RequestHeader(value = "Authorization", required = false) String authHeader,
        @RequestHeader(value = "X-Service-Token", required = false) String serviceToken,
        @RequestHeader(value = "X-CLI-Key", required = false) String cliKey
    ) {
        String actor = triggeredBy;

        // Check explicit CLI or Service token
        if (isServiceOrCliAuthorized(serviceToken, cliKey)) {
            actor = "CLI";
        } else if (authHeader != null && !authHeader.isBlank()) {
            // If user supplied a Bearer token, validate strictly.
            // Do not silently ignore an expired or invalid token.
            UserSummary user = authService.getCurrentUser(authHeader);
            actor = "USER:" + user.username();
        }

        ScanJobResponse response = scanOrchestratorService.submitScan(request, actor);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    /**
     * Retrieve scan job status and summary.
     * Enforces strict authorization: Scans submitted by a user are restricted to that user,
     * unless called by an authorized CLI/service client or admin.
     */
    @GetMapping("/{jobId}")
    public ResponseEntity<ScanReportResponse> getScanReport(
        @PathVariable UUID jobId,
        @RequestHeader(value = "Authorization", required = false) String authHeader,
        @RequestHeader(value = "X-Service-Token", required = false) String serviceToken,
        @RequestHeader(value = "X-CLI-Key", required = false) String cliKey
    ) {
        verifyScanAccess(jobId, authHeader, serviceToken, cliKey);

        return scanOrchestratorService.getScanReport(jobId)
            .map(ResponseEntity::ok)
            .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Retrieve full forensic scan report.
     * Enforces the same authorization policy as getScanReport.
     */
    @GetMapping("/{jobId}/report")
    public ResponseEntity<ScanReportResponse> getDedicatedReport(
        @PathVariable UUID jobId,
        @RequestHeader(value = "Authorization", required = false) String authHeader,
        @RequestHeader(value = "X-Service-Token", required = false) String serviceToken,
        @RequestHeader(value = "X-CLI-Key", required = false) String cliKey
    ) {
        verifyScanAccess(jobId, authHeader, serviceToken, cliKey);

        return scanOrchestratorService.getScanReport(jobId)
            .map(ResponseEntity::ok)
            .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Query recent scan audit history.
     * Supports:
     * - myScansOnly=true: Returns only scans triggered by the authenticated user.
     * - myScansOnly=false: Returns recent scans.
     */
    @GetMapping
    public ResponseEntity<Page<ScanReportResponse>> getRecentScans(
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "10") int size,
        @RequestParam(value = "myScansOnly", defaultValue = "false") boolean myScansOnly,
        @RequestHeader(value = "Authorization", required = false) String authHeader
    ) {
        if (myScansOnly) {
            if (authHeader == null || authHeader.isBlank()) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication required to view personal scan history");
            }
            UserSummary user = authService.getCurrentUser(authHeader);
            Page<ScanReportResponse> userScans = scanOrchestratorService.getUserRecentScans(user.username(), page, size);
            return ResponseEntity.ok(userScans);
        }

        Page<ScanReportResponse> recent = scanOrchestratorService.getRecentScans(page, size);
        return ResponseEntity.ok(recent);
    }

    private void verifyScanAccess(UUID jobId, String authHeader, String serviceToken, String cliKey) {
        // 1. Service / CLI authorization bypass
        if (isServiceOrCliAuthorized(serviceToken, cliKey)) {
            return;
        }

        // 2. Fetch the job entity to inspect owner
        ScanJobEntity job = scanOrchestratorService.getScanJob(jobId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan job not found: " + jobId));

        String triggeredBy = job.getTriggeredBy();
        if (triggeredBy == null || !triggeredBy.startsWith("USER:")) {
            // Public scan (e.g. WEB, CLI, DEMO)
            return;
        }

        String ownerUsername = triggeredBy.substring(5);

        // 3. User verification
        if (authHeader == null || authHeader.isBlank()) {
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "Access denied: This scan report is restricted to owner '" + ownerUsername + "'"
            );
        }

        UserSummary caller = authService.getCurrentUser(authHeader);
        if ("ADMIN".equalsIgnoreCase(caller.role())) {
            return;
        }

        if (!ownerUsername.equalsIgnoreCase(caller.username())) {
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "Access denied: You do not have permission to access another user's scan report"
            );
        }
    }

    private boolean isServiceOrCliAuthorized(String serviceToken, String cliKey) {
        if (serviceToken != null && !serviceToken.isBlank() && serviceToken.equals(expectedInternalToken)) {
            return true;
        }
        if (cliKey != null && !cliKey.isBlank() && (cliKey.equals(expectedCliToken) || cliKey.equals(expectedInternalToken))) {
            return true;
        }
        return false;
    }
}
