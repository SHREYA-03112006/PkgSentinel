package com.pkgsentinel.controller;

import com.pkgsentinel.dto.ScanCallbackRequest;
import com.pkgsentinel.service.ScanOrchestratorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/internal/v1/scans")
public class InternalScanCallbackController {

    private static final Logger log = LoggerFactory.getLogger(InternalScanCallbackController.class);
    private final ScanOrchestratorService scanOrchestratorService;

    public InternalScanCallbackController(ScanOrchestratorService scanOrchestratorService) {
        this.scanOrchestratorService = scanOrchestratorService;
    }

    /**
     * Authenticated callback endpoint invoked by Python Security Engine upon completing package analysis.
     * Guaranteed atomic transaction: returns HTTP 200 only after database commit.
     */
    @PostMapping("/{jobId}/callback")
    public ResponseEntity<?> receiveWorkerCallback(
        @PathVariable UUID jobId,
        @RequestHeader(value = "X-Internal-Token", required = false) String internalToken,
        @RequestBody ScanCallbackRequest callback
    ) {
        try {
            boolean success = scanOrchestratorService.handleWorkerCallback(jobId, internalToken, callback);
            return ResponseEntity.ok(Map.of(
                "status", "ACKNOWLEDGED",
                "jobId", jobId,
                "processed", success
            ));
        } catch (SecurityException e) {
            log.warn("Unauthorized internal callback rejected for job {}: {}", jobId, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", e.getMessage()));
        } catch (IllegalArgumentException e) {
            log.warn("Invalid callback for job {}: {}", jobId, e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Failed to process worker callback for job {}: {}", jobId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", e.getMessage()));
        }
    }
}
