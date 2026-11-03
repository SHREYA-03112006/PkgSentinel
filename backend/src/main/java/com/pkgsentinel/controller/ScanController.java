package com.pkgsentinel.controller;

import com.pkgsentinel.dto.ScanJobResponse;
import com.pkgsentinel.dto.ScanReportResponse;
import com.pkgsentinel.dto.ScanRequest;
import com.pkgsentinel.service.ScanOrchestratorService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/scans")
@CrossOrigin(origins = "*")
public class ScanController {

    private final ScanOrchestratorService scanOrchestratorService;

    public ScanController(ScanOrchestratorService scanOrchestratorService) {
        this.scanOrchestratorService = scanOrchestratorService;
    }

    @PostMapping
    public ResponseEntity<ScanJobResponse> triggerScan(
        @Valid @RequestBody ScanRequest request,
        @RequestHeader(value = "X-Triggered-By", defaultValue = "WEB") String triggeredBy
    ) {
        ScanJobResponse response = scanOrchestratorService.submitScan(request, triggeredBy);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @GetMapping("/{jobId}")
    public ResponseEntity<ScanReportResponse> getScanReport(@PathVariable UUID jobId) {
        return scanOrchestratorService.getScanReport(jobId)
            .map(ResponseEntity::ok)
            .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
