package com.pkgsentinel;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pkgsentinel.dto.ScanCallbackRequest;
import com.pkgsentinel.dto.ScanReportResponse;
import com.pkgsentinel.entity.ScanResultEntity;
import com.pkgsentinel.entity.enums.Severity;
import com.pkgsentinel.entity.enums.Verdict;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class ScanResultEntityJsonTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("ScanResultEntity sets and retrieves JSON structures correctly with null safety")
    void testScanResultEntityJsonProperties() {
        ScanResultEntity entity = new ScanResultEntity();

        // Check defaults
        assertNotNull(entity.getAnalysisCoverage());
        assertTrue(entity.getAnalysisCoverage().isEmpty());
        assertNotNull(entity.getVerdictReasons());
        assertTrue(entity.getVerdictReasons().isEmpty());

        // Set populated values
        Map<String, String> coverage = Map.of(
            "ast_heuristic", "COMPLETED",
            "metadata_checker", "COMPLETED",
            "yara_rules", "SKIPPED"
        );
        List<String> reasons = List.of(
            "Suspicious process execution identified in install hook",
            "Outbound network connection to untrusted host"
        );

        entity.setAnalysisCoverage(coverage);
        entity.setVerdictReasons(reasons);

        assertEquals(coverage, entity.getAnalysisCoverage());
        assertEquals(reasons, entity.getVerdictReasons());

        // Null safety
        entity.setAnalysisCoverage(null);
        entity.setVerdictReasons(null);
        assertNotNull(entity.getAnalysisCoverage());
        assertNotNull(entity.getVerdictReasons());
    }

    @Test
    @DisplayName("ScanCallbackRequest deserializes JSON callback payload matching Python engine output")
    void testCallbackPayloadJsonRoundTrip() throws JsonProcessingException {
        String jsonPayload = """
            {
                "jobId": "c305c48b-e854-469b-81f1-33161c56ef0b",
                "status": "COMPLETED",
                "verdict": "SUSPICIOUS",
                "riskScore": 72.50,
                "rawScore": 85.00,
                "confidenceScore": 0.950,
                "summaryNotes": "Detected obfuscated dynamic evaluation",
                "executionDurationMs": 1420,
                "verdictReasons": [
                    "Obfuscated base64 payload",
                    "Suspicious child_process.spawn call"
                ],
                "analysisCoverage": {
                    "ast_parser": "COMPLETED",
                    "typosquat_detector": "COMPLETED",
                    "entropy_analyzer": "COMPLETED"
                },
                "findings": [
                    {
                        "findingId": "FND-001",
                        "module": "AST_ANALYSIS",
                        "ruleId": "EXEC_EVAL_OBFUSCATED",
                        "category": "EXECUTION",
                        "severity": "HIGH",
                        "confidence": 0.95,
                        "title": "Dynamic Code Evaluation",
                        "description": "Found eval(Buffer.from(...)) construct",
                        "affectedFile": "index.js",
                        "affectedLine": 42,
                        "detectionMethod": "AST",
                        "evidence": {"rawMatch": "eval(Buffer.from('...'))"}
                    }
                ],
                "failureReason": null
            }
            """;

        ScanCallbackRequest callback = objectMapper.readValue(jsonPayload, ScanCallbackRequest.class);

        assertNotNull(callback);
        assertEquals(UUID.fromString("c305c48b-e854-469b-81f1-33161c56ef0b"), callback.jobId());
        assertEquals(Verdict.SUSPICIOUS, callback.verdict());
        assertEquals(new BigDecimal("72.50"), callback.riskScore());
        assertEquals(2, callback.verdictReasons().size());
        assertEquals("Obfuscated base64 payload", callback.verdictReasons().get(0));
        assertEquals(3, callback.analysisCoverage().size());
        assertEquals("COMPLETED", callback.analysisCoverage().get("ast_parser"));
        assertEquals(1, callback.findings().size());
        assertEquals(Severity.HIGH, callback.findings().get(0).severity());

        // Round trip back to JSON
        String serialized = objectMapper.writeValueAsString(callback);
        ScanCallbackRequest roundTripped = objectMapper.readValue(serialized, ScanCallbackRequest.class);
        assertEquals(callback.jobId(), roundTripped.jobId());
        assertEquals(callback.verdict(), roundTripped.verdict());
        assertEquals(callback.verdictReasons(), roundTripped.verdictReasons());
        assertEquals(callback.analysisCoverage(), roundTripped.analysisCoverage());
    }

    @Test
    @DisplayName("ScanRequest defaults omitted or blank version to latest while preserving explicit version")
    void testScanRequestVersionDefaults() {
        com.pkgsentinel.dto.ScanRequest omitted = new com.pkgsentinel.dto.ScanRequest(
            com.pkgsentinel.entity.enums.Ecosystem.NPM, "express", null, null
        );
        assertEquals("latest", omitted.versionOrDefault());

        com.pkgsentinel.dto.ScanRequest blank = new com.pkgsentinel.dto.ScanRequest(
            com.pkgsentinel.entity.enums.Ecosystem.NPM, "express", "   ", null
        );
        assertEquals("latest", blank.versionOrDefault());

        com.pkgsentinel.dto.ScanRequest explicit = new com.pkgsentinel.dto.ScanRequest(
            com.pkgsentinel.entity.enums.Ecosystem.NPM, "express", "4.18.2", null
        );
        assertEquals("4.18.2", explicit.versionOrDefault());
    }
}

