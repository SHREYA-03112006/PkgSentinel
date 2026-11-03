package com.pkgsentinel.dto;

import com.pkgsentinel.entity.enums.ScanStatus;
import java.time.Instant;
import java.util.UUID;

public record ScanJobResponse(
    UUID jobId,
    String ecosystem,
    String name,
    String version,
    ScanStatus status,
    String pollUrl,
    Instant createdAt
) {}
