package com.pkgsentinel.dto;

import com.pkgsentinel.entity.enums.Ecosystem;
import com.pkgsentinel.entity.enums.ScanDepth;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record ScanRequest(
    @NotNull(message = "Ecosystem must be specified (NPM or PYPI)")
    Ecosystem ecosystem,

    @NotBlank(message = "Package name cannot be blank")
    @Pattern(regexp = "^[a-zA-Z0-9@_./~-]+$", message = "Package name contains invalid characters")
    String name,

    @NotBlank(message = "Version cannot be blank")
    String version,

    ScanDepth depth
) {
    public ScanDepth depthOrDefault() {
        return depth != null ? depth : ScanDepth.FAST;
    }
}

