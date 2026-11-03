package com.pkgsentinel.service;

import com.pkgsentinel.entity.enums.Ecosystem;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.regex.Pattern;

@Component
public class RegistryUrlValidator {

    private static final Pattern NPM_PKG_PATTERN = Pattern.compile("^(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+$");
    private static final Pattern PYPI_PKG_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]+$");

    public boolean isValidPackageIdentifier(Ecosystem ecosystem, String packageName) {
        if (packageName == null || packageName.isBlank()) {
            return false;
        }
        return switch (ecosystem) {
            case NPM -> NPM_PKG_PATTERN.matcher(packageName).matches();
            case PYPI -> PYPI_PKG_PATTERN.matcher(packageName).matches();
        };
    }

    public URI constructMetadataUri(Ecosystem ecosystem, String packageName) {
        if (!isValidPackageIdentifier(ecosystem, packageName)) {
            throw new IllegalArgumentException("Invalid package identifier format for ecosystem: " + ecosystem);
        }
        return switch (ecosystem) {
            case NPM -> URI.create("https://registry.npmjs.org/" + packageName);
            case PYPI -> URI.create("https://pypi.org/pypi/" + packageName + "/json");
        };
    }
}

