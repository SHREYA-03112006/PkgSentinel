package com.pkgsentinel;

import com.pkgsentinel.service.RegistryUrlValidator;
import com.pkgsentinel.entity.enums.Ecosystem;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class PkgSentinelApplicationTests {

    private final RegistryUrlValidator validator = new RegistryUrlValidator();

    @Test
    void testValidNpmPackageIdentifier() {
        assertTrue(validator.isValidPackageIdentifier(Ecosystem.NPM, "express"));
        assertTrue(validator.isValidPackageIdentifier(Ecosystem.NPM, "@angular/core"));
        assertFalse(validator.isValidPackageIdentifier(Ecosystem.NPM, "express; rm -rf /"));
        assertFalse(validator.isValidPackageIdentifier(Ecosystem.NPM, ""));
    }

    @Test
    void testValidPyPiPackageIdentifier() {
        assertTrue(validator.isValidPackageIdentifier(Ecosystem.PYPI, "requests"));
        assertTrue(validator.isValidPackageIdentifier(Ecosystem.PYPI, "scikit-learn"));
        assertFalse(validator.isValidPackageIdentifier(Ecosystem.PYPI, "requests/../malicious"));
    }

    @Test
    void testMetadataUriConstruction() {
        URI npmUri = validator.constructMetadataUri(Ecosystem.NPM, "lodash");
        assertEquals("https://registry.npmjs.org/lodash", npmUri.toString());

        URI pypiUri = validator.constructMetadataUri(Ecosystem.PYPI, "fastapi");
        assertEquals("https://pypi.org/pypi/fastapi/json", pypiUri.toString());
    }
}

