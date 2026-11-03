"""
Unit tests for Module A: Metadata & Publisher Analyzer.
"""

import pytest
from engine.ingestion.models import PackageCoordinates, Ecosystem
from engine.detection.metadata_analyzer import MetadataAnalyzer
from engine.schemas.finding import Severity


def test_rapid_release_burst():
    analyzer = MetadataAnalyzer()
    coords = PackageCoordinates(ecosystem=Ecosystem.NPM, name="churn-pkg", version="1.0.5")

    # 6 releases within 1 hour
    metadata = {
        "time": {
            "created": "2026-01-01T10:00:00Z",
            "1.0.0": "2026-01-01T10:00:00Z",
            "1.0.1": "2026-01-01T10:10:00Z",
            "1.0.2": "2026-01-01T10:20:00Z",
            "1.0.3": "2026-01-01T10:30:00Z",
            "1.0.4": "2026-01-01T10:40:00Z",
            "1.0.5": "2026-01-01T10:50:00Z",
        }
    }

    findings = analyzer.analyze(coords, registry_metadata=metadata)
    burst_findings = [f for f in findings if f.rule_id == "META_RAPID_RELEASE_BURST"]
    assert len(burst_findings) == 1
    assert burst_findings[0].severity == Severity.LOW  # Weak signal as required


def test_suspicious_major_version():
    analyzer = MetadataAnalyzer()
    coords = PackageCoordinates(ecosystem=Ecosystem.NPM, name="auth-internal", version="99.0.0")
    metadata = {"versions": {"99.0.0": {}}}

    findings = analyzer.analyze(coords, registry_metadata=metadata)
    ver_findings = [f for f in findings if f.rule_id == "META_SUSPICIOUS_MAJOR_VERSION"]
    assert len(ver_findings) == 1
    assert ver_findings[0].severity == Severity.MEDIUM


def test_repository_mismatch_popular_org():
    analyzer = MetadataAnalyzer()
    coords = PackageCoordinates(ecosystem=Ecosystem.NPM, name="color-picker-js", version="1.0.0")
    manifest = {
        "repository": {"url": "https://github.com/facebook/react.git"}
    }

    findings = analyzer.analyze(coords, manifest_data=manifest)
    repo_findings = [f for f in findings if f.rule_id == "META_REPO_MISMATCH_SUSPICIOUS"]
    assert len(repo_findings) == 1
    # Must NOT exceed MEDIUM severity per architectural constraints
    assert repo_findings[0].severity == Severity.MEDIUM


def test_free_email_maintainer():
    analyzer = MetadataAnalyzer()
    coords = PackageCoordinates(ecosystem=Ecosystem.NPM, name="my-pkg", version="1.0.0")
    metadata = {
        "maintainers": [
            {"name": "anon_dev", "email": "dev123@proton.me"}
        ]
    }

    findings = analyzer.analyze(coords, registry_metadata=metadata)
    email_findings = [f for f in findings if f.rule_id == "META_FREE_EMAIL_MAINTAINER"]
    assert len(email_findings) == 1
    assert email_findings[0].severity == Severity.LOW


def test_empty_metadata_produces_no_findings():
    analyzer = MetadataAnalyzer()
    coords = PackageCoordinates(ecosystem=Ecosystem.PYPI, name="clean-lib", version="1.0.0")
    findings = analyzer.analyze(coords, registry_metadata=None, manifest_data=None)
    assert findings == []

