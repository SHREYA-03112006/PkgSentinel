"""
Integration tests for the DetectionPipeline and FastAPI /api/v1/analyze endpoint.
Tests end-to-end static detection, fault isolation, and report generation.
"""

import os
import io
import tarfile
import tempfile
import httpx
import pytest

from engine.ingestion.models import (
    PackageCoordinates,
    Ecosystem,
    ResolvedDistribution,
    DistributionType,
    PackageInventory,
    IngestionResult,
)
from engine.schemas.verdict import Verdict
from engine.detection.pipeline import DetectionPipeline
from engine.detection.metadata_analyzer import MetadataAnalyzer
from engine.detection.typosquatting import TyposquattingDetector
from engine.main import analyze_package_endpoint
from engine.ingestion.pipeline import IngestionPipeline
from engine.ingestion.registry_downloader import RegistryDownloader


def create_synthetic_ingest_workspace(files: dict[str, str]) -> tuple[tempfile.TemporaryDirectory, IngestionResult]:
    tmp_dir = tempfile.TemporaryDirectory()
    workspace = os.path.join(tmp_dir.name, "extracted")
    os.makedirs(workspace, exist_ok=True)

    for rel_path, content in files.items():
        abs_path = os.path.join(workspace, rel_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)

    inventory = PackageInventory(
        total_files=len(files),
        total_bytes=1000,
        extension_distribution={"js": len(files)},
        binary_file_count=0,
        suspicious_files=[],
        files=[],
    )

    ingest_result = IngestionResult(
        coordinates=PackageCoordinates(ecosystem=Ecosystem.NPM, name="choalk", version="1.0.0"),
        distribution=ResolvedDistribution(
            filename="choalk-1.0.0.tgz",
            download_url="https://registry.npmjs.org/choalk/-/choalk-1.0.0.tgz",
            dist_type=DistributionType.NPM_TARBALL,
            integrity_value="dummy",
            integrity_algo="sha256",
        ),
        archive_path=os.path.join(tmp_dir.name, "choalk-1.0.0.tgz"),
        extracted_workspace=workspace,
        archive_sha256="dummy",
        archive_size_bytes=1000,
        inventory=inventory,
        ingested_at="2026-01-01T00:00:00Z",
    )

    return tmp_dir, ingest_result


def test_detection_pipeline_end_to_end_malicious():
    # Package 'choalk' (Typosquatting of chalk -> HIGH) + index.js with eval -> HIGH
    # Multi-vector rule triggers MALICIOUS!
    tmp_dir, ingest_result = create_synthetic_ingest_workspace({
        "package/package.json": '{"name": "choalk", "version": "1.0.0"}',
        "package/index.js": 'eval("malicious payload");',
    })

    try:
        pipeline = DetectionPipeline()
        report = pipeline.analyze(ingest_result, job_id="job-test-e2e")

        assert report.verdict == Verdict.MALICIOUS
        assert len(report.findings) >= 2
        # Check categories present
        cats = {f.category.value for f in report.findings}
        assert "TYPOSQUATTING" in cats
        assert "STATIC_CODE" in cats
        assert report.analysis_coverage["TYPOSQUATTING_DETECTION"] == "COMPLETED"
        assert report.analysis_coverage["STATIC_AST_ANALYSIS"] == "COMPLETED"
    finally:
        tmp_dir.cleanup()


def test_detection_pipeline_fault_isolation():
    # If one module raises an unhandled exception, other modules must succeed and coverage records failure
    tmp_dir, ingest_result = create_synthetic_ingest_workspace({
        "package/index.js": 'console.log("benign");',
    })

    class CrashingAnalyzer(MetadataAnalyzer):
        def analyze(self, *args, **kwargs):
            raise RuntimeError("Database connection timed out during metadata fetch")

    try:
        pipeline = DetectionPipeline(metadata_analyzer=CrashingAnalyzer())
        report = pipeline.analyze(ingest_result, job_id="job-fault-isolation")

        # Metadata failed, but pipeline did NOT crash
        assert "FAILED" in report.analysis_coverage["METADATA_ANALYSIS"]
        assert report.analysis_coverage["TYPOSQUATTING_DETECTION"] == "COMPLETED"
        assert report.analysis_coverage["STATIC_AST_ANALYSIS"] == "COMPLETED"
        # Confidence reflects missing coverage
        assert report.confidence_score <= 0.85
    finally:
        tmp_dir.cleanup()
