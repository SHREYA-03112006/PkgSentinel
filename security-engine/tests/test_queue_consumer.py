import pytest
from unittest.mock import MagicMock
from pathlib import Path

from engine.core.queue_consumer import ScanJobWorker, WorkerLeaseManager
from engine.ingestion.models import (
    PackageCoordinates,
    Ecosystem,
    DistributionType,
    ResolvedDistribution,
    FileInventoryItem,
    PackageInventory,
    IngestionResult
)
from engine.schemas.verdict import AnalysisVerdictReport, Verdict
from engine.schemas.finding import SecurityFinding, FindingCategory, Severity


@pytest.fixture
def mock_redis():
    client = MagicMock()
    pipe = MagicMock()
    pipe.execute.return_value = [True, True]
    client.pipeline.return_value = pipe
    return client


class TestWorkerLeaseManager:
    def test_lease_start_and_stop(self, mock_redis):
        lease = WorkerLeaseManager(mock_redis, "job-abc", "worker-1", ttl_secs=15)
        lease.start()
        mock_redis.set.assert_called_with("job:job-abc:lease", "worker-1", ex=15)

        lease.stop()
        mock_redis.delete.assert_called_with("job:job-abc:lease")


class TestScanJobWorker:
    @pytest.fixture
    def mock_ingestion_pipe(self):
        pipe = MagicMock()
        return pipe

    @pytest.fixture
    def mock_detection_pipe(self):
        pipe = MagicMock()
        return pipe

    @pytest.fixture
    def mock_http_client(self):
        client = MagicMock()
        return client

    @pytest.fixture
    def worker(self, mock_redis, mock_ingestion_pipe, mock_detection_pipe, mock_http_client):
        w = ScanJobWorker(
            r=mock_redis,
            ingestion_pipe=mock_ingestion_pipe,
            detection_pipe=mock_detection_pipe,
            http_client=mock_http_client
        )
        w.internal_token = "sentinel-internal-test-token"
        w.callback_base_url = "http://localhost:8080/internal/v1/scans"
        return w

    def test_malformed_message_dropped_and_acked(self, worker, mock_redis):
        # Missing required fields (name and version)
        success = worker.process_single_job("100-0", {"jobId": "j-1"})
        assert success is False
        mock_redis.xack.assert_called_once_with(worker.stream_key, worker.consumer_group, "100-0")

    def test_successful_scan_pipeline_and_callback(
        self, worker, mock_redis, mock_ingestion_pipe, mock_detection_pipe, mock_http_client, tmp_path
    ):
        job_id = "7f3b8900-3498-4b71-b011-8899aabbccdd"
        msg_id = "101-0"
        fields = {
            "jobId": job_id,
            "ecosystem": "NPM",
            "name": "safe-package",
            "version": "1.0.0"
        }

        # Mock Ingestion result
        coords = PackageCoordinates(ecosystem=Ecosystem.NPM, name="safe-package", version="1.0.0")
        dist = ResolvedDistribution(
            filename="safe-package-1.0.0.tgz",
            download_url="https://registry.npmjs.org/safe-package/-/safe-package-1.0.0.tgz",
            dist_type=DistributionType.NPM_TARBALL,
            integrity_value="sha512-abc",
            integrity_algo="sha512"
        )
        inv = PackageInventory(
            total_files=2,
            total_bytes=300,
            extension_distribution={".json": 1, ".js": 1},
            binary_file_count=0,
            suspicious_files=[],
            files=[
                FileInventoryItem(
                    relative_path="package.json",
                    size_bytes=100,
                    sha256="h1",
                    extension=".json",
                    file_type="application/json",
                    is_binary=False,
                    is_executable=False
                ),
                FileInventoryItem(
                    relative_path="index.js",
                    size_bytes=200,
                    sha256="h2",
                    extension=".js",
                    file_type="text/javascript",
                    is_binary=False,
                    is_executable=False
                )
            ]
        )
        dummy_pkg = IngestionResult(
            coordinates=coords,
            distribution=dist,
            archive_path=str(tmp_path / "pkg.tgz"),
            extracted_workspace=str(tmp_path),
            archive_sha256="sha256:abc123",
            archive_size_bytes=2048,
            inventory=inv,
            ingested_at="2026-11-03T00:00:00Z"
        )
        mock_ingestion_pipe.ingest_package.return_value = dummy_pkg

        # Mock Detection result
        report = AnalysisVerdictReport(
            job_id=job_id,
            status="COMPLETED",
            verdict=Verdict.SAFE,
            risk_score=0.0,
            raw_score=0.0,
            confidence_score=1.0,
            summary_notes="Package clear of zero-day threats",
            execution_duration_ms=45,
            verdict_reasons=["No critical or high findings"],
            analysis_coverage={"AST": "COMPLETED", "Metadata": "COMPLETED"},
            findings=[]
        )
        mock_detection_pipe.analyze.return_value = report

        # Mock HTTP callback response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_http_client.post.return_value = mock_resp

        # Process job
        result = worker.process_single_job(msg_id, fields)

        assert result is True
        mock_ingestion_pipe.ingest_package.assert_called_once()
        mock_detection_pipe.analyze.assert_called_once_with(dummy_pkg, job_id=job_id)
        mock_ingestion_pipe.cleanup_workspace.assert_called_once_with(dummy_pkg)

        # Verify callback HTTP invocation
        mock_http_client.post.assert_called_once()
        call_url = mock_http_client.post.call_args[0][0]
        assert call_url == f"http://localhost:8080/internal/v1/scans/{job_id}/callback"

        headers = mock_http_client.post.call_args[1]["headers"]
        assert headers["X-Internal-Token"] == "sentinel-internal-test-token"

        payload = mock_http_client.post.call_args[1]["json"]
        assert payload["jobId"] == job_id
        assert payload["status"] == "SUCCESS"
        assert payload["verdict"] == "SAFE"
        assert payload["riskScore"] == 0.0

        # Verify message acknowledged on HTTP 200
        mock_redis.xack.assert_called_once_with(worker.stream_key, worker.consumer_group, msg_id)

    def test_failed_callback_delivery_leaves_unacknowledged(
        self, worker, mock_redis, mock_ingestion_pipe, mock_detection_pipe, mock_http_client, tmp_path
    ):
        job_id = "8f3b8900-3498-4b71-b011-8899aabbccee"
        msg_id = "102-0"
        fields = {
            "jobId": job_id,
            "ecosystem": "PYPI",
            "name": "requests-fake",
            "version": "2.0.0"
        }

        coords = PackageCoordinates(ecosystem=Ecosystem.PYPI, name="requests-fake", version="2.0.0")
        dist = ResolvedDistribution(
            filename="requests_fake-2.0.0-py3-none-any.whl",
            download_url="https://files.pythonhosted.org/packages/requests_fake-2.0.0.whl",
            dist_type=DistributionType.PYPI_WHEEL,
            integrity_value="sha256:def456",
            integrity_algo="sha256"
        )
        inv = PackageInventory(
            total_files=0,
            total_bytes=0,
            extension_distribution={},
            binary_file_count=0,
            suspicious_files=[],
            files=[]
        )
        dummy_pkg = IngestionResult(
            coordinates=coords,
            distribution=dist,
            archive_path=str(tmp_path / "pkg.whl"),
            extracted_workspace=str(tmp_path),
            archive_sha256="sha256:def456",
            archive_size_bytes=1000,
            inventory=inv,
            ingested_at="2026-11-03T00:00:00Z"
        )
        mock_ingestion_pipe.ingest_package.return_value = dummy_pkg

        report = AnalysisVerdictReport(
            job_id=job_id,
            status="COMPLETED",
            verdict=Verdict.MALICIOUS,
            risk_score=95.0,
            raw_score=120.0,
            confidence_score=0.9,
            summary_notes="Malicious typosquat detected",
            findings=[]
        )
        mock_detection_pipe.analyze.return_value = report

        # Backend is down or errors with HTTP 500
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        mock_http_client.post.return_value = mock_resp

        result = worker.process_single_job(msg_id, fields)

        assert result is False
        # Vital: xack must NOT be called when callback fails!
        mock_redis.xack.assert_not_called()

    def test_ingestion_failure_sends_failed_callback(
        self, worker, mock_redis, mock_ingestion_pipe, mock_http_client
    ):
        job_id = "9f3b8900-3498-4b71-b011-8899aabbccff"
        msg_id = "103-0"
        fields = {
            "jobId": job_id,
            "ecosystem": "NPM",
            "name": "bad-archive",
            "version": "1.0.0"
        }

        # Ingestion raises ValueError
        mock_ingestion_pipe.ingest_package.side_effect = ValueError("Archive violates TarSlip path containment")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_http_client.post.return_value = mock_resp

        result = worker.process_single_job(msg_id, fields)

        assert result is True
        mock_http_client.post.assert_called_once()
        payload = mock_http_client.post.call_args[1]["json"]
        assert payload["jobId"] == job_id
        assert payload["status"] == "FAILED"
        assert "TarSlip" in payload["failureReason"]

        # Once Spring Boot acknowledges the failure, worker acks the message
        mock_redis.xack.assert_called_once_with(worker.stream_key, worker.consumer_group, msg_id)

    def test_reclaim_stale_jobs_dlq_routing(self, worker, mock_redis):
        # Entry idle for 60 seconds with 3 delivery attempts
        mock_redis.xpending_range.return_value = [
            {
                "message_id": "104-0",
                "consumer": "dead-worker-1",
                "idle": 60000,
                "times_delivered": 3
            }
        ]
        # xrange returns original job payload
        mock_redis.xrange.return_value = [
            ("104-0", {"jobId": "exhausted-job", "name": "crashed-pkg", "version": "1.0"})
        ]

        worker.reclaim_stale_jobs()

        # Must route to DLQ
        mock_redis.xadd.assert_called_once_with(
            worker.dlq_key,
            {"jobId": "exhausted-job", "name": "crashed-pkg", "version": "1.0"}
        )

        # Must ACK and delete from active stream
        mock_redis.xack.assert_called_once_with(
            worker.stream_key,
            worker.consumer_group,
            "104-0"
        )
