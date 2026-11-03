"""
PkgSentinel Redis Streams Worker Daemon
Consumes scan jobs from stream:scan-jobs, executes safe ingestion and detection,
manages renewable leases, handles worker recovery, and delivers authenticated callbacks.
"""

import logging
import signal
import sys
import threading
import time
from typing import Dict, Any, Optional

import httpx
import redis
from redis.exceptions import ResponseError

from engine.core.config import settings
from engine.ingestion.models import (
    PackageCoordinates,
    Ecosystem,
    IngestionError,
)
from engine.ingestion.pipeline import IngestionPipeline
from engine.detection.pipeline import DetectionPipeline

logger = logging.getLogger("pkgsentinel.worker")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class WorkerLeaseManager:
    """Manages active worker leases via periodic Redis key heartbeat."""

    def __init__(self, r: redis.Redis, job_id: str, worker_id: str, ttl_secs: int = 30):
        self.r = r
        self.job_id = job_id
        self.worker_id = worker_id
        self.ttl_secs = ttl_secs
        self.lease_key = f"job:{job_id}:lease"
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        # Set initial lease
        try:
            self.r.set(self.lease_key, self.worker_id, ex=self.ttl_secs)
        except Exception as e:
            logger.warning(f"Failed to acquire initial lease for job {self.job_id}: {e}")

        # Start periodic heartbeat thread
        self._thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._thread.start()

    def _heartbeat_loop(self):
        while not self._stop_event.wait(timeout=self.ttl_secs // 3):
            try:
                self.r.set(self.lease_key, self.worker_id, ex=self.ttl_secs)
            except Exception as e:
                logger.warning(f"Failed to refresh lease for job {self.job_id}: {e}")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        try:
            self.r.delete(self.lease_key)
        except Exception:
            pass


class ScanJobWorker:
    """
    Autonomous worker consuming jobs from Redis Streams, coordinating ingestion
    and heuristic detection, and delivering durable callbacks to Spring Boot.
    """

    def __init__(
        self,
        r: Optional[redis.Redis] = None,
        ingestion_pipe: Optional[IngestionPipeline] = None,
        detection_pipe: Optional[DetectionPipeline] = None,
        http_client: Optional[httpx.Client] = None,
    ):
        self.r = r or redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password or None,
            decode_responses=True,
        )
        self.stream_key = settings.scan_stream_key
        self.dlq_key = settings.dlq_stream_key
        self.consumer_group = settings.consumer_group
        self.worker_id = settings.consumer_name
        self.internal_token = settings.internal_auth_secret
        self.callback_base_url = settings.backend_callback_url

        self.ingestion_pipe = ingestion_pipe or IngestionPipeline()
        self.detection_pipe = detection_pipe or DetectionPipeline()
        self.http_client = http_client or httpx.Client(timeout=15.0, trust_env=False)
        self.running = False

    def init_consumer_group(self) -> None:
        """Creates consumer group on the stream if it does not already exist."""
        try:
            self.r.xgroup_create(self.stream_key, self.consumer_group, id="$", mkstream=True)
            logger.info(f"Created consumer group '{self.consumer_group}' on stream '{self.stream_key}'")
        except ResponseError as e:
            if "BUSYGROUP" in str(e):
                logger.debug(f"Consumer group '{self.consumer_group}' already exists.")
            else:
                logger.error(f"Error creating consumer group: {e}")
                raise

    def process_single_job(self, msg_id: str, fields: Dict[str, str]) -> bool:
        """
        Executes ingestion and detection for a single message, delivers callback,
        and acknowledges message upon durable persistence.
        """
        job_id = fields.get("jobId")
        ecosystem_str = fields.get("ecosystem", "NPM")
        name = fields.get("name")
        version = fields.get("version")

        if not job_id or not name or not version:
            logger.error(f"Rejecting malformed job message {msg_id}: {fields}")
            self.r.xack(self.stream_key, self.consumer_group, msg_id)
            return False

        logger.info(f"Worker '{self.worker_id}' processing Job {job_id} ({ecosystem_str} {name}@{version})")

        # 1. Start renewable lease
        lease = WorkerLeaseManager(self.r, job_id, self.worker_id, ttl_secs=30)
        lease.start()

        ingest_result = None
        callback_payload = None

        try:
            ecosystem = Ecosystem(ecosystem_str.upper())
            coords = PackageCoordinates(ecosystem=ecosystem, name=name, version=version)

            # 2. Phase 1B Ingestion (SSRF checks, download, integrity, safe unpack, inventory)
            ingest_result = self.ingestion_pipe.ingest_package(coords)

            # 3. Phase 1C Detection (Metadata, Typosquatting, AST, Entropy, Scoring)
            report = self.detection_pipe.analyze(ingest_result, job_id=job_id)

            # 4. Construct SUCCESS callback payload
            callback_payload = {
                "jobId": job_id,
                "status": "SUCCESS",
                "resolvedVersion": ingest_result.coordinates.version,
                "verdict": report.verdict.value,
                "riskScore": report.risk_score,
                "rawScore": report.raw_score,
                "confidenceScore": report.confidence_score,
                "summaryNotes": report.summary_notes,
                "executionDurationMs": report.execution_duration_ms,
                "verdictReasons": report.verdict_reasons,
                "analysisCoverage": report.analysis_coverage,
                "findings": [
                    {
                        "findingId": f.finding_id,
                        "module": f.module,
                        "ruleId": f.rule_id,
                        "category": f.category.value,
                        "severity": f.severity.value,
                        "confidence": f.confidence,
                        "title": f.title,
                        "description": f.description,
                        "affectedFile": f.affected_file,
                        "affectedLine": f.affected_line,
                        "detectionMethod": f.detection_method,
                        "evidence": f.evidence,
                    }
                    for f in report.findings
                ],
            }

        except Exception as e:
            logger.exception(f"Analysis failed for job {job_id}: {e}")
            callback_payload = {
                "jobId": job_id,
                "status": "FAILED",
                "failureReason": f"{type(e).__name__}: {str(e)}",
            }

        finally:
            # Always clean up ephemeral workspace
            if ingest_result:
                try:
                    self.ingestion_pipe.cleanup_workspace(ingest_result)
                except Exception:
                    pass

        # 5. Deliver callback to Spring Boot
        callback_success = self.send_callback(job_id, callback_payload)

        # 6. Stop lease
        lease.stop()

        # 7. Acknowledge message only on durable persistence
        if callback_success:
            self.r.xack(self.stream_key, self.consumer_group, msg_id)
            logger.info(f"Job {job_id} completed and acknowledged (msg_id: {msg_id})")
            return True
        else:
            logger.warning(f"Job {job_id} callback delivery failed; message {msg_id} left unacknowledged for retry")
            return False

    def send_callback(self, job_id: str, payload: Dict[str, Any]) -> bool:
        """Delivers callback payload to Spring Boot internal endpoint."""
        url = f"{self.callback_base_url}/{job_id}/callback"
        headers = {
            "Content-Type": "application/json",
            "X-Internal-Token": self.internal_token,
        }

        try:
            resp = self.http_client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                logger.info(f"Callback for Job {job_id} acknowledged by Spring Boot (HTTP 200)")
                return True
            else:
                logger.error(f"Callback for Job {job_id} rejected by Spring Boot (HTTP {resp.status_code}): {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Connection error delivering callback for Job {job_id}: {e}")
            return False

    def reclaim_stale_jobs(self) -> None:
        """
        Inspects pending entries list (PEL) and claims abandoned messages from dead workers
        whose active lease has expired.
        """
        try:
            pending_info = self.r.xpending_range(
                self.stream_key,
                self.consumer_group,
                min="-",
                max="+",
                count=10,
            )
            for entry in pending_info:
                msg_id = entry["message_id"]
                idle_time_ms = entry["idle"]
                delivery_count = entry["times_delivered"]

                # If idle for > 45 seconds (45,000 ms)
                if idle_time_ms > 45000:
                    # Check if retry count exceeded
                    if delivery_count >= 3:
                        logger.warning(f"Message {msg_id} exceeded maximum retries ({delivery_count}); routing to DLQ")
                        # Fetch payload to route to DLQ
                        msg_data = self.r.xrange(self.stream_key, min=msg_id, max=msg_id)
                        if msg_data:
                            self.r.xadd(self.dlq_key, msg_data[0][1])
                        self.r.xack(self.stream_key, self.consumer_group, msg_id)
                        continue

                    # Claim message for this worker
                    claimed = self.r.xclaim(
                        self.stream_key,
                        self.consumer_group,
                        self.worker_id,
                        min_idle_time=45000,
                        message_ids=[msg_id],
                    )
                    if claimed:
                        logger.info(f"Worker '{self.worker_id}' successfully claimed abandoned message {msg_id}")
                        for cid, cfields in claimed:
                            self.process_single_job(cid, cfields)
        except Exception as e:
            logger.debug(f"Error checking pending entries: {e}")

    def run_worker_loop(self) -> None:
        """Main consumer loop reading from Redis Streams."""
        logger.info(f"Starting PkgSentinel Scan Worker (ID: {self.worker_id})...")
        self.init_consumer_group()
        self.running = True

        while self.running:
            try:
                # 1. Periodically check for stale / abandoned messages from dead workers
                self.reclaim_stale_jobs()

                # 2. Read new messages
                response = self.r.xreadgroup(
                    groupname=self.consumer_group,
                    consumername=self.worker_id,
                    streams={self.stream_key: ">"},
                    count=1,
                    block=2000,
                )

                if response:
                    for stream, messages in response:
                        for msg_id, fields in messages:
                            self.process_single_job(msg_id, fields)

            except Exception as e:
                logger.error(f"Error in worker consumer loop: {e}")
                time.sleep(1.0)


def start_worker():
    worker = ScanJobWorker()

    def signal_handler(sig, frame):
        logger.info("Termination signal received. Shutting down worker...")
        worker.running = False
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    worker.run_worker_loop()


if __name__ == "__main__":
    start_worker()
