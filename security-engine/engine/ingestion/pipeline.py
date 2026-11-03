"""
Pipeline coordinator uniting Registry Downloader, Secure Archive Extractor, and Package Inventory.
"""

import os
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Optional

from engine.ingestion.models import (
    PackageCoordinates,
    IngestionResult,
    IngestionError,
)
from engine.ingestion.registry_downloader import RegistryDownloader
from engine.ingestion.archive_extractor import SecureArchiveExtractor, ArchiveLimits
from engine.ingestion.inventory import build_package_inventory
from engine.ingestion.integrity import compute_file_hashes


class IngestionPipeline:
    """
    End-to-end coordinator for secure package ingestion.
    Resolves metadata, downloads, verifies integrity, extracts safely, and generates inventory.
    """

    def __init__(
        self,
        downloader: Optional[RegistryDownloader] = None,
        extractor: Optional[SecureArchiveExtractor] = None,
        base_workspace_dir: Optional[str] = None,
    ):
        self.downloader = downloader or RegistryDownloader()
        self.extractor = extractor or SecureArchiveExtractor()
        self.base_workspace_dir = base_workspace_dir

    def ingest_package(self, coords: PackageCoordinates) -> IngestionResult:
        """
        Executes complete ingestion pipeline.
        Creates an isolated temporary session workspace.
        Cleans up all files on any error.
        """
        # Create unique session workspace
        session_dir = tempfile.mkdtemp(prefix="pkgsentinel_ingest_", dir=self.base_workspace_dir)
        download_dir = os.path.join(session_dir, "archive")
        extracted_dir = os.path.join(session_dir, "extracted")

        try:
            # 1. Resolve official distribution metadata
            dist = self.downloader.resolve_distribution(coords)

            # 2. Download archive & verify integrity
            archive_path = self.downloader.download_archive(dist, download_dir)

            # Compute archive metadata
            archive_size = os.path.getsize(archive_path)
            sha256_hex, _ = compute_file_hashes(archive_path)

            # 3. Extract safely into isolated workspace
            self.extractor.extract(archive_path, extracted_dir)

            # 4. Generate deterministic inventory
            inventory = build_package_inventory(extracted_dir)

            return IngestionResult(
                coordinates=coords,
                distribution=dist,
                archive_path=archive_path,
                extracted_workspace=extracted_dir,
                archive_sha256=sha256_hex,
                archive_size_bytes=archive_size,
                inventory=inventory,
                ingested_at=datetime.now(timezone.utc).isoformat(),
            )

        except Exception as e:
            # Ensure full cleanup of session directory on failure
            if os.path.exists(session_dir):
                shutil.rmtree(session_dir, ignore_errors=True)
            if isinstance(e, IngestionError):
                raise
            raise IngestionError(f"Unexpected ingestion failure for {coords.name}@{coords.version}: {e}") from e

    @staticmethod
    def cleanup_workspace(result: IngestionResult) -> None:
        """Helper to purge extracted session directories when analysis is finalized."""
        session_root = os.path.dirname(result.extracted_workspace)
        if os.path.exists(session_root):
            shutil.rmtree(session_root, ignore_errors=True)

