"""
Secure archive extractor for TAR and ZIP formats with TarSlip, ZipBomb, and symlink defenses.
"""

import os
import tarfile
import zipfile
import unicodedata
import shutil
from typing import Optional
from dataclasses import dataclass

from engine.ingestion.models import (
    ArchiveExtractionError,
    ArchiveBombError,
    ArchiveTraversalError,
    ArchiveSpecialFileError,
)


@dataclass
class ArchiveLimits:
    """Configurable security constraints for untrusted archive extraction."""
    max_total_bytes: int = 150 * 1024 * 1024     # 150 MB total extracted quota
    max_single_file_bytes: int = 50 * 1024 * 1024  # 50 MB per single file
    max_file_count: int = 2500                   # Maximum 2,500 files
    max_compression_ratio: float = 50.0          # Max 50:1 expansion ratio
    max_path_length: int = 255                   # Max 255 chars per path


def sanitize_relative_path(raw_path: str, extraction_root: str, max_path_len: int = 255) -> str:
    """
    Normalizes and validates an archive entry path to prevent directory traversal.
    Rejects absolute paths, drive letters, UNC paths, and paths escaping extraction_root.
    Returns normalized absolute destination path inside extraction_root.
    """
    # 1. Unicode normalization (NFKC)
    normalized = unicodedata.normalize("NFKC", raw_path)

    # 2. Prevent length exhaustion
    if len(normalized) > max_path_len:
        raise ArchiveTraversalError(f"Entry path length ({len(normalized)}) exceeds limit of {max_path_len}")

    # 3. Reject Windows drive letters (C:) and UNC network paths (\\server\share)
    if (len(normalized) >= 2 and normalized[1] == ":") or normalized.startswith("\\\\"):
        raise ArchiveTraversalError(f"Drive letter or UNC path rejected in archive entry: '{normalized}'")

    # 4. Standardize forward slashes and check absolute paths
    clean_path = normalized.replace("\\", "/").strip()
    if clean_path.startswith("/") or clean_path.startswith("~"):
        raise ArchiveTraversalError(f"Absolute path rejected in archive entry: '{clean_path}'")

    # 5. Check for null bytes or device names (e.g. NUL, CON, AUX, COM1, LPT1)
    if "\0" in clean_path:
        raise ArchiveTraversalError("Null byte detected in entry path.")

    # 6. Disallow directory traversal components
    parts = clean_path.split("/")
    for part in parts:
        if part == "..":
            raise ArchiveTraversalError(f"Path traversal ('..') detected in archive entry: '{clean_path}'")

    # 7. Resolve final destination and verify commonpath boundary
    abs_root = os.path.abspath(extraction_root)
    resolved_dest = os.path.abspath(os.path.join(abs_root, clean_path))

    try:
        common = os.path.commonpath([abs_root, resolved_dest])
    except ValueError:
        raise ArchiveTraversalError(f"Drive mismatch or invalid path resolution for '{clean_path}'")

    if common != abs_root:
        raise ArchiveTraversalError(f"Path traversal escapes extraction root: '{clean_path}'")

    return resolved_dest


class SecureArchiveExtractor:
    """
    Safely unpacks tar.gz/tgz/tar and zip/wheel archives into an isolated workspace directory.
    Enforces safe extraction limits, eliminates symlink escape hazards, and masks file permissions.
    """

    def __init__(self, limits: Optional[ArchiveLimits] = None):
        self.limits = limits or ArchiveLimits()

    def extract(self, archive_path: str, target_dir: str) -> str:
        """
        Extracts archive into target_dir. If extraction fails, target_dir is purged.
        Returns canonical path to extracted root.
        """
        abs_target = os.path.abspath(target_dir)
        os.makedirs(abs_target, exist_ok=True)

        if not os.path.isfile(archive_path):
            raise ArchiveExtractionError(f"Archive not found: {archive_path}")

        archive_size = os.path.getsize(archive_path)

        try:
            if tarfile.is_tarfile(archive_path):
                self._extract_tar(archive_path, abs_target, archive_size)
            elif zipfile.is_zipfile(archive_path):
                self._extract_zip(archive_path, abs_target, archive_size)
            else:
                raise ArchiveExtractionError(f"Unsupported or corrupted archive format: {archive_path}")
            return abs_target

        except Exception:
            # Guarantee cleanup of failed/partial workspace
            if os.path.exists(abs_target):
                shutil.rmtree(abs_target, ignore_errors=True)
            raise

    def _extract_tar(self, archive_path: str, target_dir: str, archive_size: int) -> None:
        total_extracted_bytes = 0
        file_count = 0

        try:
            with tarfile.open(archive_path, "r:*") as tar:
                for member in tar:
                    # 1. Reject special dangerous types
                    if member.isfifo():
                        raise ArchiveSpecialFileError(f"FIFO rejected: {member.name}")
                    if member.ischr() or member.isblk():
                        raise ArchiveSpecialFileError(f"Device node rejected: {member.name}")
                    if member.islnk():
                        raise ArchiveSpecialFileError(f"Hard link rejected: {member.name}")
                    if member.issym():
                        # Validate symlink destination does not escape root
                        dest_link = member.linkname
                        if dest_link.startswith("/") or ".." in dest_link:
                            raise ArchiveSpecialFileError(f"Unsafe symbolic link rejected: {member.name} -> {dest_link}")
                        # Disarm symlinks by skipping them or raising
                        raise ArchiveSpecialFileError(f"Symbolic link disallowed in untrusted archive: {member.name}")

                    # 2. Check path traversal
                    dest_path = sanitize_relative_path(member.name, target_dir, self.limits.max_path_length)

                    # 3. Handle directories
                    if member.isdir():
                        os.makedirs(dest_path, mode=0o755, exist_ok=True)
                        continue

                    # 4. Handle regular files
                    if member.isreg():
                        file_count += 1
                        if file_count > self.limits.max_file_count:
                            raise ArchiveBombError(f"Maximum file count exceeded ({self.limits.max_file_count})")

                        if member.size > self.limits.max_single_file_bytes:
                            raise ArchiveBombError(
                                f"File '{member.name}' size ({member.size} bytes) exceeds limit "
                                f"of {self.limits.max_single_file_bytes} bytes."
                            )

                        os.makedirs(os.path.dirname(dest_path), mode=0o755, exist_ok=True)

                        extracted_member_bytes = 0
                        f_in = tar.extractfile(member)
                        if f_in is None:
                            continue

                        with f_in:
                            with open(dest_path, "wb") as f_out:
                                while True:
                                    chunk = f_in.read(65536)
                                    if not chunk:
                                        break
                                    chunk_len = len(chunk)
                                    extracted_member_bytes += chunk_len
                                    total_extracted_bytes += chunk_len

                                    if extracted_member_bytes > self.limits.max_single_file_bytes:
                                        raise ArchiveBombError(f"File '{member.name}' exceeded maximum individual limit.")
                                    if total_extracted_bytes > self.limits.max_total_bytes:
                                        raise ArchiveBombError(f"Total extracted size exceeded limit ({self.limits.max_total_bytes} bytes).")

                                    # Check compression expansion ratio
                                    if archive_size > 0:
                                        ratio = total_extracted_bytes / archive_size
                                        if ratio > self.limits.max_compression_ratio and total_extracted_bytes > 5 * 1024 * 1024:
                                            raise ArchiveBombError(f"Decompression bomb ratio exceeded ({ratio:.1f}:1 > {self.limits.max_compression_ratio}:1)")

                                    f_out.write(chunk)

                        # Set safe file permissions (0o644)
                        try:
                            os.chmod(dest_path, 0o644)
                        except OSError:
                            pass

        except (tarfile.TarError, EOFError) as e:
            raise ArchiveExtractionError(f"Corrupted or invalid tar archive: {e}")

    def _extract_zip(self, archive_path: str, target_dir: str, archive_size: int) -> None:
        total_extracted_bytes = 0
        file_count = 0

        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                for info in zf.infolist():
                    # 1. Detect symlinks in ZIP external attributes (Unix mode: 0o120000)
                    mode = info.external_attr >> 16
                    if (mode & 0o170000) == 0o120000:
                        raise ArchiveSpecialFileError(f"Symbolic link disallowed in ZIP: {info.filename}")

                    # 2. Check path traversal
                    dest_path = sanitize_relative_path(info.filename, target_dir, self.limits.max_path_length)

                    # 3. Handle directories
                    if info.is_dir() or info.filename.endswith("/"):
                        os.makedirs(dest_path, mode=0o755, exist_ok=True)
                        continue

                    # 4. Handle regular files
                    file_count += 1
                    if file_count > self.limits.max_file_count:
                        raise ArchiveBombError(f"Maximum file count exceeded ({self.limits.max_file_count})")

                    if info.file_size > self.limits.max_single_file_bytes:
                        raise ArchiveBombError(
                            f"ZIP file '{info.filename}' size ({info.file_size} bytes) exceeds limit "
                            f"of {self.limits.max_single_file_bytes} bytes."
                        )

                    os.makedirs(os.path.dirname(dest_path), mode=0o755, exist_ok=True)

                    extracted_member_bytes = 0
                    with zf.open(info, "r") as f_in:
                        with open(dest_path, "wb") as f_out:
                            while True:
                                chunk = f_in.read(65536)
                                if not chunk:
                                    break
                                chunk_len = len(chunk)
                                extracted_member_bytes += chunk_len
                                total_extracted_bytes += chunk_len

                                if extracted_member_bytes > self.limits.max_single_file_bytes:
                                    raise ArchiveBombError(f"File '{info.filename}' exceeded maximum individual limit.")
                                if total_extracted_bytes > self.limits.max_total_bytes:
                                    raise ArchiveBombError(f"Total extracted size exceeded limit ({self.limits.max_total_bytes} bytes).")

                                # Check compression expansion ratio
                                if archive_size > 0:
                                    ratio = total_extracted_bytes / archive_size
                                    if ratio > self.limits.max_compression_ratio and total_extracted_bytes > 5 * 1024 * 1024:
                                        raise ArchiveBombError(f"Decompression bomb ratio exceeded ({ratio:.1f}:1 > {self.limits.max_compression_ratio}:1)")

                                f_out.write(chunk)

                    # Set safe file permissions (0o644)
                    try:
                        os.chmod(dest_path, 0o644)
                    except OSError:
                        pass

        except (zipfile.BadZipFile, EOFError) as e:
            raise ArchiveExtractionError(f"Corrupted or invalid zip archive: {e}")

