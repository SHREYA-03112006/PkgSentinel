"""
Security and regression test suite for SecureArchiveExtractor.
Tests TarSlip, ZipSlip, symlinks, hardlinks, FIFOs, bombs, and unicode traversal vectors.
"""

import os
import io
import tarfile
import zipfile
import tempfile
import pytest

from engine.ingestion.archive_extractor import (
    SecureArchiveExtractor,
    ArchiveLimits,
    sanitize_relative_path,
)
from engine.ingestion.models import (
    ArchiveExtractionError,
    ArchiveBombError,
    ArchiveTraversalError,
    ArchiveSpecialFileError,
)


# ==============================================================================
# Helper functions to build test archives in memory
# ==============================================================================

def create_tar_archive(entries: dict[str, bytes | str]) -> bytes:
    """Creates an in-memory tar.gz archive with specified relative paths and bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in entries.items():
            if isinstance(data, str):
                data = data.encode("utf-8")
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mtime = 1700000000
            ti.type = tarfile.REGTYPE
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def create_zip_archive(entries: dict[str, bytes | str]) -> bytes:
    """Creates an in-memory zip archive with specified relative paths and bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            if isinstance(data, str):
                data = data.encode("utf-8")
            zf.writestr(name, data)
    return buf.getvalue()


# ==============================================================================
# Normal extraction tests
# ==============================================================================

def test_extract_normal_tar():
    archive_bytes = create_tar_archive({
        "package/package.json": '{"name": "test-pkg", "version": "1.0.0"}',
        "package/index.js": 'console.log("hello world");'
    })
    extractor = SecureArchiveExtractor()

    with tempfile.TemporaryDirectory() as tmp_dir:
        tar_path = os.path.join(tmp_dir, "test.tgz")
        with open(tar_path, "wb") as f:
            f.write(archive_bytes)

        out_dir = os.path.join(tmp_dir, "out")
        extracted_root = extractor.extract(tar_path, out_dir)

        assert os.path.exists(os.path.join(extracted_root, "package", "package.json"))
        assert os.path.exists(os.path.join(extracted_root, "package", "index.js"))


def test_extract_normal_wheel_zip():
    archive_bytes = create_zip_archive({
        "mypkg-1.0.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: mypkg\nVersion: 1.0.0",
        "mypkg/__init__.py": "__version__ = '1.0.0'"
    })
    extractor = SecureArchiveExtractor()

    with tempfile.TemporaryDirectory() as tmp_dir:
        whl_path = os.path.join(tmp_dir, "mypkg-1.0.0-py3-none-any.whl")
        with open(whl_path, "wb") as f:
            f.write(archive_bytes)

        out_dir = os.path.join(tmp_dir, "out")
        extracted_root = extractor.extract(whl_path, out_dir)

        assert os.path.exists(os.path.join(extracted_root, "mypkg", "__init__.py"))
        assert os.path.exists(os.path.join(extracted_root, "mypkg-1.0.0.dist-info", "METADATA"))


# ==============================================================================
# Path Traversal & Escape Tests (ZipSlip & TarSlip)
# ==============================================================================

def test_tar_slip_dot_dot_rejected():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        ti = tarfile.TarInfo(name="../../escaped_tar.txt")
        data = b"malicious content outside root"
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))

    extractor = SecureArchiveExtractor()
    with tempfile.TemporaryDirectory() as tmp_dir:
        tar_path = os.path.join(tmp_dir, "tarslip.tgz")
        with open(tar_path, "wb") as f:
            f.write(buf.getvalue())

        out_dir = os.path.join(tmp_dir, "out")
        with pytest.raises(ArchiveTraversalError):
            extractor.extract(tar_path, out_dir)

        # Ensure no escaped files outside workspace
        assert not os.path.exists(os.path.join(tmp_dir, "escaped_tar.txt"))
        # Ensure partial directory is completely cleaned up
        assert not os.path.exists(out_dir)


def test_zip_slip_dot_dot_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w") as zf:
        zf.writestr("../../escaped_zip.txt", b"evil content")

    extractor = SecureArchiveExtractor()
    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_path = os.path.join(tmp_dir, "zipslip.zip")
        with open(zip_path, "wb") as f:
            f.write(buf.getvalue())

        out_dir = os.path.join(tmp_dir, "out")
        with pytest.raises(ArchiveTraversalError):
            extractor.extract(zip_path, out_dir)

        assert not os.path.exists(os.path.join(tmp_dir, "escaped_zip.txt"))
        assert not os.path.exists(out_dir)


def test_absolute_path_rejected():
    with tempfile.TemporaryDirectory() as root:
        with pytest.raises(ArchiveTraversalError):
            sanitize_relative_path("/etc/shadow", root)
        with pytest.raises(ArchiveTraversalError):
            sanitize_relative_path("/root/.ssh/id_rsa", root)


def test_windows_drive_letter_and_unc_rejected():
    with tempfile.TemporaryDirectory() as root:
        with pytest.raises(ArchiveTraversalError):
            sanitize_relative_path("C:\\Windows\\System32\\calc.exe", root)
        with pytest.raises(ArchiveTraversalError):
            sanitize_relative_path("D:evil.txt", root)
        with pytest.raises(ArchiveTraversalError):
            sanitize_relative_path("\\\\192.168.1.10\\share\\payload.exe", root)


def test_unicode_normalization_traversal_rejected():
    # Fullwidth solidus U+FF0F or special dots
    with tempfile.TemporaryDirectory() as root:
        with pytest.raises(ArchiveTraversalError):
            sanitize_relative_path("..\uFF0Fetc\uFF0Fpasswd", root)


def test_excessive_path_length_rejected():
    with tempfile.TemporaryDirectory() as root:
        long_path = "a/" * 130 + "file.txt"  # > 255 chars
        with pytest.raises(ArchiveTraversalError):
            sanitize_relative_path(long_path, root, max_path_len=255)


# ==============================================================================
# Dangerous Filesystem Objects (Symlinks, Hard links, FIFOs)
# ==============================================================================

def test_tar_symlink_rejected():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        ti = tarfile.TarInfo(name="package/symlink_to_etc")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/passwd"
        tar.addfile(ti)

    extractor = SecureArchiveExtractor()
    with tempfile.TemporaryDirectory() as tmp_dir:
        tar_path = os.path.join(tmp_dir, "symlink.tgz")
        with open(tar_path, "wb") as f:
            f.write(buf.getvalue())

        out_dir = os.path.join(tmp_dir, "out")
        with pytest.raises(ArchiveSpecialFileError):
            extractor.extract(tar_path, out_dir)


def test_tar_hard_link_rejected():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        ti = tarfile.TarInfo(name="package/hardlink")
        ti.type = tarfile.LNKTYPE
        ti.linkname = "package/target"
        tar.addfile(ti)

    extractor = SecureArchiveExtractor()
    with tempfile.TemporaryDirectory() as tmp_dir:
        tar_path = os.path.join(tmp_dir, "hardlink.tgz")
        with open(tar_path, "wb") as f:
            f.write(buf.getvalue())

        out_dir = os.path.join(tmp_dir, "out")
        with pytest.raises(ArchiveSpecialFileError):
            extractor.extract(tar_path, out_dir)


def test_tar_fifo_rejected():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        ti = tarfile.TarInfo(name="package/named_pipe")
        ti.type = tarfile.FIFOTYPE
        tar.addfile(ti)

    extractor = SecureArchiveExtractor()
    with tempfile.TemporaryDirectory() as tmp_dir:
        tar_path = os.path.join(tmp_dir, "fifo.tgz")
        with open(tar_path, "wb") as f:
            f.write(buf.getvalue())

        out_dir = os.path.join(tmp_dir, "out")
        with pytest.raises(ArchiveSpecialFileError):
            extractor.extract(tar_path, out_dir)


# ==============================================================================
# Archive Bomb Safeguard Tests
# ==============================================================================

def test_archive_bomb_single_file_exceeded():
    archive_bytes = create_zip_archive({
        "big.bin": b"0" * 2048
    })
    # Set limit to 1024 bytes
    extractor = SecureArchiveExtractor(limits=ArchiveLimits(max_single_file_bytes=1024))

    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_path = os.path.join(tmp_dir, "bomb.zip")
        with open(zip_path, "wb") as f:
            f.write(archive_bytes)

        out_dir = os.path.join(tmp_dir, "out")
        with pytest.raises(ArchiveBombError):
            extractor.extract(zip_path, out_dir)

        # Workspace must be purged
        assert not os.path.exists(out_dir)


def test_archive_bomb_file_count_exceeded():
    archive_bytes = create_tar_archive({
        f"file_{i}.txt": f"data {i}" for i in range(10)
    })
    extractor = SecureArchiveExtractor(limits=ArchiveLimits(max_file_count=5))

    with tempfile.TemporaryDirectory() as tmp_dir:
        tar_path = os.path.join(tmp_dir, "many_files.tgz")
        with open(tar_path, "wb") as f:
            f.write(archive_bytes)

        out_dir = os.path.join(tmp_dir, "out")
        with pytest.raises(ArchiveBombError):
            extractor.extract(tar_path, out_dir)

        assert not os.path.exists(out_dir)


def test_corrupted_archive_rejected():
    extractor = SecureArchiveExtractor()
    with tempfile.TemporaryDirectory() as tmp_dir:
        corrupted_path = os.path.join(tmp_dir, "corrupt.tgz")
        with open(corrupted_path, "wb") as f:
            f.write(b"this is not a valid tar or zip header")

        out_dir = os.path.join(tmp_dir, "out")
        with pytest.raises(ArchiveExtractionError):
            extractor.extract(corrupted_path, out_dir)

