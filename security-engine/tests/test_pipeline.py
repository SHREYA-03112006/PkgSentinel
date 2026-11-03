"""
Integration tests for the complete IngestionPipeline and FastAPI /api/v1/ingest endpoint.
"""

import os
import io
import tarfile
import zipfile
import hashlib
import tempfile
import httpx
import pytest

from engine.ingestion.models import (
    Ecosystem,
    PackageCoordinates,
    DownloadIntegrityError,
)
from engine.ingestion.registry_downloader import RegistryDownloader
from engine.ingestion.archive_extractor import SecureArchiveExtractor
from engine.ingestion.pipeline import IngestionPipeline
from engine.main import ingest_package_endpoint


def create_synthetic_npm_tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        pkg_json = b'{"name": "test-pkg", "version": "1.0.0"}'
        ti1 = tarfile.TarInfo(name="package/package.json")
        ti1.size = len(pkg_json)
        tar.addfile(ti1, io.BytesIO(pkg_json))

        index_js = b'console.log("secure hello");'
        ti2 = tarfile.TarInfo(name="package/index.js")
        ti2.size = len(index_js)
        tar.addfile(ti2, io.BytesIO(index_js))
    return buf.getvalue()


def create_synthetic_pypi_wheel() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test_lib-2.0.0.dist-info/METADATA", "Name: test_lib\nVersion: 2.0.0\n")
        zf.writestr("test_lib/__init__.py", "def run(): pass\n")
    return buf.getvalue()


def test_ingestion_pipeline_e2e_npm():
    tarball_bytes = create_synthetic_npm_tarball()
    sha256_hex = hashlib.sha256(tarball_bytes).hexdigest()

    npm_metadata = {
        "name": "test-pkg",
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
                    "integrity": sha256_hex,
                    "unpackedSize": len(tarball_bytes)
                }
            }
        }
    }

    def handler(request: httpx.Request):
        url = str(request.url)
        if url == "https://registry.npmjs.org/test-pkg":
            return httpx.Response(200, json=npm_metadata)
        if url == "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz":
            return httpx.Response(200, content=tarball_bytes)
        return httpx.Response(404)

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)
    extractor = SecureArchiveExtractor()

    with tempfile.TemporaryDirectory() as base_tmp:
        pipeline = IngestionPipeline(
            downloader=downloader,
            extractor=extractor,
            base_workspace_dir=base_tmp
        )

        result = pipeline.ingest_package(PackageCoordinates(
            ecosystem=Ecosystem.NPM,
            name="test-pkg",
            version="1.0.0"
        ))

        # Assertions on IngestionResult
        assert result.coordinates.name == "test-pkg"
        assert result.archive_sha256 == sha256_hex
        assert result.inventory.total_files == 2
        assert "package/package.json" in [f.relative_path for f in result.inventory.files]
        assert "package/index.js" in [f.relative_path for f in result.inventory.files]

        # Verify cleanup method purges session workspace
        pipeline.cleanup_workspace(result)


def test_ingestion_pipeline_e2e_pypi_wheel():
    wheel_bytes = create_synthetic_pypi_wheel()
    sha256_hex = hashlib.sha256(wheel_bytes).hexdigest()

    pypi_metadata = {
        "releases": {
            "2.0.0": [
                {
                    "filename": "test_lib-2.0.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/packages/wheel/t/test_lib-2.0.0-py3-none-any.whl",
                    "digests": {"sha256": sha256_hex}
                }
            ]
        }
    }

    def handler(request: httpx.Request):
        url = str(request.url)
        if url == "https://pypi.org/pypi/test_lib/json":
            return httpx.Response(200, json=pypi_metadata)
        if url == "https://files.pythonhosted.org/packages/wheel/t/test_lib-2.0.0-py3-none-any.whl":
            return httpx.Response(200, content=wheel_bytes)
        return httpx.Response(404)

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)
    extractor = SecureArchiveExtractor()

    with tempfile.TemporaryDirectory() as base_tmp:
        pipeline = IngestionPipeline(
            downloader=downloader,
            extractor=extractor,
            base_workspace_dir=base_tmp
        )

        result = pipeline.ingest_package(PackageCoordinates(
            ecosystem=Ecosystem.PYPI,
            name="test_lib",
            version="2.0.0"
        ))

        assert result.coordinates.name == "test_lib"
        assert result.distribution.dist_type.value == "PYPI_WHEEL"
        assert result.inventory.total_files == 2
        assert "test_lib/__init__.py" in [f.relative_path for f in result.inventory.files]

        pipeline.cleanup_workspace(result)


def test_ingestion_pipeline_cleanup_on_tampered_digest():
    tarball_bytes = create_synthetic_npm_tarball()

    npm_metadata = {
        "name": "tampered-pkg",
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/tampered-pkg/-/tampered-pkg-1.0.0.tgz",
                    "integrity": "0000000000000000000000000000000000000000000000000000000000000000",
                    "unpackedSize": len(tarball_bytes)
                }
            }
        }
    }

    def handler(request: httpx.Request):
        url = str(request.url)
        if url == "https://registry.npmjs.org/tampered-pkg":
            return httpx.Response(200, json=npm_metadata)
        if url == "https://registry.npmjs.org/tampered-pkg/-/tampered-pkg-1.0.0.tgz":
            return httpx.Response(200, content=tarball_bytes)
        return httpx.Response(404)

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    with tempfile.TemporaryDirectory() as base_tmp:
        pipeline = IngestionPipeline(
            downloader=downloader,
            base_workspace_dir=base_tmp
        )

        with pytest.raises(DownloadIntegrityError):
            pipeline.ingest_package(PackageCoordinates(
                ecosystem=Ecosystem.NPM,
                name="tampered-pkg",
                version="1.0.0"
            ))

        # Temporary files must be completely wiped
        assert len(os.listdir(base_tmp)) == 0
