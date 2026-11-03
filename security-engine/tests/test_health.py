import pytest
from engine.main import health_check, system_status


def test_health_check_endpoint():
    result = health_check()
    assert result["status"] == "HEALTHY"
    assert result["service"] == "pkgsentinel-security-engine"
    assert "timestamp" in result


def test_system_status_endpoint():
    result = system_status()
    assert result["engine_version"] == "0.1.0"
    assert "scan_stream" in result
    assert result["consumer_group"] == "engine-workers"
