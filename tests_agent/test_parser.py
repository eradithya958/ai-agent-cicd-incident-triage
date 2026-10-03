"""
Tests for CI/CD Log Parser
"""
import pytest
from src.parser.log_parser import CICDLogParser


@pytest.fixture
def parser():
    return CICDLogParser()


def test_parse_timeout_error(parser):
    log = """
    2026-10-03T14:22:01.300Z [ERROR] tests/test_api.py::test_valid_telemetry_batch_ingest FAILED
    httpx.ConnectTimeout: Connection to mock-sensor.internal timed out after 2.0s
    Process completed with exit code 1.
    """
    parsed = parser.parse(log)
    assert parsed.pipeline_stage == "test-suite"
    assert parsed.failure_signature == "NETWORK_TIMEOUT"
    assert parsed.error_type == "ConnectTimeout"
    assert parsed.exit_code == 1
    assert "timeout" in parsed.keywords


def test_parse_cve_security_finding(parser):
    log = """
    pip-audit: KNOWN VULNERABILITY FOUND - libcrypto 1.1.1 (CVE-2026-901) - Severity: CRITICAL
    Security gate failed: Vulnerabilities above MEDIUM threshold detected.
    Error: Process completed with exit code 1.
    """
    parsed = parser.parse(log)
    assert parsed.pipeline_stage == "security-audit"
    assert parsed.failure_signature == "SECURITY_VULNERABILITY_DETECTED"
    assert parsed.error_type == "SecurityVulnerabilityError"
    assert "cve" in parsed.keywords


def test_parse_secret_leak(parser):
    log = """
    [CRITICAL_SECURITY_ALERT] Potential AWS Access Key ID detected: AKIAIOSFODNN7EXAMPLE
    Raw credentials present in unmasked log stream.
    """
    parsed = parser.parse(log)
    assert parsed.failure_signature == "SECRET_LEAK_DETECTED"
    assert parsed.error_type == "CredentialLeakError"
    assert "credential" in parsed.keywords

