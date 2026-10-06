"""
CI/CD Log and Output Parser.
Ingests raw CI run logs and extracts structured failure signatures, stages, and error summaries.
"""
import re
from typing import ClassVar

from src.parser.models import ParsedIncident


class CICDLogParser:
    """
    Extracts structured failure data from GitHub Actions or local CI logs.
    """

    STAGE_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"deploy|canary|rollout|staging", "deploy-simulation"),
        (r"pip-audit|bandit|secret|vulnerability", "security-audit"),
        (r"ruff|flake8|mypy|lint", "lint-and-quality"),
        (r"pytest|test_api|test_telemetry|test session starts", "test-suite"),
        (r"docker build|building docker|extracting layer|build definition", "build-package"),
    ]

    SIGNATURE_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        # High Risk signatures
        (r"(AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|Raw credentials present|Potential AWS Access Key)", "SECRET_LEAK_DETECTED"),
        (r"KNOWN VULNERABILITY FOUND|CVE-\d{4}-\d+|Security gate failed", "SECURITY_VULNERABILITY_DETECTED"),
        (r"Canary health threshold not met|canary.*500 Internal Server Error|DatabaseMigrationMismatchException", "CANARY_DEPLOYMENT_FAILED"),

        # Low Risk signatures
        (r"ConnectTimeout|Read timed out|Max retries exceeded with url", "NETWORK_TIMEOUT"),
        (r"RemoteDisconnected|Connection reset by peer|HTTP 503 Service Unavailable", "PACKAGE_MIRROR_CONNECTION_ERROR"),
        (r"no space left on device|Errno 28.*No space left on device", "RUNNER_DISK_EXHAUSTED"),
        (r"AssertionError: assert 0 == 1.*flaky|test_async_batch_flush.*AssertionError", "ASYNC_TEST_FLAKE"),

        # Medium Risk signatures
        (r"ResolutionImpossible|conflicting dependencies", "DEPENDENCY_RESOLUTION_CONFLICT"),
        (r"F401.*imported but unused|Line too long|F841.*Local variable.*never used|Found \d+ errors", "LINT_STYLE_VIOLATION"),
        (r"assert 400 == 200|ValueError: speed_kmh must be|FAILED tests/.*AssertionError|FAILED tests/.*ValueError", "CODE_ASSERTION_REGRESSION"),
    ]

    def parse(self, raw_log: str, explicit_stage: str | None = None, scenario_id: str | None = None) -> ParsedIncident:
        """
        Parses raw CI log text into a structured ParsedIncident.
        """
        stage = explicit_stage or self._detect_stage(raw_log)
        error_type, error_msg, signature = self._extract_error_details(raw_log)
        stack_trace = self._extract_stack_trace(raw_log)
        keywords = self._extract_keywords(raw_log)

        return ParsedIncident(
            scenario_id=scenario_id,
            pipeline_stage=stage,
            failure_signature=signature,
            error_type=error_type,
            error_message=error_msg,
            stack_trace=stack_trace,
            exit_code=1 if "exit code 1" in raw_log or "FAILED" in raw_log or "ERROR" in raw_log else 0,
            keywords=keywords,
            raw_log_excerpt=raw_log.strip()
        )

    def _detect_stage(self, log_text: str) -> str:
        for pattern, stage_name in self.STAGE_PATTERNS:
            if re.search(pattern, log_text, re.IGNORECASE):
                return stage_name
        return "unknown-stage"

    def _extract_error_details(self, log_text: str) -> tuple[str, str, str]:
        # Match signature first
        detected_sig = "GENERIC_CI_FAILURE"
        for sig_regex, sig_name in self.SIGNATURE_PATTERNS:
            if re.search(sig_regex, log_text, re.IGNORECASE):
                detected_sig = sig_name
                break

        # Extract specific error message & type
        if "ConnectTimeout" in log_text or "Read timed out" in log_text:
            return "ConnectTimeout", "Connection to mock service timed out after 2.0s", detected_sig

        if "no space left on device" in log_text.lower():
            return "OSError[ENOSPC]", "No space left on device during container layer extraction", detected_sig

        if "ResolutionImpossible" in log_text:
            return "ResolutionImpossible", "Conflicting package dependency specifications encountered", detected_sig

        if "RemoteDisconnected" in log_text or "HTTP 503" in log_text:
            return "NetworkConnectionError", "PyPI mirror socket disconnected with HTTP 503 error", detected_sig

        if "CVE-" in log_text or "KNOWN VULNERABILITY FOUND" in log_text:
            match = re.search(r"(CVE-\d{4}-\d+:[^\n]+)", log_text)
            msg = match.group(1) if match else "Critical security vulnerability discovered in dependency"
            return "SecurityVulnerabilityError", msg, detected_sig

        if "AKIA" in log_text or "ghp_" in log_text or "Raw credentials" in log_text:
            return "CredentialLeakError", "Unmasked secret or credential pattern detected in logs", detected_sig

        if "500 Internal Server Error" in log_text or "DatabaseMigrationMismatchException" in log_text:
            return "DeploymentHealthProbeError", "Canary deployment health probe failed with HTTP 500 (schema mismatch)", detected_sig

        if "Found" in log_text and "errors" in log_text and ("F401" in log_text or "E501" in log_text):
            return "LintQualityGateError", "Ruff/linter detected code formatting and unused import violations", detected_sig

        if "assert 0 == 1" in log_text or "flaky" in log_text.lower():
            return "AssertionError", "Flaky async timing condition in batch collector test", detected_sig

        if "AssertionError" in log_text or "ValueError" in log_text:
            match = re.search(r"FAILED\s+([^\n]+)", log_text)
            msg = match.group(1) if match else "Test failure due to assertion error / value error"
            return "TestFailure", msg, detected_sig

        # Fallback generic line
        for line in log_text.splitlines():
            if "ERROR" in line or "FAILED" in line or "CRITICAL" in line:
                return "CIExecutionError", line.strip(), detected_sig

        return "UnknownError", "Command completed with non-zero exit code", detected_sig

    def _extract_stack_trace(self, log_text: str) -> str | None:
        if "FAILURES" in log_text:
            lines = log_text.split("FAILURES")[-1]
            return lines[:1200].strip()
        if "Traceback (most recent call last):" in log_text:
            lines = log_text.split("Traceback (most recent call last):")[-1]
            return ("Traceback (most recent call last):" + lines)[:1200].strip()
        if "ERROR:" in log_text or "CRITICAL" in log_text:
            lines = [line for line in log_text.splitlines() if any(k in line for k in ["ERROR", "CRITICAL", "FAILED", "WARNING"])]
            return "\n".join(lines[:10])
        return None

    def _extract_keywords(self, log_text: str) -> list:
        vocab = [
            "timeout", "connecttimeout", "enospc", "flaky", "assertionerror",
            "resolutionimpossible", "ruff", "lint", "cve", "vulnerability",
            "healthz", "500", "secret", "credential", "pypi", "database"
        ]
        text_lower = log_text.lower()
        return [w for w in vocab if w in text_lower]
