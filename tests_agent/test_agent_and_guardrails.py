"""
Unit Tests for Phase 3 & 4: Autonomous Remediation, Human Escalation, and Safety Guardrails.
"""
import os
import pytest
from src.agent.triage_agent import CICDIncidentTriageAgent
from src.parser.models import ParsedIncident
from src.policy.models import ActionType
from src.policy.rules_engine import EscalationPolicyEngine
from src.remediation.actions import AutonomousRemediationExecutor, UnauthorizedActionError


@pytest.fixture
def agent():
    return CICDIncidentTriageAgent()


@pytest.fixture
def executor():
    return AutonomousRemediationExecutor()


def test_agent_auto_resolves_low_risk_timeout(agent):
    raw_log = """
    2026-10-03T14:22:01.300Z [ERROR] tests/test_api.py::test_valid_telemetry_batch_ingest FAILED
    httpx.ConnectTimeout: Connection to mock-sensor.internal timed out after 2.0s
    Process completed with exit code 1.
    """
    result = agent.triage_incident(raw_log, stage="test-suite")

    assert result["status"] == "AUTONOMOUSLY_RESOLVED"
    assert result["execution_outcome"] is not None
    assert result["execution_outcome"]["status"] == "EXECUTED"
    assert result["execution_outcome"]["action_type"] == "RETRY_JOB"
    assert result["escalation_report"] is None


def test_agent_escalates_medium_risk_regression(agent):
    raw_log = """
    FAILED tests/test_api.py::test_valid_telemetry_batch_ingest - assert 400 == 200
    app/models.py:18: ValueError: speed_kmh must be an integer, received float
    """
    result = agent.triage_incident(raw_log, stage="test-suite")

    assert result["status"] == "ESCALATED_TO_HUMAN"
    assert result["execution_outcome"] is None
    assert result["escalation_report"] is not None
    assert result["escalation_report"]["risk_tier"] == "MEDIUM"
    assert "diff" in result["escalation_report"]["recommended_patch_proposal"]
    assert os.path.exists(result["escalation_report"]["json_path"])


def test_agent_escalates_high_risk_cve(agent):
    raw_log = """
    pip-audit: KNOWN VULNERABILITY FOUND - libcrypto 1.1.1 (CVE-2026-901) - Severity: CRITICAL
    Security gate failed: Vulnerabilities above MEDIUM threshold detected.
    """
    result = agent.triage_incident(raw_log, stage="security-audit")

    assert result["status"] == "ESCALATED_TO_HUMAN"
    assert result["execution_outcome"] is None
    assert result["escalation_report"] is not None
    assert result["escalation_report"]["risk_tier"] == "HIGH"
    assert result["escalation_report"]["escalation_channel"] == "slack-#platform-incident-triage"


def test_executor_blocks_unauthorized_actions(executor):
    incident = ParsedIncident(
        pipeline_stage="test-suite",
        failure_signature="NETWORK_TIMEOUT",
        error_type="ConnectTimeout",
        error_message="timeout",
        raw_log_excerpt="timeout"
    )
    with pytest.raises(UnauthorizedActionError):
        executor.execute(ActionType.AUTO_COMMIT_CODE, incident)

    with pytest.raises(UnauthorizedActionError):
        executor.execute(ActionType.MODIFY_PRODUCTION_CONFIG, incident)

    with pytest.raises(UnauthorizedActionError):
        executor.execute(ActionType.TRIGGER_PROD_ROLLBACK, incident)


def test_circuit_breaker_rate_limiting_in_agent():
    engine = EscalationPolicyEngine()
    agent = CICDIncidentTriageAgent(policy_engine=engine)
    raw_log = "httpx.ConnectTimeout: Connection to mock-sensor.internal timed out after 2.0s"

    # Attempt 0: Auto resolved
    res0 = agent.triage_incident(raw_log, stage="test-suite", retry_count=0)
    assert res0["status"] == "AUTONOMOUSLY_RESOLVED"

    # Attempt 1: Auto resolved
    res1 = agent.triage_incident(raw_log, stage="test-suite", retry_count=1)
    assert res1["status"] == "AUTONOMOUSLY_RESOLVED"

    # Attempt 2: Circuit breaker trips -> Escalated to human
    res2 = agent.triage_incident(raw_log, stage="test-suite", retry_count=2)
    assert res2["status"] == "ESCALATED_TO_HUMAN"
    assert res2["policy_decision"]["circuit_breaker_tripped"] is True
    assert res2["policy_decision"]["effective_risk_tier"] == "HIGH"


def test_kill_switch_forces_full_escalation():
    killed_agent = CICDIncidentTriageAgent(kill_switch_active=True)
    raw_log = "httpx.ConnectTimeout: Connection to mock-sensor.internal timed out after 2.0s"

    res = killed_agent.triage_incident(raw_log, stage="test-suite", retry_count=0)
    assert res["status"] == "ESCALATED_TO_HUMAN"
    assert res["policy_decision"]["kill_switch_active"] is True
    assert res["execution_outcome"] is None
