"""
Unit Tests for Phase 5 & 6: Audit Logging, SQLite Persistence, and Safety Edge Cases.
"""
import pytest

from src.agent.triage_agent import CICDIncidentTriageAgent
from src.audit.logger import AuditLogger
from src.policy.models import RiskTier


@pytest.fixture
def temp_log_dir(tmp_path):
    return str(tmp_path / "test_logs")


def test_audit_logger_persists_to_sqlite_and_jsonl(temp_log_dir):
    logger = AuditLogger(log_dir=temp_log_dir)
    mock_result = {
        "incident_id": "TEST-INC-100",
        "scenario_id": "SCEN-LOW-01",
        "pipeline_stage": "test-suite",
        "status": "AUTONOMOUSLY_RESOLVED",
        "classification": {
            "category": "TRANSIENT_NETWORK_TIMEOUT",
            "confidence": 0.95,
        },
        "policy_decision": {
            "effective_risk_tier": "LOW",
            "is_auto_actionable": True,
            "authorized_action": "RETRY_JOB",
            "rule_code": "POL-TIER1-LOW-RISK-AUTO",
            "circuit_breaker_tripped": False,
            "kill_switch_active": False,
            "justification": "Reversible low risk retry",
        }
    }

    inc_id = logger.log_triage_decision(mock_result)
    assert inc_id == "TEST-INC-100"

    # Verify SQLite record
    records = logger.fetch_all_records()
    assert len(records) == 1
    assert records[0]["incident_id"] == "TEST-INC-100"
    assert records[0]["effective_risk_tier"] == "LOW"
    assert records[0]["is_auto_actionable"] == 1

    # Verify JSONL file
    with open(logger.jsonl_path, "r") as f:
        lines = f.readlines()
        assert len(lines) == 1
        assert "TEST-INC-100" in lines[0]


def test_edge_case_timeout_during_deployment_escalates_to_high(temp_log_dir):
    """
    EDGE CASE:
    A ConnectTimeout during 'deploy-simulation' MUST NOT be treated as a low-risk test timeout.
    Because it touches live deployment/staging infrastructure, it must escalate to High Risk.
    """
    logger = AuditLogger(log_dir=temp_log_dir)
    agent = CICDIncidentTriageAgent(audit_logger=logger)

    log = """
    2026-10-03T16:00:00.000Z [INFO] Deploying container to live staging cluster...
    ConnectTimeout: Connection to live staging ingress timed out after 10.0s
    [FATAL] Deploy healthcheck failed during canary rollout. Target host unreachable.
    """
    result = agent.triage_incident(log, stage="deploy-simulation", scenario_id="EDGE-01")

    assert result["policy_decision"]["effective_risk_tier"] == RiskTier.HIGH
    assert result["policy_decision"]["is_auto_actionable"] is False
    assert result["status"] == "ESCALATED_TO_HUMAN"


def test_edge_case_secret_detected_during_lint_escalates_to_high(temp_log_dir):
    """
    EDGE CASE:
    A secret detected during lint checks must take precedence over linting and escalate to High Risk.
    """
    logger = AuditLogger(log_dir=temp_log_dir)
    agent = CICDIncidentTriageAgent(audit_logger=logger)

    log = """
    config/prod.env:12:1: E501 Line too long (found AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY123456 in plain text)
    [CRITICAL_SECURITY_ALERT] Raw credentials present in unmasked log stream.
    """
    result = agent.triage_incident(log, stage="lint-and-quality", scenario_id="EDGE-02")

    assert result["policy_decision"]["effective_risk_tier"] == RiskTier.HIGH
    assert result["policy_decision"]["is_auto_actionable"] is False
    assert result["status"] == "ESCALATED_TO_HUMAN"
