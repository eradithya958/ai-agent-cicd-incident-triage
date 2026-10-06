"""
Unit Tests for Deterministic Risk-Tiering & Escalation Policy Engine (Phase 2).
"""
import glob
import json
import os

import pytest

from src.classifier.hybrid_classifier import HybridTriageClassifier
from src.parser.log_parser import CICDLogParser
from src.parser.models import ParsedIncident
from src.policy.models import ActionType, RiskTier
from src.policy.rules_engine import (
    INVARIANT_PROHIBITED_ACTIONS,
    EscalationPolicyEngine,
    is_prohibited_action,
)


@pytest.fixture
def policy_engine():
    return EscalationPolicyEngine()


@pytest.fixture
def mock_low_risk_incident():
    return ParsedIncident(
        pipeline_stage="test-suite",
        failure_signature="NETWORK_TIMEOUT",
        error_type="ConnectTimeout",
        error_message="Connection to mock-sensor.internal timed out",
        raw_log_excerpt="httpx.ConnectTimeout"
    )


def test_low_risk_auto_action_allowed(policy_engine, mock_low_risk_incident):
    classification = {
        "category": "TRANSIENT_NETWORK_TIMEOUT",
        "predicted_risk_tier": "LOW",
        "confidence": 0.95,
    }
    decision = policy_engine.evaluate_policy(
        mock_low_risk_incident,
        classification,
        requested_action=ActionType.RETRY_JOB,
        retry_count=0
    )

    assert decision.is_auto_actionable is True
    assert decision.effective_risk_tier == RiskTier.LOW
    assert decision.authorized_action == ActionType.RETRY_JOB
    assert decision.requires_human_approval is False
    assert decision.rule_code == "POL-TIER1-LOW-RISK-AUTO"


def test_medium_risk_escalate_with_patch(policy_engine):
    incident = ParsedIncident(
        pipeline_stage="test-suite",
        failure_signature="CODE_ASSERTION_REGRESSION",
        error_type="AssertionError",
        error_message="assert 400 == 200",
        raw_log_excerpt="FAILED tests/test_api.py - assert 400 == 200"
    )
    classification = {
        "category": "CODE_REGRESSION_BUG",
        "predicted_risk_tier": "MEDIUM",
        "confidence": 0.95,
    }
    decision = policy_engine.evaluate_policy(incident, classification)

    assert decision.is_auto_actionable is False
    assert decision.effective_risk_tier == RiskTier.MEDIUM
    assert decision.authorized_action == ActionType.ESCALATE_WITH_PATCH_PROPOSAL
    assert decision.requires_human_approval is True
    assert decision.rule_code == "POL-TIER2-MEDIUM-RISK-ASSIST"


def test_high_risk_security_vulnerability_strict_escalation(policy_engine):
    incident = ParsedIncident(
        pipeline_stage="security-audit",
        failure_signature="SECURITY_VULNERABILITY_DETECTED",
        error_type="SecurityVulnerabilityError",
        error_message="CVE-2026-901 in libcrypto",
        raw_log_excerpt="pip-audit: KNOWN VULNERABILITY FOUND"
    )
    classification = {
        "category": "SECURITY_VULNERABILITY_DETECTED",
        "predicted_risk_tier": "HIGH",
        "confidence": 1.0,
    }
    decision = policy_engine.evaluate_policy(incident, classification)

    assert decision.is_auto_actionable is False
    assert decision.effective_risk_tier == RiskTier.HIGH
    assert decision.authorized_action == ActionType.MANDATORY_HUMAN_ESCALATION
    assert decision.requires_human_approval is True
    assert decision.rule_code == "POL-TIER3-HIGH-RISK-ESCALATE"


def test_invariant_prohibited_actions_blocked_under_all_confidence(policy_engine, mock_low_risk_incident):
    """
    CRITICAL CONSTRAINT:
    Even if the LLM or user requests a prohibited action with 1.00 confidence on a Low risk issue,
    the policy engine MUST reject autonomous execution.
    """
    classification = {
        "category": "TRANSIENT_NETWORK_TIMEOUT",
        "predicted_risk_tier": "LOW",
        "confidence": 1.0,
    }

    for prohibited in INVARIANT_PROHIBITED_ACTIONS:
        assert is_prohibited_action(prohibited) is True
        decision = policy_engine.evaluate_policy(
            mock_low_risk_incident,
            classification,
            requested_action=prohibited,
            retry_count=0
        )
        assert decision.is_auto_actionable is False
        assert decision.requires_human_approval is True
        assert decision.rule_code == "POL-INVARIANT-01-PROHIBITED-ACTION"


def test_circuit_breaker_trips_after_max_retries(policy_engine, mock_low_risk_incident):
    classification = {
        "category": "TRANSIENT_NETWORK_TIMEOUT",
        "predicted_risk_tier": "LOW",
        "confidence": 0.95,
    }

    # Attempt 0: Allowed
    d0 = policy_engine.evaluate_policy(mock_low_risk_incident, classification, retry_count=0)
    assert d0.is_auto_actionable is True

    # Attempt 1: Allowed
    d1 = policy_engine.evaluate_policy(mock_low_risk_incident, classification, retry_count=1)
    assert d1.is_auto_actionable is True

    # Attempt 2 (Max reached): Circuit breaker trips
    d2 = policy_engine.evaluate_policy(mock_low_risk_incident, classification, retry_count=2)
    assert d2.is_auto_actionable is False
    assert d2.circuit_breaker_tripped is True
    assert d2.effective_risk_tier == RiskTier.HIGH
    assert d2.rule_code == "POL-GUARD-02-CIRCUIT-BREAKER"


def test_kill_switch_revokes_autonomy_immediately(mock_low_risk_incident):
    killed_engine = EscalationPolicyEngine(kill_switch_active=True)
    classification = {
        "category": "TRANSIENT_NETWORK_TIMEOUT",
        "predicted_risk_tier": "LOW",
        "confidence": 0.99,
    }

    decision = killed_engine.evaluate_policy(mock_low_risk_incident, classification, retry_count=0)
    assert decision.is_auto_actionable is False
    assert decision.kill_switch_active is True
    assert decision.rule_code == "POL-GUARD-01-KILL-SWITCH"


def test_low_confidence_uncertainty_escalation(policy_engine, mock_low_risk_incident):
    # Low confidence (< 0.85) on a low-looking error must force escalation
    classification = {
        "category": "TRANSIENT_NETWORK_TIMEOUT",
        "predicted_risk_tier": "LOW",
        "confidence": 0.65,
    }
    decision = policy_engine.evaluate_policy(mock_low_risk_incident, classification)
    assert decision.is_auto_actionable is False
    assert decision.effective_risk_tier == RiskTier.HIGH
    assert decision.rule_code == "POL-EPISTEMIC-01-LOW-CONFIDENCE"


def test_policy_engine_across_all_10_fixtures():
    parser = CICDLogParser()
    classifier = HybridTriageClassifier()
    policy_engine = EscalationPolicyEngine()

    fixtures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "fixtures"))
    fixture_files = sorted(glob.glob(os.path.join(fixtures_dir, "*.json")))

    for fpath in fixture_files:
        with open(fpath, "r") as f:
            data = json.load(f)

        parsed = parser.parse(data["log_content"], explicit_stage=data["pipeline_stage"])
        triage = classifier.classify(parsed)
        decision = policy_engine.evaluate_policy(parsed, triage)

        expected_tier = data["expected_risk_tier"]

        if expected_tier == "LOW":
            assert decision.is_auto_actionable is True
            assert decision.effective_risk_tier == RiskTier.LOW
        elif expected_tier == "MEDIUM":
            assert decision.is_auto_actionable is False
            assert decision.effective_risk_tier == RiskTier.MEDIUM
            assert decision.authorized_action == ActionType.ESCALATE_WITH_PATCH_PROPOSAL
        elif expected_tier == "HIGH":
            assert decision.is_auto_actionable is False
            assert decision.effective_risk_tier == RiskTier.HIGH
            assert decision.authorized_action == ActionType.MANDATORY_HUMAN_ESCALATION
