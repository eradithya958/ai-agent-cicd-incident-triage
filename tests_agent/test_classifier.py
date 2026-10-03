"""
Tests for Rule-based, LLM, and Hybrid Classifiers
"""
import glob
import json
import os
import pytest
from src.parser.log_parser import CICDLogParser
from src.classifier.rule_classifier import RuleBasedClassifier
from src.classifier.llm_classifier import LLMClassifier
from src.classifier.hybrid_classifier import HybridTriageClassifier


@pytest.fixture
def parser():
    return CICDLogParser()


@pytest.fixture
def rule_classifier():
    return RuleBasedClassifier()


@pytest.fixture
def hybrid_classifier():
    return HybridTriageClassifier()


def test_rule_classification_on_timeout(parser, rule_classifier):
    log = "ConnectTimeout: Connection to mock-sensor.internal timed out after 2.0s"
    incident = parser.parse(log, explicit_stage="test-suite")
    result = rule_classifier.classify(incident)

    assert result["category"] == "TRANSIENT_NETWORK_TIMEOUT"
    assert result["predicted_risk_tier"] == "LOW"
    assert result["confidence"] >= 0.80


def test_rule_classification_on_secret_leak(parser, rule_classifier):
    log = "[CRITICAL_SECURITY_ALERT] Potential AWS Access Key ID detected: AKIAIOSFODNN7EXAMPLE"
    incident = parser.parse(log, explicit_stage="security-audit")
    result = rule_classifier.classify(incident)

    assert result["category"] == "SECRET_OR_CREDENTIAL_LEAK"
    assert result["predicted_risk_tier"] == "HIGH"
    assert result["confidence"] >= 0.80


def test_safety_boundary_zero_false_positives_on_high_risk(parser, hybrid_classifier):
    """
    CRITICAL SAFETY REQUIREMENT:
    Ensure no High or Medium risk fixture is ever classified as Low risk.
    """
    fixtures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "fixtures"))
    fixture_files = glob.glob(os.path.join(fixtures_dir, "*.json"))
    assert len(fixture_files) >= 10

    for fpath in fixture_files:
        with open(fpath, "r") as f:
            data = json.load(f)

        expected_tier = data["expected_risk_tier"]
        incident = parser.parse(data["log_content"], explicit_stage=data["pipeline_stage"])
        res = hybrid_classifier.classify(incident)

        # Invariant: Never downgrade High or Medium to Low
        if expected_tier in ["HIGH", "MEDIUM"]:
            assert res["predicted_risk_tier"] != "LOW", (
                f"SAFETY BREACH in {data['scenario_id']}: Expected {expected_tier}, but got LOW!"
            )
