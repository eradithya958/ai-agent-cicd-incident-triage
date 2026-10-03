"""
Rule-Based CI/CD Failure Classifier.
Maps structured incident logs to failure taxonomy categories and confidence scores using deterministic patterns.
"""
from typing import Dict, Any
from src.parser.models import ParsedIncident


class RuleBasedClassifier:
    """
    Stage 1 classifier applying pattern-matching rules derived from the failure taxonomy.
    """

    TAXONOMY_CATEGORIES = {
        # LOW RISK
        "TRANSIENT_NETWORK_TIMEOUT": {
            "risk_tier": "LOW",
            "signatures": ["NETWORK_TIMEOUT"],
            "keywords": ["connecttimeout", "read timed out", "max retries exceeded", "timeout"],
        },
        "FLAKY_TEST": {
            "risk_tier": "LOW",
            "signatures": ["ASYNC_TEST_FLAKE"],
            "keywords": ["flaky", "test_async_batch_flush"],
        },
        "RUNNER_DISK_EXHAUSTION": {
            "risk_tier": "LOW",
            "signatures": ["RUNNER_DISK_EXHAUSTED"],
            "keywords": ["enospc", "no space left on device", "errno 28"],
        },
        "DEPENDENCY_DOWNLOAD_TIMEOUT": {
            "risk_tier": "LOW",
            "signatures": ["PACKAGE_MIRROR_CONNECTION_ERROR"],
            "keywords": ["remotedisconnected", "connection reset", "503", "backing index"],
        },

        # MEDIUM RISK
        "CODE_REGRESSION_BUG": {
            "risk_tier": "MEDIUM",
            "signatures": ["CODE_ASSERTION_REGRESSION"],
            "keywords": ["assertionerror", "valueerror", "assert 400 == 200"],
        },
        "DEPENDENCY_VERSION_CONFLICT": {
            "risk_tier": "MEDIUM",
            "signatures": ["DEPENDENCY_RESOLUTION_CONFLICT"],
            "keywords": ["resolutionimpossible", "conflicting dependencies"],
        },
        "LINT_OR_QUALITY_GATE_FAILURE": {
            "risk_tier": "MEDIUM",
            "signatures": ["LINT_STYLE_VIOLATION"],
            "keywords": ["ruff", "lint", "f401", "e501", "f841"],
        },

        # HIGH RISK
        "SECURITY_VULNERABILITY_DETECTED": {
            "risk_tier": "HIGH",
            "signatures": ["SECURITY_VULNERABILITY_DETECTED"],
            "keywords": ["cve-", "pip-audit", "known vulnerability found", "vulnerability"],
        },
        "PRODUCTION_DEPLOYMENT_FAILURE": {
            "risk_tier": "HIGH",
            "signatures": ["CANARY_DEPLOYMENT_FAILED"],
            "keywords": ["canary", "databasemigrationmismatchexception", "500 internal server error", "healthz"],
        },
        "SECRET_OR_CREDENTIAL_LEAK": {
            "risk_tier": "HIGH",
            "signatures": ["SECRET_LEAK_DETECTED"],
            "keywords": ["akia", "ghp_", "raw credentials", "potential aws access key"],
        },
    }

    def classify(self, incident: ParsedIncident) -> Dict[str, Any]:
        """
        Evaluates the parsed incident against rule patterns.
        Returns category, confidence (0.0 - 1.0), and rule explanation.
        """
        raw_text = (incident.raw_log_excerpt + " " + incident.failure_signature + " " + incident.error_message).lower()

        best_category = "UNKNOWN_FAILURE"
        best_tier = "HIGH" # Fail-safe default
        highest_score = 0.0
        matched_rules = []

        for category, config in self.TAXONOMY_CATEGORIES.items():
            score = 0.0
            reasons = []

            # Exact signature match gives high weight
            if incident.failure_signature in config["signatures"]:
                score += 0.65
                reasons.append(f"matched signature '{incident.failure_signature}'")

            # Keyword matches
            matched_kw = [kw for kw in config["keywords"] if kw in raw_text]
            if matched_kw:
                score += min(0.35, len(matched_kw) * 0.15)
                reasons.append(f"matched keywords {matched_kw}")

            # Specific stage alignment
            if category.startswith("SECURITY") and incident.pipeline_stage == "security-audit":
                score += 0.05
            elif category.startswith("PRODUCTION") and incident.pipeline_stage == "deploy-simulation":
                score += 0.05

            final_confidence = min(1.0, round(score, 2))

            if final_confidence > highest_score:
                highest_score = final_confidence
                best_category = category
                best_tier = config["risk_tier"]
                matched_rules = reasons

        # If low confidence or no rule matched
        if highest_score < 0.50:
            return {
                "category": "UNKNOWN_FAILURE",
                "predicted_risk_tier": "HIGH", # High is the safety default
                "confidence": highest_score,
                "reasoning": "No rule pattern matched with sufficient confidence (threshold 0.50).",
                "classifier_type": "rule-based",
                "requires_llm_fallback": True,
            }

        return {
            "category": best_category,
            "predicted_risk_tier": best_tier,
            "confidence": highest_score,
            "reasoning": f"Rule-based match: {'; '.join(matched_rules)}",
            "classifier_type": "rule-based",
            "requires_llm_fallback": highest_score < 0.85,
        }
