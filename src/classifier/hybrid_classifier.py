"""
Two-Stage Hybrid CI/CD Failure Classifier.
Orchestrates fast deterministic rule matching (Stage 1) with semantic LLM evaluation (Stage 2).
"""
from typing import Dict, Any, Optional
from src.parser.models import ParsedIncident
from src.classifier.rule_classifier import RuleBasedClassifier
from src.classifier.llm_classifier import LLMClassifier


class HybridTriageClassifier:
    """
    Two-stage classifier:
    1. Deterministic pattern matching (high precision, sub-millisecond).
    2. LLM semantic triage fallback (for edge cases, composite logs, or ambiguous patterns).
    """

    def __init__(
        self,
        confidence_threshold: float = 0.80,
        rule_classifier: Optional[RuleBasedClassifier] = None,
        llm_classifier: Optional[LLMClassifier] = None,
    ):
        self.confidence_threshold = confidence_threshold
        self.rule_engine = rule_classifier or RuleBasedClassifier()
        self.llm_engine = llm_classifier or LLMClassifier()

    def classify(self, incident: ParsedIncident) -> Dict[str, Any]:
        """
        Classifies the incident using Stage 1 rules, falling back to Stage 2 LLM when needed.
        """
        rule_result = self.rule_engine.classify(incident)

        # If rule classifier has high confidence and known category, accept immediately
        if (
            rule_result["confidence"] >= self.confidence_threshold
            and rule_result["category"] != "UNKNOWN_FAILURE"
        ):
            rule_result["triage_pipeline_path"] = "stage1-rule-match"
            return rule_result

        # Otherwise invoke Stage 2 LLM semantic triage
        llm_result = self.llm_engine.classify(incident)
        llm_result["triage_pipeline_path"] = "stage2-llm-fallback"
        llm_result["stage1_confidence"] = rule_result["confidence"]
        llm_result["stage1_tentative_category"] = rule_result["category"]

        return llm_result
