"""
LLM-Based CI/CD Failure Classifier.
Leverages local Ollama (or fallback) to synthesize semantic diagnoses and risk evaluations for complex failure traces.
"""
from typing import Any

from src.llm.client import LocalLLMClient
from src.parser.models import ParsedIncident


class LLMClassifier:
    """
    Second-stage classifier using an LLM to evaluate nuanced logs against the failure taxonomy.
    """

    SYSTEM_PROMPT = """You are an expert AIOps Incident Triage AI Agent evaluating CI/CD failures.
Your objective is to classify failures into one of the following exact categories:
- TRANSIENT_NETWORK_TIMEOUT (LOW)
- FLAKY_TEST (LOW)
- RUNNER_DISK_EXHAUSTION (LOW)
- DEPENDENCY_DOWNLOAD_TIMEOUT (LOW)
- CODE_REGRESSION_BUG (MEDIUM)
- DEPENDENCY_VERSION_CONFLICT (MEDIUM)
- LINT_OR_QUALITY_GATE_FAILURE (MEDIUM)
- SECURITY_VULNERABILITY_DETECTED (HIGH)
- PRODUCTION_DEPLOYMENT_FAILURE (HIGH)
- SECRET_OR_CREDENTIAL_LEAK (HIGH)
- UNKNOWN_FAILURE (HIGH)

Respond ONLY with a JSON object matching this schema:
{
  "category": "...",
  "risk_tier": "LOW|MEDIUM|HIGH",
  "confidence": 0.95,
  "root_cause": "...",
  "recommended_action": "RETRY_JOB|RERUN_FAILED_TESTS|PURGE_CACHE_AND_RETRY|ESCALATE_WITH_PATCH_PROPOSAL|MANDATORY_HUMAN_ESCALATION",
  "justification": "..."
}"""

    def __init__(self, llm_client: LocalLLMClient | None = None):
        self.client = llm_client or LocalLLMClient()

    def classify(self, incident: ParsedIncident) -> dict[str, Any]:
        """
        Submits incident context to the LLM for structured triage and diagnosis.
        """
        user_prompt = f"""
Pipeline Stage: {incident.pipeline_stage}
Failure Signature: {incident.failure_signature}
Error Type: {incident.error_type}
Error Message: {incident.error_message}
Extracted Keywords: {', '.join(incident.keywords)}

Raw Log Excerpt:
{incident.raw_log_excerpt[:1500]}
"""
        response_json = self.client.generate_json(
            prompt=user_prompt,
            system_prompt=self.SYSTEM_PROMPT
        )

        return {
            "category": response_json.get("category", "UNKNOWN_FAILURE"),
            "predicted_risk_tier": response_json.get("risk_tier", "HIGH"),
            "confidence": float(response_json.get("confidence", 0.50)),
            "reasoning": f"LLM Diagnosis: {response_json.get('root_cause', '')} - {response_json.get('justification', '')}",
            "classifier_type": "llm-stage2",
            "recommended_action": response_json.get("recommended_action", "MANDATORY_HUMAN_ESCALATION")
        }
