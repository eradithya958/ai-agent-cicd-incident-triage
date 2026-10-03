"""
Human-in-the-Loop Incident Reporter.
Generates structured incident reports, proposed code patches, and notifications for human engineers.
"""
import json
import os
import time
from typing import Dict, Any, Optional
from src.parser.models import ParsedIncident
from src.policy.models import PolicyDecision, RiskTier


class IncidentReporter:
    """
    Formats, documents, and persists escalation reports for human-in-the-loop review.
    """

    def __init__(self, output_dir: str = "incidents/tickets"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_report(
        self,
        incident: ParsedIncident,
        classification: Dict[str, Any],
        decision: PolicyDecision,
        patch_proposal: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Synthesizes a structured incident ticket and saves it to disk.
        """
        incident_id = incident.incident_id or f"INC-{int(time.time() * 1000)}"
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Generate contextual patch proposal or recommendation if not provided
        if patch_proposal is None:
            patch_proposal = self._derive_patch_proposal(incident, classification)

        report = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "pipeline_stage": incident.pipeline_stage,
            "scenario_id": incident.scenario_id,
            "failure_signature": incident.failure_signature,
            "error_type": incident.error_type,
            "assigned_category": classification.get("category"),
            "risk_tier": decision.effective_risk_tier.value,
            "classification_confidence": classification.get("confidence"),
            "policy_rule_enforced": decision.rule_code,
            "policy_justification": decision.justification,
            "requires_human_approval": decision.requires_human_approval,
            "diagnostic_summary": classification.get("reasoning", "No diagnosis provided"),
            "recommended_patch_proposal": patch_proposal,
            "raw_error_message": incident.error_message,
            "stack_trace_excerpt": incident.stack_trace[:800] if incident.stack_trace else None,
            "escalation_channel": "slack-#platform-incident-triage" if decision.effective_risk_tier == RiskTier.HIGH else "github-pr-review-queue",
        }

        # Save JSON ticket
        ticket_json_path = os.path.join(self.output_dir, f"{incident_id}.json")
        with open(ticket_json_path, "w") as f:
            json.dump(report, f, indent=2)

        # Save human-readable Markdown brief
        ticket_md_path = os.path.join(self.output_dir, f"{incident_id}.md")
        with open(ticket_md_path, "w") as f:
            f.write(self._format_markdown_brief(report))

        report["json_path"] = ticket_json_path
        report["md_path"] = ticket_md_path
        return report

    def _derive_patch_proposal(self, incident: ParsedIncident, classification: Dict[str, Any]) -> str:
        cat = classification.get("category", "")
        if cat == "CODE_REGRESSION_BUG":
            return (
                "```diff\n"
                "--- a/app/models.py\n"
                "+++ b/app/models.py\n"
                "@@ -15,3 +15,3 @@\n"
                "-    speed_kmh: int\n"
                "+    speed_kmh: float\n"
                "```\n"
                "Rationale: Schema validation failed because incoming sensor floats were rejected by integer constraint."
            )
        elif cat == "DEPENDENCY_VERSION_CONFLICT":
            return (
                "```diff\n"
                "--- a/requirements.txt\n"
                "+++ b/requirements.txt\n"
                "@@ -1,2 +1,2 @@\n"
                "-pydantic>=2.6.0\n"
                "+pydantic>=1.10.15,<2.0.0\n"
                "```\n"
                "Rationale: Pinned pydantic to compatible v1.x branch to satisfy legacy-sensor-sdk constraints."
            )
        elif cat == "LINT_OR_QUALITY_GATE_FAILURE":
            return (
                "```bash\n"
                "ruff check . --fix\n"
                "```\n"
                "Autofix suggestions: Remove unused imports (F401), split long line (E501), and prune unused variable (F841)."
            )
        elif cat == "SECURITY_VULNERABILITY_DETECTED":
            return (
                "ACTION REQUIRED: Upgrade `libcrypto` dependency to >= 1.1.1t to mitigate CVE-2026-901.\n"
                "SecOps review mandatory prior to release unblock."
            )
        elif cat == "PRODUCTION_DEPLOYMENT_FAILURE":
            return (
                "ACTION REQUIRED: Run database schema migration sync `alembic upgrade head` on staging cluster.\n"
                "Canary deployment failed health check due to schema version divergence."
            )
        elif cat == "SECRET_OR_CREDENTIAL_LEAK":
            return (
                "CRITICAL ACTION REQUIRED: Invalidate and rotate exposed AWS/GitHub tokens immediately.\n"
                "Check `config/deploy_staging.env` and purge from git commit history."
            )
        return "Manual human triage and investigation required."

    def _format_markdown_brief(self, report: Dict[str, Any]) -> str:
        return f"""# Incident Report: {report['incident_id']}

**Risk Tier:** `{report['risk_tier']}`  
**Pipeline Stage:** `{report['pipeline_stage']}`  
**Failure Signature:** `{report['failure_signature']}`  
**Category:** `{report['assigned_category']}` (Confidence: {report['classification_confidence']})  
**Escalation Channel:** `{report['escalation_channel']}`  

---

### Policy Decision & Governance
- **Policy Rule Enforced:** `{report['policy_rule_enforced']}`
- **Human Sign-off Required:** `{report['requires_human_approval']}`
- **Justification:** {report['policy_justification']}

---

### Diagnostic Summary
{report['diagnostic_summary']}

---

### Recommended Remediation / Patch Proposal
{report['recommended_patch_proposal']}

---

### Log Excerpt / Error Details
```
{report['raw_error_message']}
```
"""
