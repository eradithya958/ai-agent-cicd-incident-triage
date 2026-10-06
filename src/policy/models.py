"""
Data models and Enums for the CI/CD Risk-Tiering & Escalation Policy Engine.
"""
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ActionType(str, Enum):
    # Permitted Low-Risk Autonomous Actions
    RETRY_JOB = "RETRY_JOB"
    RERUN_FAILED_TESTS = "RERUN_FAILED_TESTS"
    PURGE_CACHE_AND_RETRY = "PURGE_CACHE_AND_RETRY"

    # Permitted Medium-Risk Assisted Actions (Human-in-the-loop)
    ESCALATE_WITH_PATCH_PROPOSAL = "ESCALATE_WITH_PATCH_PROPOSAL"
    CREATE_DEFECT_TICKET = "CREATE_DEFECT_TICKET"
    POST_PR_REVIEW_COMMENT = "POST_PR_REVIEW_COMMENT"

    # High-Risk Strict Escalation Actions
    MANDATORY_HUMAN_ESCALATION = "MANDATORY_HUMAN_ESCALATION"
    HALT_PIPELINE_AND_ALERT = "HALT_PIPELINE_AND_ALERT"
    SECURITY_FREEZE = "SECURITY_FREEZE"

    # Invariant Prohibited Actions (Never Automate)
    AUTO_COMMIT_CODE = "AUTO_COMMIT_CODE"
    MODIFY_PRODUCTION_CONFIG = "MODIFY_PRODUCTION_CONFIG"
    BYPASS_SECURITY_GATE = "BYPASS_SECURITY_GATE"
    ACCESS_RAW_SECRETS = "ACCESS_RAW_SECRETS"
    TRIGGER_PROD_ROLLBACK = "TRIGGER_PROD_ROLLBACK"


class PolicyDecision(BaseModel):
    """
    Formal decision object produced by the deterministic Policy Engine.
    """
    is_auto_actionable: bool = Field(..., description="True if agent is permitted to execute action autonomously")
    authorized_action: ActionType = Field(..., description="The approved action type")
    effective_risk_tier: RiskTier = Field(..., description="Final risk tier enforced by policy")
    requires_human_approval: bool = Field(..., description="True if human oversight/signoff is required")
    circuit_breaker_tripped: bool = Field(False, description="True if rate limit/retry threshold was exceeded")
    kill_switch_active: bool = Field(False, description="True if emergency kill switch is engaged")
    rule_code: str = Field(..., description="Specific policy rule identifier enforced")
    justification: str = Field(..., description="Formal SRE/governance rationale for the decision")
    guardrail_violations: list[str] = Field(default_factory=list, description="Any detected guardrail violations")
    audit_metadata: dict[str, Any] = Field(default_factory=dict, description="Audit logging payload")
