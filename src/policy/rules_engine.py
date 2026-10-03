"""
Deterministic Policy Engine for CI/CD Incident Triage and Autonomy Escalation.
This module is the sole authority governing whether an agent may execute an action or must escalate.
"""
from typing import Dict, Any, Optional
from src.parser.models import ParsedIncident
from src.policy.models import RiskTier, ActionType, PolicyDecision


# Hard-coded, immutable allowlist of autonomous actions
PERMITTED_AUTONOMOUS_ACTIONS = {
    ActionType.RETRY_JOB,
    ActionType.RERUN_FAILED_TESTS,
    ActionType.PURGE_CACHE_AND_RETRY,
}

# Invariant Prohibited actions (Never Automate)
INVARIANT_PROHIBITED_ACTIONS = {
    ActionType.AUTO_COMMIT_CODE,
    ActionType.MODIFY_PRODUCTION_CONFIG,
    ActionType.BYPASS_SECURITY_GATE,
    ActionType.ACCESS_RAW_SECRETS,
    ActionType.TRIGGER_PROD_ROLLBACK,
}

# Max automated retries before circuit breaker trips
MAX_AUTONOMOUS_RETRIES = 2
MIN_AUTONOMOUS_CONFIDENCE = 0.85


def is_prohibited_action(action: ActionType) -> bool:
    """Returns True if the action is explicitly on the invariant prohibited list."""
    return action in INVARIANT_PROHIBITED_ACTIONS


def is_permitted_low_risk_action(action: ActionType) -> bool:
    """Returns True if the action is on the strict low-risk allowlist."""
    return action in PERMITTED_AUTONOMOUS_ACTIONS


def is_auto_actionable(
    failure: ParsedIncident,
    confidence: float,
    action: ActionType,
    retry_count: int = 0,
    kill_switch_active: bool = False,
) -> bool:
    """
    Pure boolean evaluation function: determines if an action may execute autonomously.
    """
    if kill_switch_active:
        return False
    if is_prohibited_action(action):
        return False
    if retry_count >= MAX_AUTONOMOUS_RETRIES:
        return False
    if confidence < MIN_AUTONOMOUS_CONFIDENCE:
        return False
    if not is_permitted_low_risk_action(action):
        return False
    return True


class EscalationPolicyEngine:
    """
    Inspectable Rules Engine implementing the formal CI/CD escalation policy.
    """

    def __init__(self, kill_switch_active: bool = False):
        self.kill_switch_active = kill_switch_active

    def evaluate_policy(
        self,
        failure: ParsedIncident,
        classification: Dict[str, Any],
        requested_action: Optional[ActionType] = None,
        retry_count: int = 0,
    ) -> PolicyDecision:
        """
        Evaluates the incident against all governance rules, invariant constraints,
        and circuit breakers, returning a definitive PolicyDecision.
        """
        tier_str = classification.get("predicted_risk_tier", "HIGH")
        confidence = float(classification.get("confidence", 0.0))
        category = classification.get("category", "UNKNOWN_FAILURE")

        # Map requested or default action
        if requested_action is None:
            if tier_str == "LOW":
                # Derive default low risk action
                if category == "RUNNER_DISK_EXHAUSTION":
                    target_action = ActionType.PURGE_CACHE_AND_RETRY
                elif category == "FLAKY_TEST":
                    target_action = ActionType.RERUN_FAILED_TESTS
                else:
                    target_action = ActionType.RETRY_JOB
            elif tier_str == "MEDIUM":
                target_action = ActionType.ESCALATE_WITH_PATCH_PROPOSAL
            else:
                target_action = ActionType.MANDATORY_HUMAN_ESCALATION
        else:
            target_action = requested_action

        # RULE 1: KILL SWITCH ENGAGED
        if self.kill_switch_active:
            return PolicyDecision(
                is_auto_actionable=False,
                authorized_action=ActionType.MANDATORY_HUMAN_ESCALATION,
                effective_risk_tier=RiskTier.HIGH,
                requires_human_approval=True,
                kill_switch_active=True,
                rule_code="POL-GUARD-01-KILL-SWITCH",
                justification="Master autonomy kill switch is ACTIVE. All autonomous operations suspended.",
                guardrail_violations=["AUTONOMY_KILL_SWITCH_ACTIVE"],
                audit_metadata={"retry_count": retry_count, "original_action": target_action.value}
            )

        # RULE 2: INVARIANT PROHIBITED ACTIONS
        if is_prohibited_action(target_action):
            return PolicyDecision(
                is_auto_actionable=False,
                authorized_action=ActionType.MANDATORY_HUMAN_ESCALATION,
                effective_risk_tier=RiskTier.HIGH,
                requires_human_approval=True,
                rule_code="POL-INVARIANT-01-PROHIBITED-ACTION",
                justification=f"Action '{target_action.value}' violates invariant safety policy (Never-Automate list).",
                guardrail_violations=[f"PROHIBITED_ACTION_{target_action.value}"],
                audit_metadata={"rejected_action": target_action.value}
            )

        # RULE 3: CIRCUIT BREAKER (EXCEEDED MAX RETRIES)
        if retry_count >= MAX_AUTONOMOUS_RETRIES:
            return PolicyDecision(
                is_auto_actionable=False,
                authorized_action=ActionType.MANDATORY_HUMAN_ESCALATION,
                effective_risk_tier=RiskTier.HIGH,
                requires_human_approval=True,
                circuit_breaker_tripped=True,
                rule_code="POL-GUARD-02-CIRCUIT-BREAKER",
                justification=(
                    f"Circuit breaker tripped: Automated retry limit ({MAX_AUTONOMOUS_RETRIES}) reached. "
                    "Escalating to human on-call to prevent infinite loops."
                ),
                guardrail_violations=["CIRCUIT_BREAKER_MAX_RETRIES_EXCEEDED"],
                audit_metadata={"retry_count": retry_count}
            )

        # RULE 4: PRODUCTION/DEPLOYMENT STAGE BOUNDARY (BLAST RADIUS OVERRIDE)
        # Even if a failure looks like a low-risk timeout, if it occurs during deployment/staging,
        # it carries production blast radius and must strictly escalate to High Risk.
        if failure.pipeline_stage in ["deploy-simulation", "production-deploy", "deploy", "staging-deploy"]:
            return PolicyDecision(
                is_auto_actionable=False,
                authorized_action=ActionType.MANDATORY_HUMAN_ESCALATION,
                effective_risk_tier=RiskTier.HIGH,
                requires_human_approval=True,
                rule_code="POL-STAGE-01-PROD-BOUNDARY",
                justification=(
                    f"Incident occurred in deployment stage '{failure.pipeline_stage}'. "
                    "Production/staging environment mutations carry high blast radius and strictly forbid autonomous action."
                ),
                audit_metadata={"stage": failure.pipeline_stage, "category": category}
            )

        # RULE 5: HIGH RISK TIER ENFORCEMENT
        if tier_str == "HIGH" or category.startswith("SECURITY") or category.startswith("PRODUCTION") or category.startswith("SECRET"):
            return PolicyDecision(
                is_auto_actionable=False,
                authorized_action=ActionType.MANDATORY_HUMAN_ESCALATION,
                effective_risk_tier=RiskTier.HIGH,
                requires_human_approval=True,
                rule_code="POL-TIER3-HIGH-RISK-ESCALATE",
                justification=(
                    f"High-risk incident ({category}). Potential blast radius affects production/security perimeter. "
                    "Mandatory human operator oversight required."
                ),
                audit_metadata={"category": category, "confidence": confidence}
            )

        # RULE 6: LOW CONFIDENCE UNCERTAINTY FALLBACK
        if confidence < MIN_AUTONOMOUS_CONFIDENCE:
            return PolicyDecision(
                is_auto_actionable=False,
                authorized_action=ActionType.MANDATORY_HUMAN_ESCALATION,
                effective_risk_tier=RiskTier.HIGH,
                requires_human_approval=True,
                rule_code="POL-EPISTEMIC-01-LOW-CONFIDENCE",
                justification=(
                    f"Classification confidence ({confidence:.2f}) is below minimum threshold ({MIN_AUTONOMOUS_CONFIDENCE}). "
                    "Fail-safe policy forces escalation."
                ),
                guardrail_violations=["INSUFFICIENT_CLASSIFIER_CONFIDENCE"],
                audit_metadata={"confidence": confidence, "threshold": MIN_AUTONOMOUS_CONFIDENCE}
            )

        # RULE 7: MEDIUM RISK TIER (ASSISTED ESCALATION)
        if tier_str == "MEDIUM":
            return PolicyDecision(
                is_auto_actionable=False,
                authorized_action=ActionType.ESCALATE_WITH_PATCH_PROPOSAL,
                effective_risk_tier=RiskTier.MEDIUM,
                requires_human_approval=True,
                rule_code="POL-TIER2-MEDIUM-RISK-ASSIST",
                justification=(
                    f"Medium-risk incident ({category}). Mutable code or configuration changes required. "
                    "Agent generates patch diff for human engineer approval."
                ),
                audit_metadata={"category": category, "confidence": confidence}
            )

        # RULE 8: LOW RISK TIER (AUTONOMOUS EXECUTION AUTHORIZED)
        if tier_str == "LOW" and is_permitted_low_risk_action(target_action):
            return PolicyDecision(
                is_auto_actionable=True,
                authorized_action=target_action,
                effective_risk_tier=RiskTier.LOW,
                requires_human_approval=False,
                rule_code="POL-TIER1-LOW-RISK-AUTO",
                justification=(
                    f"Low-risk incident ({category}). Action '{target_action.value}' is idempotent, fully reversible, "
                    "and bounded to ephemeral runner with zero production blast radius."
                ),
                audit_metadata={"category": category, "confidence": confidence, "retry_count": retry_count}
            )


        # Catch-all safe fallback
        return PolicyDecision(
            is_auto_actionable=False,
            authorized_action=ActionType.MANDATORY_HUMAN_ESCALATION,
            effective_risk_tier=RiskTier.HIGH,
            requires_human_approval=True,
            rule_code="POL-FALLTHROUGH-SAFETY",
            justification="Unmatched policy condition. Defaulting to safe human escalation.",
            guardrail_violations=["UNMATCHED_POLICY_FALLTHROUGH"],
        )
