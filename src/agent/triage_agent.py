"""
Autonomous CI/CD Incident Triage Agent with Human-in-the-Loop Escalation.
"""
from typing import Dict, Any, Optional
from src.parser.log_parser import CICDLogParser
from src.parser.models import ParsedIncident
from src.classifier.hybrid_classifier import HybridTriageClassifier
from src.policy.rules_engine import EscalationPolicyEngine
from src.policy.models import PolicyDecision, ActionType
from src.remediation.actions import AutonomousRemediationExecutor
from src.remediation.incident_reporter import IncidentReporter


class CICDIncidentTriageAgent:
    """
    Main Autonomous Triage Agent orchestrating detection, policy-governed triage,
    allowlisted autonomous remediation, and human-in-the-loop escalation.
    """

    def __init__(
        self,
        parser: Optional[CICDLogParser] = None,
        classifier: Optional[HybridTriageClassifier] = None,
        policy_engine: Optional[EscalationPolicyEngine] = None,
        executor: Optional[AutonomousRemediationExecutor] = None,
        reporter: Optional[IncidentReporter] = None,
        kill_switch_active: bool = False,
    ):
        self.parser = parser or CICDLogParser()
        self.classifier = classifier or HybridTriageClassifier()
        self.policy_engine = policy_engine or EscalationPolicyEngine(kill_switch_active=kill_switch_active)
        self.executor = executor or AutonomousRemediationExecutor()
        self.reporter = reporter or IncidentReporter()

    def triage_incident(
        self,
        raw_log: str,
        stage: Optional[str] = None,
        scenario_id: Optional[str] = None,
        retry_count: int = 0,
        requested_action: Optional[ActionType] = None,
    ) -> Dict[str, Any]:
        """
        Full end-to-end incident triage pipeline:
        1. Ingest & Parse
        2. Classify (Rule + LLM fallback)
        3. Policy Authorization Check (with Circuit Breaker & Kill Switch)
        4. Execute Autonomous Action OR Route to Human Escalation Ticket
        """
        # Step 1: Parse CI Log
        parsed_incident: ParsedIncident = self.parser.parse(
            raw_log, explicit_stage=stage, scenario_id=scenario_id
        )

        # Step 2: Diagnostic Classification (Deterministic rules + semantic LLM)
        classification = self.classifier.classify(parsed_incident)

        # Step 3: Policy Engine Authorization (Deterministic boundary)
        decision: PolicyDecision = self.policy_engine.evaluate_policy(
            failure=parsed_incident,
            classification=classification,
            requested_action=requested_action,
            retry_count=retry_count,
        )

        # Step 4: Dispatch based on Policy Decision
        execution_outcome = None
        escalation_report = None

        if decision.is_auto_actionable:
            # Autonomous execution granted (Low risk, idempotent, reversible)
            execution_outcome = self.executor.execute(
                action=decision.authorized_action,
                incident=parsed_incident,
            )
            final_status = "AUTONOMOUSLY_RESOLVED"
        else:
            # Escalation to Human (Medium/High risk or guardrail trip)
            escalation_report = self.reporter.generate_report(
                incident=parsed_incident,
                classification=classification,
                decision=decision,
            )
            final_status = "ESCALATED_TO_HUMAN"

        return {
            "incident_id": parsed_incident.incident_id,
            "scenario_id": parsed_incident.scenario_id,
            "pipeline_stage": parsed_incident.pipeline_stage,
            "status": final_status,
            "parsed_incident": parsed_incident.model_dump(),
            "classification": classification,
            "policy_decision": decision.model_dump(),
            "execution_outcome": execution_outcome,
            "escalation_report": escalation_report,
        }
