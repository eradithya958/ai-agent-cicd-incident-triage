"""
Structured Compliance Audit Logger for Autonomous CI/CD Incident Triage.
Logs every agent evaluation, policy decision, and remediation outcome to SQLite and JSONL.
"""
import json
import os
import sqlite3
import time
from typing import Dict, Any, List, Optional


class AuditLogger:
    """
    Records immutable audit entries for all triage agent operations to SQLite and JSON Lines.
    """

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.db_path = os.path.join(self.log_dir, "audit_trail.db")
        self.jsonl_path = os.path.join(self.log_dir, "audit_trail.jsonl")
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    scenario_id TEXT,
                    pipeline_stage TEXT NOT NULL,
                    category TEXT NOT NULL,
                    effective_risk_tier TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    is_auto_actionable INTEGER NOT NULL,
                    authorized_action TEXT NOT NULL,
                    policy_rule TEXT NOT NULL,
                    status TEXT NOT NULL,
                    circuit_breaker_tripped INTEGER NOT NULL,
                    kill_switch_active INTEGER NOT NULL,
                    justification TEXT,
                    raw_payload TEXT
                )
            """)
            conn.commit()

    def log_triage_decision(self, triage_result: Dict[str, Any]) -> str:
        """
        Persists a complete triage cycle to the SQLite database and JSONL file.
        """
        incident_id = triage_result.get("incident_id") or f"INC-{int(time.time() * 1000)}"
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        scenario_id = triage_result.get("scenario_id")
        stage = triage_result.get("pipeline_stage", "unknown")
        status = triage_result.get("status", "UNKNOWN")

        classification = triage_result.get("classification", {})
        category = classification.get("category", "UNKNOWN")
        confidence = float(classification.get("confidence", 0.0))

        policy = triage_result.get("policy_decision", {})
        effective_tier = policy.get("effective_risk_tier", "HIGH")
        is_auto = 1 if policy.get("is_auto_actionable", False) else 0
        action = policy.get("authorized_action", "UNKNOWN")
        rule_code = policy.get("rule_code", "UNKNOWN")
        cb_tripped = 1 if policy.get("circuit_breaker_tripped", False) else 0
        kill_switch = 1 if policy.get("kill_switch_active", False) else 0
        justification = policy.get("justification", "")

        raw_payload_str = json.dumps(triage_result)

        # 1. Write to SQLite
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_records (
                    incident_id, timestamp, scenario_id, pipeline_stage,
                    category, effective_risk_tier, confidence, is_auto_actionable,
                    authorized_action, policy_rule, status, circuit_breaker_tripped,
                    kill_switch_active, justification, raw_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident_id, timestamp, scenario_id, stage,
                category, effective_tier, confidence, is_auto,
                action, rule_code, status, cb_tripped,
                kill_switch, justification, raw_payload_str
            ))
            conn.commit()

        # 2. Append to JSON Lines file
        record_json = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "scenario_id": scenario_id,
            "pipeline_stage": stage,
            "category": category,
            "effective_risk_tier": effective_tier,
            "confidence": confidence,
            "is_auto_actionable": bool(is_auto),
            "authorized_action": action,
            "policy_rule": rule_code,
            "status": status,
            "circuit_breaker_tripped": bool(cb_tripped),
            "kill_switch_active": bool(kill_switch),
            "justification": justification,
        }
        with open(self.jsonl_path, "a") as f:
            f.write(json.dumps(record_json) + "\n")

        return incident_id

    def fetch_all_records(self) -> List[Dict[str, Any]]:
        """Returns all audit records from SQLite."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_records ORDER BY id DESC")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
