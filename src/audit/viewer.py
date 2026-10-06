"""
Audit Trail Viewer and Compliance Summary Dashboard CLI.
"""
import sys

from tabulate import tabulate

from src.audit.logger import AuditLogger


def render_audit_trail(log_dir: str = "logs", filter_tier: str | None = None):
    logger = AuditLogger(log_dir=log_dir)
    records = logger.fetch_all_records()

    if not records:
        print(f"No audit records found in '{log_dir}'.")
        return

    if filter_tier:
        records = [r for r in records if r["effective_risk_tier"].upper() == filter_tier.upper()]

    table_data = []
    auto_resolved_count = 0
    escalated_count = 0
    tier_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

    for r in records:
        tier = r["effective_risk_tier"]
        status = r["status"]
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

        if status == "AUTONOMOUSLY_RESOLVED":
            auto_resolved_count += 1
        else:
            escalated_count += 1

        table_data.append([
            r["id"],
            r["timestamp"][:19],
            r["scenario_id"] or "N/A",
            r["pipeline_stage"][:15],
            r["category"][:22],
            tier,
            f"{r['confidence']:.2f}",
            "YES" if r["is_auto_actionable"] else "NO",
            r["authorized_action"][:20],
            status,
            r["policy_rule"][:16]
        ])

    headers = [
        "ID", "Timestamp", "Scenario", "Stage", "Category",
        "Tier", "Conf", "Auto?", "Action", "Status", "Policy Rule"
    ]

    print("\n" + "=" * 115)
    print("AI AGENT CI/CD INCIDENT TRIAGE AUDIT LOG & COMPLIANCE REPORT")
    print("=" * 115)
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))

    total = len(records)
    print("\n--- COMPLIANCE & GOVERNANCE SUMMARY ---")
    print(f"Total Triage Cycles Audited:    {total}")
    print(f"Autonomous Self-Healing Count:  {auto_resolved_count} ({auto_resolved_count/total*100:.1f}%) [Tier 1 Low Risk]")
    print(f"Human Escalations Routed:       {escalated_count} ({escalated_count/total*100:.1f}%) [Tier 2/3 or Guardrails]")
    print(f"Risk Tier Distribution:         LOW: {tier_counts.get('LOW', 0)} | MED: {tier_counts.get('MEDIUM', 0)} | HIGH: {tier_counts.get('HIGH', 0)}")
    print("=" * 115 + "\n")


if __name__ == "__main__":
    tier_arg = sys.argv[1] if len(sys.argv) > 1 else None
    render_audit_trail(filter_tier=tier_arg)
