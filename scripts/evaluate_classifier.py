"""
Evaluation and Benchmarking Script for CI/CD Failure Detection & Diagnosis (Phase 1).
Runs the parser and hybrid classifier across all labeled test fixtures and outputs metrics.
"""
import glob
import json
import os
import sys

from tabulate import tabulate

# Ensure project root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.classifier.hybrid_classifier import HybridTriageClassifier
from src.parser.log_parser import CICDLogParser


def evaluate_dataset(fixtures_dir: str):
    parser = CICDLogParser()
    hybrid_classifier = HybridTriageClassifier()

    fixture_files = sorted(glob.glob(os.path.join(fixtures_dir, "*.json")))
    if not fixture_files:
        print(f"No fixture files found in {fixtures_dir}")
        return

    results_table = []
    correct_category_count = 0
    correct_tier_count = 0
    total_count = len(fixture_files)
    false_positives_low_risk = 0 # Count if Med/High misclassified as Low

    for fpath in fixture_files:
        with open(fpath, "r") as f:
            data = json.load(f)

        scenario_id = data["scenario_id"]
        expected_cat = data["expected_category"]
        expected_tier = data["expected_risk_tier"]
        raw_log = data["log_content"]
        stage = data.get("pipeline_stage")

        # 1. Parse log
        parsed = parser.parse(raw_log, explicit_stage=stage, scenario_id=scenario_id)

        # 2. Hybrid Classification
        triage = hybrid_classifier.classify(parsed)
        pred_cat = triage["category"]
        pred_tier = triage["predicted_risk_tier"]
        confidence = triage["confidence"]
        path = triage.get("triage_pipeline_path", "stage1")

        is_cat_correct = (pred_cat == expected_cat)
        is_tier_correct = (pred_tier == expected_tier)

        if is_cat_correct:
            correct_category_count += 1
        if is_tier_correct:
            correct_tier_count += 1

        # Check critical safety false positive: High or Med predicted as Low
        if expected_tier in ["MEDIUM", "HIGH"] and pred_tier == "LOW":
            false_positives_low_risk += 1
            safety_status = "CRITICAL_SAFETY_BREACH"
        else:
            safety_status = "SAFE"

        results_table.append([
            scenario_id,
            data["name"][:28],
            expected_tier,
            pred_tier,
            f"{confidence:.2f}",
            "MATCH" if is_cat_correct else "MISMATCH",
            path,
            safety_status
        ])

    headers = ["Scenario ID", "Name", "Exp Tier", "Pred Tier", "Conf", "Category", "Pipeline Path", "Safety"]
    print("\n" + "=" * 95)
    print("PHASE 1: CI/CD FAILURE CLASSIFIER EVALUATION REPORT")
    print("=" * 95)
    print(tabulate(results_table, headers=headers, tablefmt="fancy_grid"))

    cat_accuracy = (correct_category_count / total_count) * 100.0
    tier_accuracy = (correct_tier_count / total_count) * 100.0

    print("\n--- SUMMARY METRICS ---")
    print(f"Total Scenarios Evaluated:         {total_count}")
    print(f"Category Classification Accuracy: {cat_accuracy:.1f}% ({correct_category_count}/{total_count})")
    print(f"Risk Tier Accuracy:               {tier_accuracy:.1f}% ({correct_tier_count}/{total_count})")
    print(f"False Positives (Med/High as Low): {false_positives_low_risk} (Target: 0)")
    print("=" * 95 + "\n")

    return {
        "total": total_count,
        "category_accuracy_pct": cat_accuracy,
        "risk_tier_accuracy_pct": tier_accuracy,
        "critical_safety_false_positives": false_positives_low_risk
    }


if __name__ == "__main__":
    fixtures_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "fixtures"))
    evaluate_dataset(fixtures_path)
