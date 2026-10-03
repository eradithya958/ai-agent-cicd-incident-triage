"""
Interactive CI/CD Simulation and Triage CLI
"""
import glob
import json
import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.simulator.pipeline_runner import PipelineSimulator
from src.parser.log_parser import CICDLogParser
from src.classifier.hybrid_classifier import HybridTriageClassifier

console = Console()


def run_interactive_simulation(scenario_id: str = "SCEN-LOW-01"):
    fixtures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "fixtures"))
    fixture_files = glob.glob(os.path.join(fixtures_dir, "*.json"))
    
    scenario_data = None
    target_norm = scenario_id.lower().replace("-", "_")
    for fpath in fixture_files:
        if target_norm in os.path.basename(fpath).lower():
            with open(fpath, "r") as f:
                scenario_data = json.load(f)
                break
        with open(fpath, "r") as f:
            data = json.load(f)
            if data.get("scenario_id", "").lower() == scenario_id.lower():
                scenario_data = data
                break

    if not scenario_data:
        console.print(f"[bold red]Scenario {scenario_id} not found in {fixtures_dir}.[/bold red]")
        return


    console.print(Panel(
        f"[bold cyan]Injecting Scenario:[/bold cyan] {scenario_data['scenario_id']} - {scenario_data['name']}\n"
        f"[bold yellow]Target Stage:[/bold yellow] {scenario_data['pipeline_stage']}\n"
        f"[bold magenta]Expected Tier:[/bold magenta] {scenario_data['expected_risk_tier']}",
        title="CI Pipeline Simulation Engine",
        expand=False
    ))

    # 1. Run Pipeline
    sim = PipelineSimulator(scenario_data)
    run_result = sim.run_pipeline()

    console.print(f"\n[bold white]Pipeline Status:[/bold white] [bold red]{run_result['status']}[/bold red]")
    console.print(f"[bold white]Failed Stage:[/bold white] [bold red]{run_result['failed_stage']}[/bold red]")

    # 2. Ingest & Parse
    parser = CICDLogParser()
    parsed = parser.parse(run_result["failure_log"], explicit_stage=run_result["failed_stage"])

    # 3. Classify
    classifier = HybridTriageClassifier()
    triage = classifier.classify(parsed)

    # 4. Display Triage Report
    table = Table(title="Triage & Classification Result", show_header=True, header_style="bold green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Detected Stage", parsed.pipeline_stage)
    table.add_row("Failure Signature", parsed.failure_signature)
    table.add_row("Error Type", parsed.error_type)
    table.add_row("Assigned Category", triage["category"])
    table.add_row("Risk Tier", f"[bold]{triage['predicted_risk_tier']}[/bold]")
    table.add_row("Confidence", f"{triage['confidence']:.2f}")
    table.add_row("Triage Path", triage.get("triage_pipeline_path", "stage1"))
    table.add_row("Diagnosis / Reasoning", triage.get("reasoning", ""))

    console.print(table)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "SCEN-HIGH-01"
    run_interactive_simulation(target)
