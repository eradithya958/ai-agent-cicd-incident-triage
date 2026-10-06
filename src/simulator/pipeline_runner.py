"""
CI Pipeline Simulation Runner.
Executes or simulates the 5 pipeline stages and injects deliberate failures for test runs.
"""
import time
from typing import Any, ClassVar


class PipelineSimulator:
    """
    Simulates the 5-stage Fleet Telemetry CI pipeline, capable of injecting specific scenarios.
    """

    STAGES: ClassVar[list[str]] = [
        "lint-and-quality",
        "security-audit",
        "test-suite",
        "build-package",
        "deploy-simulation"
    ]

    def __init__(self, scenario_fixture_data: dict[str, Any] | None = None):
        self.scenario = scenario_fixture_data

    def run_pipeline(self, target_scenario_id: str | None = None) -> dict[str, Any]:
        """
        Executes stages in order. If a failure scenario is active for a stage, stops and returns failure log.
        """
        run_id = f"RUN-{int(time.time() * 1000)}"
        logs = []
        status = "SUCCESS"
        failed_stage = None
        raw_failure_log = ""

        logs.append(f"[{time.strftime('%X')}] [CI_ENGINE] Initializing pipeline run {run_id} for fleet-telemetry-gateway...")

        for stage in self.STAGES:
            logs.append(f"[{time.strftime('%X')}] [CI_ENGINE] Starting Stage: {stage} ...")

            # Check if this stage should fail based on injected scenario
            if self.scenario and self.scenario.get("pipeline_stage") == stage:
                status = "FAILED"
                failed_stage = stage
                raw_failure_log = self.scenario["log_content"]
                logs.append(f"[{time.strftime('%X')}] [STAGE_ERROR] Stage {stage} failed with non-zero exit code.")
                logs.append(raw_failure_log)
                break
            else:
                logs.append(f"[{time.strftime('%X')}] [STAGE_SUCCESS] Stage {stage} completed successfully (0 errors).")

        return {
            "run_id": run_id,
            "status": status,
            "failed_stage": failed_stage,
            "full_log": "\n".join(logs),
            "failure_log": raw_failure_log if status == "FAILED" else "",
            "scenario_id": self.scenario.get("scenario_id") if self.scenario else None,
        }
