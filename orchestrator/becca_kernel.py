#!/usr/bin/env python3
"""
becca_kernel.py - BECCA Automation Kernel v2.0

The main dispatcher that orchestrates the full pipeline:
  MQ (Mission Queue) → BQ (Bee Queue) → Ghost (Archivist)

Pipeline:
  1. MQ receives mission, generates PLAN.json
  2. BQ executes plan with gates and validation
  3. Ghost collects evidence and generates reports

Usage:
    python becca_kernel.py --project sonny --mission "Find hardcoded secrets"
    python becca_kernel.py --project sonny --mission "Audit security rules" --scan-mode deep
    python becca_kernel.py --plan path/to/PLAN.json  # Resume from existing plan

Components:
  - MQ Planner: Mission → Plan conversion
  - BQ Executor: Plan → Task execution
  - Ghost Archivist: Results → Reports

Protocol contracts:
  - PLAN.json: Task definitions with inputs/outputs/stop conditions
  - RESULT.json: Per-task execution results
  - RISKS.json: Aggregated security findings
  - EVIDENCE_INDEX.json: Artifact catalog
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# Add orchestrator to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.mq_planner import MQPlanner, generate_plan
from agents.bq_executor import BQExecutor, run_bq_executor
from agents.ghost_archivist import GhostArchivist, run_ghost_archivist
from agents.verifier import RunVerifier, verify_run

# Base paths
BECCA_ROOT = Path(__file__).parent.parent
RUNS_DIR = BECCA_ROOT / "governance" / "runs"
LEDGER_PATH = BECCA_ROOT / "governance" / "command-center" / "ledger" / "RUN_LEDGER.jsonl"
PROJECTS_FILE = BECCA_ROOT / "governance" / "specs" / "PROJECTS.json"


def load_projects() -> dict:
    """Load project configurations."""
    if PROJECTS_FILE.exists():
        with open(PROJECTS_FILE) as f:
            config = json.load(f)
        return config.get("projects", {})

    # Fallback defaults
    return {
        "sonny": {"path": "d:/projects/sonny"},
        "colony-os": {"path": "d:/projects/colony-os"},
    }


def generate_run_id(project: str) -> str:
    """Generate unique run ID."""
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return f"RUN-{project.upper()}-{timestamp}"


def create_run_directory(run_id: str) -> Path:
    """Create run directory structure."""
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Create agent subdirectories
    (run_dir / "mq_planner" / "evidence").mkdir(parents=True, exist_ok=True)
    (run_dir / "bq_executor" / "evidence").mkdir(parents=True, exist_ok=True)
    (run_dir / "ghost_archivist" / "evidence").mkdir(parents=True, exist_ok=True)
    (run_dir / "tool_inspector" / "evidence").mkdir(parents=True, exist_ok=True)
    (run_dir / "backups").mkdir(parents=True, exist_ok=True)

    return run_dir


def append_to_ledger(run_id: str, event_type: str, details: dict = None):
    """Append event to global ledger."""
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)

    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "run_id": run_id,
        "event": event_type,
        **(details or {})
    }

    with open(LEDGER_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")


def init_run_state(run_id: str, project: str, mission: str, run_dir: Path) -> dict:
    """Initialize RUN_STATE.json."""
    now = datetime.utcnow().isoformat() + "Z"

    state = {
        "run_id": run_id,
        "project_id": project,
        "mission": mission,
        "current_state": "INIT",
        "state_history": [{"state": "INIT", "entered_at": now}],
        "agents": ["mq_planner", "bq_executor", "ghost_archivist"],
        "agents_completed": [],
        "created_at": now,
        "updated_at": now,
    }

    state_file = run_dir / "RUN_STATE.json"
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)

    return state


def transition_state(run_dir: Path, new_state: str):
    """Transition to a new state."""
    state_file = run_dir / "RUN_STATE.json"

    with open(state_file) as f:
        state = json.load(f)

    now = datetime.utcnow().isoformat() + "Z"

    state["state_history"].append({"state": new_state, "entered_at": now})
    state["current_state"] = new_state
    state["updated_at"] = now

    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)


class BECCAKernel:
    """
    BECCA Automation Kernel - The Queen's Command Center.

    Orchestrates: MQ → BQ → Ghost
    """

    VERSION = "2.0.0"

    def __init__(self, project: str, mission: str = None, plan_path: Path = None, scan_mode: str = "fast"):
        self.project = project
        self.mission = mission
        self.plan_path = Path(plan_path) if plan_path else None
        self.scan_mode = scan_mode

        # Load project config
        projects = load_projects()
        if project not in projects:
            raise ValueError(f"Unknown project: {project}. Available: {list(projects.keys())}")

        project_config = projects[project]
        self.project_path = Path(project_config.get("path", f"d:/projects/{project}"))

        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {self.project_path}")

        # Generate run ID
        self.run_id = generate_run_id(project)
        self.run_dir = create_run_directory(self.run_id)

        # State tracking
        self.plan: dict = {}
        self.results: list = []
        self.archive_output: dict = {}

    def run(self) -> dict:
        """
        Execute full kernel pipeline.

        Returns dict with final status and outputs.
        """
        print("\n" + "=" * 70)
        print("  BECCA Kernel v2.0 - Automation Pipeline")
        print("=" * 70)

        print(f"\n  Run ID:     {self.run_id}")
        print(f"  Project:    {self.project} ({self.project_path})")
        print(f"  Mission:    {self.mission or 'From plan file'}")
        print(f"  Scan Mode:  {self.scan_mode}")
        print(f"  Run Dir:    {self.run_dir}")

        # Initialize state
        init_run_state(self.run_id, self.project, self.mission or "", self.run_dir)
        append_to_ledger(self.run_id, "KERNEL_STARTED", {
            "project": self.project,
            "mission": self.mission,
            "version": self.VERSION
        })

        try:
            # Phase 1: Planning (MQ)
            self._run_mq_planner()

            # Phase 2: Execution (BQ)
            self._run_bq_executor()

            # Phase 3: Archival (Ghost)
            self._run_ghost_archivist()

            # Phase 4: Verification (no false greens)
            self._run_verification()

            # Determine final state based on verification
            if self.verified_status.final_status in ["ALL_CLEAR", "OK_WITH_WARNINGS"]:
                transition_state(self.run_dir, "COMPLETE")
            elif self.verified_status.final_status == "STOPPED":
                transition_state(self.run_dir, "STOPPED")
            else:
                transition_state(self.run_dir, "FAILED")

            append_to_ledger(self.run_id, "KERNEL_COMPLETE", {
                "final_status": self.verified_status.final_status,
                "tasks_executed": len(self.results),
                "risks_found": self.archive_output.get("risks_summary", {}).get("total_risks", 0),
                "evidence_items": self.archive_output.get("evidence_summary", {}).get("total_items", 0),
                "verification_passed": self.verified_status.verification.get("passed", False)
            })

            self._print_summary()

            return {
                "status": self.verified_status.final_status.lower(),
                "run_id": self.run_id,
                "run_dir": str(self.run_dir),
                "plan": self.plan,
                "results": self.results,
                "archive": self.archive_output,
                "verification": self.verified_status.to_dict(),
            }

        except Exception as e:
            transition_state(self.run_dir, "HALTED")
            append_to_ledger(self.run_id, "KERNEL_HALTED", {"error": str(e)})

            print(f"\n  [X] KERNEL HALTED: {e}")
            return {
                "status": "halted",
                "run_id": self.run_id,
                "error": str(e),
            }

    def _run_mq_planner(self):
        """Phase 1: Generate or load plan."""
        print("\n" + "-" * 70)
        print("  Phase 1: PLANNING (MQ)")
        print("-" * 70)

        transition_state(self.run_dir, "PLANNING")

        if self.plan_path and self.plan_path.exists():
            # Load existing plan
            print(f"\n      Loading plan from: {self.plan_path}")
            with open(self.plan_path) as f:
                self.plan = json.load(f)
            print(f"      Plan ID: {self.plan.get('plan_id', 'UNKNOWN')}")
            print(f"      Tasks: {len(self.plan.get('tasks', []))}")
        else:
            # Generate new plan
            print(f"\n      Generating plan for mission...")
            planner = MQPlanner(self.mission, self.project, self.run_id)
            self.plan = planner.generate_plan()

            # Apply scan mode override if specified
            if self.scan_mode != "fast":
                for task in self.plan.get("tasks", []):
                    if task.get("tool") == "secrets_scanner":
                        task["inputs"]["scan_mode"] = self.scan_mode

            # Write plan
            plan_path = self.run_dir / "mq_planner" / "evidence" / "PLAN.json"
            planner.write_plan(plan_path)

            print(f"      Plan ID: {self.plan['plan_id']}")
            print(f"      Intent: {self.plan.get('intent', {}).get('category')}/{self.plan.get('intent', {}).get('subcategory')}")
            print(f"      Tasks: {len(self.plan['tasks'])}")

            for task in self.plan["tasks"]:
                print(f"        {task['task_id']}: {task['tool']} ({task['profile']})")

    def _run_bq_executor(self):
        """Phase 2: Execute plan tasks."""
        print("\n" + "-" * 70)
        print("  Phase 2: EXECUTING (BQ)")
        print("-" * 70)

        transition_state(self.run_dir, "EXECUTING")

        # Write plan for BQ (if not already written)
        plan_path = self.run_dir / "mq_planner" / "evidence" / "PLAN.json"
        if not plan_path.exists():
            with open(plan_path, "w") as f:
                json.dump(self.plan, f, indent=2)

        # Run BQ executor
        executor = BQExecutor(plan_path, self.run_dir, self.project_path)
        results = executor.execute()

        # Convert results to dicts
        self.results = [r.to_dict() for r in results]

        # Summary
        successful = sum(1 for r in self.results if r["status"] == "success")
        failed = sum(1 for r in self.results if r["status"] == "failed")
        print(f"\n      Tasks: {len(self.results)} executed, {successful} successful, {failed} failed")

    def _run_ghost_archivist(self):
        """Phase 3: Archive and report."""
        print("\n" + "-" * 70)
        print("  Phase 3: ARCHIVING (Ghost)")
        print("-" * 70)

        transition_state(self.run_dir, "ARCHIVING")

        # Run Ghost archivist
        ghost = GhostArchivist(self.run_dir, self.plan, self.results)
        self.archive_output = ghost.archive()

        # Store risks and evidence for verification
        self._risks_doc = {}
        self._evidence_doc = {}

        risks_path = self.run_dir / "ghost_archivist" / "evidence" / "RISKS.json"
        if risks_path.exists():
            with open(risks_path) as f:
                self._risks_doc = json.load(f)

        evidence_path = self.run_dir / "ghost_archivist" / "evidence" / "EVIDENCE_INDEX.json"
        if evidence_path.exists():
            with open(evidence_path) as f:
                self._evidence_doc = json.load(f)

    def _run_verification(self):
        """Phase 4: Verify run integrity and determine final status."""
        print("\n" + "-" * 70)
        print("  Phase 4: VERIFICATION")
        print("-" * 70)

        transition_state(self.run_dir, "VERIFYING")

        # Run verification
        self.verified_status = verify_run(
            self.run_dir,
            self.plan,
            self.results,
            self._risks_doc,
            self._evidence_doc
        )

        # Print verification summary
        v = self.verified_status.verification
        passed = v.get("passed", False)
        total_checks = len(v.get("checks", []))
        failed_checks = len(v.get("failed_checks", []))

        status_icon = "[OK]" if passed else "[X]"
        print(f"\n      {status_icon} Verification: {total_checks - failed_checks}/{total_checks} checks passed")

        if not passed:
            print(f"      Failed checks:")
            for fc in v.get("failed_checks", [])[:5]:  # Show first 5
                print(f"        - {fc}")

        print(f"      Final Status: {self.verified_status.final_status}")
        print(f"      Reason: {self.verified_status.status_reason}")

    def _print_summary(self):
        """Print final summary using verified status."""
        print("\n" + "=" * 70)
        print("  KERNEL COMPLETE")
        print("=" * 70)

        # Use verified status (no false greens)
        final_status = self.verified_status.final_status
        status_reason = self.verified_status.status_reason
        task_summary = self.verified_status.task_summary
        risk_summary = self.verified_status.risk_summary

        # Map final status to display
        status_display = {
            "ALL_CLEAR": "[OK] ALL CLEAR",
            "OK_WITH_WARNINGS": "[*] OK WITH WARNINGS",
            "STOPPED": "[!] STOPPED",
            "FAILED": "[X] FAILED",
            "FAILED_VERIFY": "[X] FAILED_VERIFY",
        }.get(final_status, f"[?] {final_status}")

        print(f"\n  Status:     {status_display}")
        print(f"  Reason:     {status_reason}")
        print(f"  Run ID:     {self.run_id}")

        # Task breakdown by status
        by_status = task_summary.get("by_status", {})
        task_line = ", ".join(f"{s}: {c}" for s, c in by_status.items() if c > 0)
        print(f"  Tasks:      {task_summary.get('total', 0)} ({task_line})")

        # Risk breakdown
        print(f"  Risks:      {risk_summary.get('critical', 0)} CRIT, "
              f"{risk_summary.get('high', 0)} HIGH, "
              f"{risk_summary.get('medium', 0)} MED, "
              f"{risk_summary.get('low', 0)} LOW")
        print(f"  Evidence:   {self.archive_output.get('evidence_summary', {}).get('total_items', 0)} items")
        print(f"\n  Report:     {self.archive_output.get('report_path', 'N/A')}")
        print(f"  Run Dir:    {self.run_dir}")
        print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="BECCA Kernel v2.0 - Automation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run security audit
  python becca_kernel.py --project sonny --mission "Find hardcoded secrets"

  # Deep scan
  python becca_kernel.py --project sonny --mission "Security audit" --scan-mode deep

  # Resume from plan
  python becca_kernel.py --project sonny --plan ./PLAN.json
        """
    )

    parser.add_argument("--project", required=True, help="Target project ID")
    parser.add_argument("--mission", help="Mission statement")
    parser.add_argument("--plan", help="Path to existing PLAN.json")
    parser.add_argument("--scan-mode", choices=["fast", "deep", "release"], default="fast",
                        help="Scan mode for secrets scanner")

    args = parser.parse_args()

    # Validate args
    if not args.mission and not args.plan:
        parser.error("Either --mission or --plan is required")

    try:
        kernel = BECCAKernel(
            project=args.project,
            mission=args.mission,
            plan_path=args.plan,
            scan_mode=args.scan_mode
        )

        result = kernel.run()
        # Exit 0 for ALL_CLEAR or OK_WITH_WARNINGS, 1 for FAILED/STOPPED/FAILED_VERIFY
        success_statuses = {"all_clear", "ok_with_warnings"}
        sys.exit(0 if result["status"] in success_statuses else 1)

    except Exception as e:
        print(f"\n[X] ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
