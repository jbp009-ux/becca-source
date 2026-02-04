#!/usr/bin/env python3
"""
becca_mvp.py - Minimum Viable BECCA Automation

This MVP proves the concept with 3 tools:
  1. Inspector - Read/grep codebase
  2. Browser - DevTools capture (console, network, screenshots)
  3. Reporter - Generate final report

Usage:
    python becca_mvp.py --project sonny --mission "Find console errors"
    python becca_mvp.py --project sonny --mission "Check login flow" --url http://localhost:3000
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add tools to path
sys.path.insert(0, str(Path(__file__).parent))

from tools.tool_inspector import run_inspector
from tools.tool_browser import run_browser
from tools.tool_reporter import run_reporter

# Base paths
BECCA_ROOT = Path(__file__).parent.parent
RUNS_DIR = BECCA_ROOT / "governance" / "runs"
LEDGER_PATH = BECCA_ROOT / "governance" / "command-center" / "ledger" / "RUN_LEDGER.jsonl"

# Project paths
PROJECTS = {
    "sonny": Path("d:/projects/sonny"),
    "colony-os": Path("d:/projects/colony-os"),
}


def generate_run_id(project: str) -> str:
    """Generate a unique run ID."""
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return f"RUN-{project.upper()}-{timestamp}"


def create_run_folder(run_id: str) -> Path:
    """Create folder structure for a run."""
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Create subdirectories
    (run_dir / "tool_inspector" / "evidence").mkdir(parents=True, exist_ok=True)
    (run_dir / "tool_browser" / "evidence").mkdir(parents=True, exist_ok=True)
    (run_dir / "tool_reporter" / "evidence").mkdir(parents=True, exist_ok=True)
    (run_dir / "backups").mkdir(parents=True, exist_ok=True)

    return run_dir


def init_run_state(run_id: str, project: str, mission: str, run_dir: Path) -> dict:
    """Initialize RUN_STATE.json."""
    now = datetime.utcnow().isoformat() + "Z"

    state = {
        "run_id": run_id,
        "project_id": project,
        "mission": mission,
        "current_state": "INIT",
        "previous_state": None,
        "state_history": [
            {"state": "INIT", "entered_at": now, "exited_at": None}
        ],
        "tools_planned": ["tool_inspector", "tool_browser", "tool_reporter"],
        "tools_completed": [],
        "tools_remaining": ["tool_inspector", "tool_browser", "tool_reporter"],
        "current_tool": None,
        "approvals_pending": [],
        "approvals_granted": [],
        "created_at": now,
        "updated_at": now
    }

    state_file = run_dir / "RUN_STATE.json"
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)

    return state


def transition_state(run_dir: Path, new_state: str) -> dict:
    """Transition to a new state."""
    state_file = run_dir / "RUN_STATE.json"

    with open(state_file) as f:
        state = json.load(f)

    now = datetime.utcnow().isoformat() + "Z"

    # Update history
    if state["state_history"]:
        state["state_history"][-1]["exited_at"] = now

    state["state_history"].append({
        "state": new_state,
        "entered_at": now,
        "exited_at": None
    })

    state["previous_state"] = state["current_state"]
    state["current_state"] = new_state
    state["updated_at"] = now

    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)

    return state


def update_tool_progress(run_dir: Path, tool_id: str, completed: bool = False):
    """Update tool progress in state."""
    state_file = run_dir / "RUN_STATE.json"

    with open(state_file) as f:
        state = json.load(f)

    state["current_tool"] = tool_id if not completed else None
    state["updated_at"] = datetime.utcnow().isoformat() + "Z"

    if completed and tool_id in state["tools_remaining"]:
        state["tools_remaining"].remove(tool_id)
        state["tools_completed"].append(tool_id)

    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)


def append_to_log(run_dir: Path, event: dict):
    """Append event to RUN_LOG.jsonl."""
    log_file = run_dir / "RUN_LOG.jsonl"
    event["timestamp"] = datetime.utcnow().isoformat() + "Z"

    with open(log_file, "a") as f:
        f.write(json.dumps(event) + "\n")


def append_to_ledger(run_id: str, event_type: str, details: dict = None):
    """Append to global RUN_LEDGER.jsonl."""
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "run_id": run_id,
        "event": event_type,
        **(details or {})
    }

    with open(LEDGER_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")


def run_becca_mvp(project: str, mission: str, url: str = None):
    """Execute the MVP pipeline: Inspector -> Browser -> Reporter."""

    print("\n" + "="*70)
    print("  BECCA MVP - Automation Kernel")
    print("="*70)

    # Validate project
    if project not in PROJECTS:
        print(f"\nERROR: Unknown project '{project}'")
        print(f"Available projects: {', '.join(PROJECTS.keys())}")
        return False

    project_path = PROJECTS[project]
    if not project_path.exists():
        print(f"\nERROR: Project path does not exist: {project_path}")
        return False

    # Generate run ID
    run_id = generate_run_id(project)
    print(f"\nRun ID: {run_id}")
    print(f"Project: {project} ({project_path})")
    print(f"Mission: {mission}")

    # Create run folder
    run_dir = create_run_folder(run_id)
    print(f"Run folder: {run_dir}")

    # Initialize state
    state = init_run_state(run_id, project, mission, run_dir)
    append_to_ledger(run_id, "RUN_STARTED", {"project": project, "mission": mission})

    # Transition to PLANNING
    transition_state(run_dir, "PLANNING")
    append_to_log(run_dir, {"event": "STATE_CHANGE", "to": "PLANNING"})

    print("\n" + "-"*70)
    print("  Phase: PLANNING")
    print("-"*70)
    print(f"  Tools planned: {state['tools_planned']}")

    # Transition to EXECUTING
    transition_state(run_dir, "EXECUTING")
    append_to_log(run_dir, {"event": "STATE_CHANGE", "to": "EXECUTING"})

    print("\n" + "-"*70)
    print("  Phase: EXECUTING")
    print("-"*70)

    all_outputs = {}
    all_evidence = []

    # Tool 1: Inspector
    print("\n[1/3] Running tool_inspector...")
    update_tool_progress(run_dir, "tool_inspector")
    append_to_log(run_dir, {"event": "TOOL_START", "tool": "tool_inspector"})

    try:
        inspector_output = run_inspector(
            run_id=run_id,
            run_dir=run_dir,
            project_path=project_path,
            mission=mission
        )
        all_outputs["tool_inspector"] = inspector_output
        all_evidence.extend(inspector_output.get("evidence", []))

        update_tool_progress(run_dir, "tool_inspector", completed=True)
        append_to_log(run_dir, {"event": "TOOL_COMPLETE", "tool": "tool_inspector", "status": inspector_output["status"]})
        print(f"      Status: {inspector_output['status']}")

    except Exception as e:
        print(f"      ERROR: {e}")
        transition_state(run_dir, "HALTED_UNSAFE")
        append_to_ledger(run_id, "RUN_HALTED", {"reason": str(e)})
        return False

    # Tool 2: Browser
    print("\n[2/3] Running tool_browser...")
    update_tool_progress(run_dir, "tool_browser")
    append_to_log(run_dir, {"event": "TOOL_START", "tool": "tool_browser"})

    try:
        browser_output = run_browser(
            run_id=run_id,
            run_dir=run_dir,
            url=url or f"http://localhost:3000",
            mission=mission
        )
        all_outputs["tool_browser"] = browser_output
        all_evidence.extend(browser_output.get("evidence", []))

        update_tool_progress(run_dir, "tool_browser", completed=True)
        append_to_log(run_dir, {"event": "TOOL_COMPLETE", "tool": "tool_browser", "status": browser_output["status"]})
        print(f"      Status: {browser_output['status']}")

    except Exception as e:
        print(f"      ERROR: {e}")
        # Browser errors are non-fatal for MVP
        all_outputs["tool_browser"] = {"status": "fail", "error": str(e)}
        update_tool_progress(run_dir, "tool_browser", completed=True)

    # Transition to VERIFYING
    transition_state(run_dir, "VERIFYING")
    append_to_log(run_dir, {"event": "STATE_CHANGE", "to": "VERIFYING"})

    print("\n" + "-"*70)
    print("  Phase: VERIFYING")
    print("-"*70)

    # Tool 3: Reporter
    print("\n[3/3] Running tool_reporter...")
    update_tool_progress(run_dir, "tool_reporter")
    append_to_log(run_dir, {"event": "TOOL_START", "tool": "tool_reporter"})

    try:
        reporter_output = run_reporter(
            run_id=run_id,
            run_dir=run_dir,
            mission=mission,
            tool_outputs=all_outputs,
            all_evidence=all_evidence
        )
        all_outputs["tool_reporter"] = reporter_output

        update_tool_progress(run_dir, "tool_reporter", completed=True)
        append_to_log(run_dir, {"event": "TOOL_COMPLETE", "tool": "tool_reporter", "status": reporter_output["status"]})
        print(f"      Status: {reporter_output['status']}")
        print(f"      Report: {reporter_output.get('report_path', 'N/A')}")

    except Exception as e:
        print(f"      ERROR: {e}")
        transition_state(run_dir, "HALTED_UNSAFE")
        append_to_ledger(run_id, "RUN_HALTED", {"reason": str(e)})
        return False

    # Transition to COMPLETE
    transition_state(run_dir, "COMPLETE")
    append_to_log(run_dir, {"event": "STATE_CHANGE", "to": "COMPLETE"})
    append_to_ledger(run_id, "RUN_COMPLETE", {"tools_run": 3, "evidence_count": len(all_evidence)})

    # Final summary
    print("\n" + "="*70)
    print("  RUN COMPLETE")
    print("="*70)
    print(f"\n  Run ID:     {run_id}")
    print(f"  State:      COMPLETE")
    print(f"  Tools run:  {len(all_outputs)}")
    print(f"  Evidence:   {len(all_evidence)} items")
    print(f"\n  Report:     {run_dir / 'FINAL_REPORT.md'}")
    print(f"  Run folder: {run_dir}")
    print("="*70 + "\n")

    return True


def main():
    parser = argparse.ArgumentParser(description="BECCA MVP - Automation Kernel")
    parser.add_argument("--project", required=True, choices=list(PROJECTS.keys()), help="Target project")
    parser.add_argument("--mission", required=True, help="What to investigate")
    parser.add_argument("--url", default=None, help="URL for browser tool (default: http://localhost:3000)")

    args = parser.parse_args()

    success = run_becca_mvp(args.project, args.mission, args.url)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
