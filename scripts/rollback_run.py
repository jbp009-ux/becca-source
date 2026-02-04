#!/usr/bin/env python3
"""
rollback_run.py - Emergency rollback for BECCA runs

Usage:
    python rollback_run.py --run-id RUN-PROJECT-20260131-120000
    python rollback_run.py --run-id RUN-xxx --dry-run
"""

import argparse
import json
import os
import shutil
from datetime import datetime
from pathlib import Path

# Base paths
BECCA_ROOT = Path(__file__).parent.parent
RUNS_DIR = BECCA_ROOT / "governance" / "runs"
LEDGER_PATH = BECCA_ROOT / "governance" / "command-center" / "ledger" / "RUN_LEDGER.jsonl"


def load_run_state(run_id: str) -> dict:
    """Load RUN_STATE.json for a run."""
    run_dir = RUNS_DIR / run_id
    state_file = run_dir / "RUN_STATE.json"

    if not state_file.exists():
        raise FileNotFoundError(f"Run not found: {run_id}")

    with open(state_file) as f:
        return json.load(f)


def find_backups(run_id: str) -> list:
    """Find all backup directories for a run."""
    run_dir = RUNS_DIR / run_id
    backups_dir = run_dir / "backups"

    if not backups_dir.exists():
        return []

    return sorted(backups_dir.iterdir(), reverse=True)


def restore_from_backup(backup_dir: Path, dry_run: bool = False) -> list:
    """Restore files from a backup directory."""
    restored = []

    for backup_file in backup_dir.rglob("*"):
        if backup_file.is_file():
            # Calculate original path
            relative = backup_file.relative_to(backup_dir)
            original_path = Path("/") / relative  # Reconstruct absolute path

            if dry_run:
                print(f"  [DRY RUN] Would restore: {backup_file} -> {original_path}")
            else:
                # Create parent directory if needed
                original_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup_file, original_path)
                print(f"  Restored: {original_path}")

            restored.append(str(original_path))

    return restored


def update_run_state(run_id: str, dry_run: bool = False):
    """Mark run as ROLLED_BACK."""
    run_dir = RUNS_DIR / run_id
    state_file = run_dir / "RUN_STATE.json"

    with open(state_file) as f:
        state = json.load(f)

    now = datetime.utcnow().isoformat() + "Z"

    # Update state
    old_state = state["current_state"]
    state["previous_state"] = old_state
    state["current_state"] = "ROLLED_BACK"
    state["updated_at"] = now

    # Add to history
    if state["state_history"]:
        state["state_history"][-1]["exited_at"] = now
    state["state_history"].append({
        "state": "ROLLED_BACK",
        "entered_at": now,
        "exited_at": None
    })

    if dry_run:
        print(f"  [DRY RUN] Would update state: {old_state} -> ROLLED_BACK")
    else:
        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
        print(f"  Updated state: {old_state} -> ROLLED_BACK")


def append_to_ledger(run_id: str, restored_files: list, dry_run: bool = False):
    """Append rollback event to RUN_LEDGER.jsonl."""
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "run_id": run_id,
        "event": "ROLLBACK",
        "files_restored": len(restored_files),
        "actor": "rollback_run.py"
    }

    if dry_run:
        print(f"  [DRY RUN] Would append to ledger: {json.dumps(event)}")
    else:
        with open(LEDGER_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")
        print(f"  Appended rollback event to ledger")


def rollback(run_id: str, dry_run: bool = False):
    """Execute full rollback for a run."""
    print(f"\n{'='*60}")
    print(f"ROLLBACK: {run_id}")
    print(f"{'='*60}")

    if dry_run:
        print("\n[DRY RUN MODE - No changes will be made]\n")

    # 1. Load run state
    print("\n1. Loading run state...")
    try:
        state = load_run_state(run_id)
        print(f"   Current state: {state['current_state']}")
    except FileNotFoundError as e:
        print(f"   ERROR: {e}")
        return False

    # Check if already rolled back
    if state["current_state"] in ["ROLLED_BACK", "HALTED_UNSAFE"]:
        print(f"   Run is already in terminal state: {state['current_state']}")
        return False

    # 2. Find backups
    print("\n2. Finding backups...")
    backups = find_backups(run_id)

    if not backups:
        print("   No backups found. Nothing to restore.")
    else:
        print(f"   Found {len(backups)} backup(s)")
        for b in backups:
            print(f"   - {b.name}")

    # 3. Restore from backups (newest first)
    print("\n3. Restoring files...")
    all_restored = []

    for backup_dir in backups:
        print(f"   From: {backup_dir.name}")
        restored = restore_from_backup(backup_dir, dry_run)
        all_restored.extend(restored)

    if not all_restored:
        print("   No files to restore.")
    else:
        print(f"   Total files restored: {len(all_restored)}")

    # 4. Update run state
    print("\n4. Updating run state...")
    update_run_state(run_id, dry_run)

    # 5. Append to ledger
    print("\n5. Updating ledger...")
    append_to_ledger(run_id, all_restored, dry_run)

    # 6. Summary
    print(f"\n{'='*60}")
    if dry_run:
        print("DRY RUN COMPLETE - No changes made")
    else:
        print("ROLLBACK COMPLETE")
    print(f"{'='*60}\n")

    return True


def main():
    parser = argparse.ArgumentParser(description="Rollback a BECCA run")
    parser.add_argument("--run-id", required=True, help="Run ID to rollback (e.g., RUN-PROJECT-20260131-120000)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")

    args = parser.parse_args()

    success = rollback(args.run_id, args.dry_run)
    exit(0 if success else 1)


if __name__ == "__main__":
    main()
