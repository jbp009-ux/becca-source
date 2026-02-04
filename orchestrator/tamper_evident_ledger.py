#!/usr/bin/env python3
"""
tamper_evident_ledger.py - Append-Only Hash-Chained Ledger

Makes the RUN_LEDGER.jsonl tamper-evident using SHA256 hash chains.
Each entry includes:
  - entry_hash: SHA256(previous_hash + canonical_json(entry))
  - previous_hash: hash of the previous entry

If anyone edits a past entry, the chain breaks and verification fails.

Usage:
    from tamper_evident_ledger import TamperEvidentLedger

    ledger = TamperEvidentLedger()
    ledger.append(run_id="...", project="...", event="...", data={...})
    is_valid, errors = ledger.verify_chain()
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any


# Paths
BECCA_ROOT = Path(__file__).parent.parent
LEDGER_FILE = BECCA_ROOT / "governance" / "command-center" / "ledger" / "RUN_LEDGER.jsonl"
GENESIS_HASH = "0" * 64  # Genesis block has no previous


def canonical_json(obj: dict) -> str:
    """
    Convert dict to canonical JSON (sorted keys, no whitespace).

    This ensures the same dict always produces the same hash.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def compute_hash(previous_hash: str, entry: dict) -> str:
    """
    Compute SHA256 hash for an entry.

    hash = SHA256(previous_hash + canonical_json(entry_without_hash_fields))
    """
    # Remove hash fields for computation
    entry_clean = {k: v for k, v in entry.items()
                   if k not in ("entry_hash", "previous_hash")}

    data = previous_hash + canonical_json(entry_clean)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class TamperEvidentLedger:
    """
    Append-only hash-chained ledger.

    Every entry is linked to the previous via SHA256.
    Tampering with any entry breaks the chain.
    """

    def __init__(self, ledger_path: Path = None):
        self.ledger_path = ledger_path or LEDGER_FILE
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)

    def get_last_hash(self) -> str:
        """Get the hash of the last entry, or genesis hash if empty."""
        if not self.ledger_path.exists():
            return GENESIS_HASH

        last_line = None
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line

        if not last_line:
            return GENESIS_HASH

        try:
            entry = json.loads(last_line)
            return entry.get("entry_hash", GENESIS_HASH)
        except json.JSONDecodeError:
            return GENESIS_HASH

    def append(self, run_id: str, project: str, event: str,
               state: str = None, tool: str = None, action: str = None,
               status: str = None, artifacts: List[str] = None,
               evidence_refs: List[str] = None, data: Dict = None) -> dict:
        """
        Append a new entry to the ledger with hash chain.

        Returns the entry with hash fields included.
        """
        # Get previous hash
        previous_hash = self.get_last_hash()

        # Build entry
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "project": project,
            "event": event,
        }

        # Optional fields
        if state:
            entry["state"] = state
        if tool:
            entry["tool"] = tool
        if action:
            entry["action"] = action
        if status:
            entry["status"] = status
        if artifacts:
            entry["artifacts"] = artifacts
        if evidence_refs:
            entry["evidenceRefs"] = evidence_refs
        if data:
            entry.update(data)

        # Compute hash
        entry_hash = compute_hash(previous_hash, entry)

        # Add hash fields
        entry["previous_hash"] = previous_hash
        entry["entry_hash"] = entry_hash

        # Append to file
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        return entry

    def verify_chain(self) -> Tuple[bool, List[str]]:
        """
        Verify the entire hash chain.

        Returns (is_valid, list_of_errors).
        """
        if not self.ledger_path.exists():
            return True, []

        errors = []
        previous_hash = GENESIS_HASH
        line_num = 0

        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                line_num += 1
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    errors.append(f"Line {line_num}: Invalid JSON - {e}")
                    continue

                # Check previous_hash matches
                stored_prev = entry.get("previous_hash")
                if stored_prev != previous_hash:
                    errors.append(
                        f"Line {line_num}: Chain broken! "
                        f"Expected previous_hash={previous_hash[:16]}..., "
                        f"got {stored_prev[:16] if stored_prev else 'None'}..."
                    )

                # Recompute hash
                stored_hash = entry.get("entry_hash")
                computed_hash = compute_hash(previous_hash, entry)

                if stored_hash != computed_hash:
                    errors.append(
                        f"Line {line_num}: Hash mismatch! "
                        f"Stored={stored_hash[:16]}..., "
                        f"Computed={computed_hash[:16]}..."
                    )

                # Update for next iteration
                previous_hash = stored_hash or computed_hash

        return len(errors) == 0, errors

    def get_entries(self, limit: int = None, project: str = None,
                    run_id: str = None) -> List[dict]:
        """
        Read entries from the ledger with optional filters.
        """
        if not self.ledger_path.exists():
            return []

        entries = []
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)

                    # Apply filters
                    if project and entry.get("project") != project:
                        continue
                    if run_id and entry.get("run_id") != run_id:
                        continue

                    entries.append(entry)

                except json.JSONDecodeError:
                    continue

        # Apply limit (from end)
        if limit:
            entries = entries[-limit:]

        return entries

    def get_run_entries(self, run_id: str) -> List[dict]:
        """Get all entries for a specific run."""
        return self.get_entries(run_id=run_id)

    def get_chain_summary(self) -> dict:
        """Get a summary of the ledger chain."""
        if not self.ledger_path.exists():
            return {
                "total_entries": 0,
                "first_entry": None,
                "last_entry": None,
                "chain_valid": True,
                "errors": []
            }

        entries = self.get_entries()
        is_valid, errors = self.verify_chain()

        return {
            "total_entries": len(entries),
            "first_entry": entries[0].get("ts") if entries else None,
            "last_entry": entries[-1].get("ts") if entries else None,
            "last_hash": entries[-1].get("entry_hash")[:16] + "..." if entries else None,
            "chain_valid": is_valid,
            "errors": errors[:5]  # First 5 errors only
        }


def migrate_existing_ledger(ledger_path: Path = None):
    """
    Migrate an existing ledger to hash-chained format.

    Reads all entries, adds hash fields, writes to new file.
    """
    ledger_path = ledger_path or LEDGER_FILE

    if not ledger_path.exists():
        print("No existing ledger to migrate")
        return

    # Read existing entries
    entries = []
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not entries:
        print("No entries to migrate")
        return

    # Check if already migrated
    if entries[0].get("entry_hash"):
        print("Ledger already has hashes - verifying chain...")
        ledger = TamperEvidentLedger(ledger_path)
        is_valid, errors = ledger.verify_chain()
        if is_valid:
            print("Chain is valid!")
        else:
            print(f"Chain has {len(errors)} errors:")
            for e in errors[:5]:
                print(f"  - {e}")
        return

    # Backup original
    backup_path = ledger_path.with_suffix(".jsonl.backup")
    ledger_path.rename(backup_path)
    print(f"Backed up to: {backup_path}")

    # Write with hashes
    previous_hash = GENESIS_HASH
    with open(ledger_path, "w", encoding="utf-8") as f:
        for entry in entries:
            # Remove any existing hash fields
            entry.pop("entry_hash", None)
            entry.pop("previous_hash", None)

            # Compute hash
            entry_hash = compute_hash(previous_hash, entry)

            # Add hash fields
            entry["previous_hash"] = previous_hash
            entry["entry_hash"] = entry_hash

            f.write(json.dumps(entry) + "\n")

            previous_hash = entry_hash

    print(f"Migrated {len(entries)} entries with hash chain")

    # Verify
    ledger = TamperEvidentLedger(ledger_path)
    is_valid, errors = ledger.verify_chain()
    print(f"Verification: {'PASSED' if is_valid else 'FAILED'}")


# CLI
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "migrate":
        migrate_existing_ledger()
    elif len(sys.argv) > 1 and sys.argv[1] == "verify":
        ledger = TamperEvidentLedger()
        is_valid, errors = ledger.verify_chain()
        print(f"Chain valid: {is_valid}")
        if errors:
            for e in errors:
                print(f"  ERROR: {e}")
    elif len(sys.argv) > 1 and sys.argv[1] == "summary":
        ledger = TamperEvidentLedger()
        summary = ledger.get_chain_summary()
        print(json.dumps(summary, indent=2))
    else:
        print("Usage:")
        print("  python tamper_evident_ledger.py migrate  - Migrate existing ledger")
        print("  python tamper_evident_ledger.py verify   - Verify hash chain")
        print("  python tamper_evident_ledger.py summary  - Show chain summary")
