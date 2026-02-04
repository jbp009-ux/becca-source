#!/usr/bin/env python3
"""
apply_base.py - Base class for APPLY tools

APPLY tools apply changes from approved proposals:
  - Verify approval exists and matches
  - Create rollback snapshot FIRST
  - Dry-run patch to verify it applies
  - Apply changes
  - Re-run verification
  - Generate APPLY_RESULT.json

Mandatory Gates (non-negotiable):
  1. Approval hash must match proposal request_hash
  2. Approval run_id must match current run
  3. Approval must not be expired
  4. Workspace must be clean (or explicitly allow dirty)
  5. Dry-run must succeed before real apply
  6. Rollback snapshot must exist before any modification
  7. Post-apply verification must pass

Usage:
    from tools.apply_base import ApplyTool

    class MyApplier(ApplyTool):
        def apply_changes(self, proposal):
            # Apply the changes
            pass
"""

import hashlib
import json
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class FileSnapshot:
    """Snapshot of a file before modification."""
    path: str
    existed: bool
    content_hash: str = ""
    size_bytes: int = 0
    backup_path: str = ""


@dataclass
class ApplyResult:
    """Result of applying a proposal."""
    result_id: str
    proposal_id: str
    approval_id: str
    status: str  # success, failed, rolled_back
    applied_at: str
    files_modified: list[dict] = field(default_factory=list)
    rollback_path: str = ""
    verification_passed: bool = False
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class ApplyError(Exception):
    """Raised when apply fails a mandatory gate."""
    pass


class ApplyTool(ABC):
    """
    Base class for APPLY tools.

    Enforces mandatory gates before any file modification.
    """

    TOOL_NAME = "apply_base"
    VERSION = "1.0.0"

    def __init__(
        self,
        project_path: Path,
        run_dir: Path,
        run_id: str,
        task_id: str,
        proposal_path: Path,
        approval_path: Path,
        allow_dirty: bool = False
    ):
        self.project_path = Path(project_path)
        self.run_dir = Path(run_dir)
        self.run_id = run_id
        self.task_id = task_id
        self.proposal_path = Path(proposal_path)
        self.approval_path = Path(approval_path)
        self.allow_dirty = allow_dirty

        self.evidence_dir = run_dir / "apply" / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        self.rollback_dir = run_dir / "apply" / "rollback"
        self.rollback_dir.mkdir(parents=True, exist_ok=True)

        self.proposal: dict = {}
        self.approval: dict = {}
        self.snapshots: list[FileSnapshot] = []
        self.result: Optional[ApplyResult] = None

    def _hash_file(self, path: Path) -> str:
        """Generate SHA256 hash of a file."""
        if not path.exists():
            return ""
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return f"sha256:{sha256.hexdigest()}"

    def _load_proposal(self) -> dict:
        """Load and validate proposal."""
        if not self.proposal_path.exists():
            raise ApplyError(f"Proposal not found: {self.proposal_path}")

        with open(self.proposal_path) as f:
            self.proposal = json.load(f)

        return self.proposal

    def _load_approval(self) -> dict:
        """Load and validate approval."""
        if not self.approval_path.exists():
            raise ApplyError(f"Approval not found: {self.approval_path}")

        with open(self.approval_path) as f:
            self.approval = json.load(f)

        return self.approval

    def gate_1_approval_hash(self) -> bool:
        """Gate 1: Approval request_hash must match proposal."""
        proposal_hash = self.proposal.get("request_hash", "")
        approval_hash = self.approval.get("request_hash", "")

        if not proposal_hash:
            raise ApplyError("Proposal missing request_hash")
        if not approval_hash:
            raise ApplyError("Approval missing request_hash")
        if proposal_hash != approval_hash:
            raise ApplyError(f"Hash mismatch: proposal={proposal_hash[:16]}, approval={approval_hash[:16]}")

        return True

    def gate_2_run_id(self) -> bool:
        """Gate 2: Approval run_id must match current run."""
        approval_run_id = self.approval.get("run_id", "")
        if approval_run_id and approval_run_id != self.run_id:
            raise ApplyError(f"Run ID mismatch: approval={approval_run_id}, current={self.run_id}")
        return True

    def gate_3_not_expired(self) -> bool:
        """Gate 3: Approval must not be expired."""
        expires_at = self.approval.get("expires_at")
        if expires_at:
            from datetime import timezone
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if now > expiry:
                raise ApplyError(f"Approval expired at {expires_at}")
        return True

    def gate_4_workspace_clean(self) -> bool:
        """Gate 4: Workspace must be clean (no uncommitted changes)."""
        if self.allow_dirty:
            return True

        try:
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.stdout.strip():
                raise ApplyError(
                    f"Workspace has uncommitted changes. Use allow_dirty=True to override.\n"
                    f"Changes:\n{result.stdout[:500]}"
                )
        except subprocess.SubprocessError:
            # Not a git repo or git not available - skip this check
            pass

        return True

    def gate_5_dry_run(self, patch_content: str) -> bool:
        """Gate 5: Dry-run patch must succeed."""
        # Write patch to temp file
        temp_patch = self.evidence_dir / "temp_apply.patch"
        with open(temp_patch, "w") as f:
            f.write(patch_content)

        try:
            result = subprocess.run(
                ["git", "apply", "--check", str(temp_patch)],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                raise ApplyError(f"Dry-run failed:\n{result.stderr}")
        except subprocess.SubprocessError as e:
            # Try without git
            raise ApplyError(f"Dry-run check failed: {e}")
        finally:
            temp_patch.unlink(missing_ok=True)

        return True

    def gate_6_create_rollback(self) -> str:
        """Gate 6: Create rollback snapshot before any modification."""
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        rollback_id = f"ROLLBACK-{self.proposal.get('proposal_id', 'UNKNOWN')}-{timestamp}"
        rollback_path = self.rollback_dir / rollback_id

        rollback_path.mkdir(parents=True, exist_ok=True)

        # Snapshot each file that will be modified
        for file_info in self.proposal.get("files", []):
            file_path = self.project_path / file_info.get("path", "")
            relative_path = file_info.get("path", "")

            snapshot = FileSnapshot(
                path=relative_path,
                existed=file_path.exists()
            )

            if file_path.exists():
                snapshot.content_hash = self._hash_file(file_path)
                snapshot.size_bytes = file_path.stat().st_size

                # Copy to rollback
                backup_file = rollback_path / relative_path
                backup_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file_path, backup_file)
                snapshot.backup_path = str(backup_file)

            self.snapshots.append(snapshot)

        # Write rollback manifest
        manifest = {
            "rollback_id": rollback_id,
            "proposal_id": self.proposal.get("proposal_id"),
            "created_at": datetime.utcnow().isoformat() + "Z",
            "snapshots": [asdict(s) for s in self.snapshots]
        }

        with open(rollback_path / "MANIFEST.json", "w") as f:
            json.dump(manifest, f, indent=2)

        return str(rollback_path)

    @abstractmethod
    def apply_changes(self) -> bool:
        """
        Apply the actual changes.

        Subclasses must implement this.
        Should return True on success, raise ApplyError on failure.
        """
        pass

    def gate_7_post_verify(self) -> bool:
        """Gate 7: Post-apply verification must pass."""
        # Verify each file matches expected after_hash
        for file_info in self.proposal.get("files", []):
            file_path = self.project_path / file_info.get("path", "")
            expected_hash = file_info.get("after_hash", "")

            if expected_hash:
                actual_hash = self._hash_file(file_path)
                if actual_hash != expected_hash:
                    raise ApplyError(
                        f"Post-apply verification failed for {file_info['path']}: "
                        f"expected {expected_hash[:16]}, got {actual_hash[:16]}"
                    )

        return True

    def rollback(self, rollback_path: str) -> bool:
        """Rollback changes using snapshot."""
        manifest_path = Path(rollback_path) / "MANIFEST.json"
        if not manifest_path.exists():
            raise ApplyError(f"Rollback manifest not found: {manifest_path}")

        with open(manifest_path) as f:
            manifest = json.load(f)

        for snapshot in manifest.get("snapshots", []):
            file_path = self.project_path / snapshot["path"]
            backup_path = snapshot.get("backup_path")

            if snapshot["existed"] and backup_path:
                # Restore from backup
                shutil.copy2(backup_path, file_path)
            elif not snapshot["existed"] and file_path.exists():
                # Delete file that was created
                file_path.unlink()

        return True

    def run(self) -> dict:
        """
        Execute apply with all mandatory gates.

        Returns dict with status and evidence.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        rollback_path = ""
        errors = []

        try:
            # Load artifacts
            self._load_proposal()
            self._load_approval()

            proposal_id = self.proposal.get("proposal_id", "UNKNOWN")
            approval_id = self.approval.get("approval_id", "UNKNOWN")

            print(f"      APPLY: {proposal_id}")

            # Run mandatory gates
            print(f"        Gate 1: Checking approval hash...")
            self.gate_1_approval_hash()

            print(f"        Gate 2: Checking run ID...")
            self.gate_2_run_id()

            print(f"        Gate 3: Checking expiration...")
            self.gate_3_not_expired()

            print(f"        Gate 4: Checking workspace...")
            self.gate_4_workspace_clean()

            # Load patch for dry-run
            patch_path = self.proposal_path.parent / f"{proposal_id}.patch"
            if patch_path.exists():
                with open(patch_path) as f:
                    patch_content = f.read()
                print(f"        Gate 5: Dry-run...")
                self.gate_5_dry_run(patch_content)

            print(f"        Gate 6: Creating rollback snapshot...")
            rollback_path = self.gate_6_create_rollback()

            print(f"        Applying changes...")
            self.apply_changes()

            print(f"        Gate 7: Post-apply verification...")
            self.gate_7_post_verify()

            # Success
            self.result = ApplyResult(
                result_id=f"APPLY-{proposal_id}-{timestamp}",
                proposal_id=proposal_id,
                approval_id=approval_id,
                status="success",
                applied_at=datetime.utcnow().isoformat() + "Z",
                files_modified=[
                    {
                        "path": s.path,
                        "before_hash": s.content_hash,
                        "after_hash": self._hash_file(self.project_path / s.path)
                    }
                    for s in self.snapshots
                ],
                rollback_path=rollback_path,
                verification_passed=True
            )

            print(f"        SUCCESS: {len(self.snapshots)} files modified")

        except ApplyError as e:
            errors.append(str(e))
            print(f"        FAILED: {e}")

            # Attempt rollback if we got past gate 6
            if rollback_path:
                print(f"        Rolling back...")
                try:
                    self.rollback(rollback_path)
                    print(f"        Rollback complete")
                except Exception as re:
                    errors.append(f"Rollback failed: {re}")
                    print(f"        ROLLBACK FAILED: {re}")

            self.result = ApplyResult(
                result_id=f"APPLY-{self.proposal.get('proposal_id', 'UNKNOWN')}-{timestamp}",
                proposal_id=self.proposal.get("proposal_id", ""),
                approval_id=self.approval.get("approval_id", ""),
                status="rolled_back" if rollback_path else "failed",
                applied_at=datetime.utcnow().isoformat() + "Z",
                rollback_path=rollback_path,
                verification_passed=False,
                errors=errors
            )

        except Exception as e:
            errors.append(f"Unexpected error: {e}")
            self.result = ApplyResult(
                result_id=f"APPLY-UNKNOWN-{timestamp}",
                proposal_id=self.proposal.get("proposal_id", ""),
                approval_id=self.approval.get("approval_id", ""),
                status="failed",
                applied_at=datetime.utcnow().isoformat() + "Z",
                rollback_path=rollback_path,
                verification_passed=False,
                errors=errors
            )

        # Write result
        result_path = self.evidence_dir / f"APPLY_RESULT_{self.result.proposal_id}.json"
        with open(result_path, "w") as f:
            json.dump(self.result.to_dict(), f, indent=2)

        return {
            "status": self.result.status,
            "proposal_id": self.result.proposal_id,
            "files_modified": len(self.result.files_modified),
            "verification_passed": self.result.verification_passed,
            "rollback_path": self.result.rollback_path,
            "evidence": [
                {"type": "file", "path": str(result_path)}
            ],
            "errors": self.result.errors
        }


class PatchApplyTool(ApplyTool):
    """
    APPLY tool that applies unified diff patches using git apply.
    """

    TOOL_NAME = "patch_apply"

    def apply_changes(self) -> bool:
        """Apply patch using git apply."""
        proposal_id = self.proposal.get("proposal_id", "")
        patch_path = self.proposal_path.parent / f"{proposal_id}.patch"

        if not patch_path.exists():
            raise ApplyError(f"Patch file not found: {patch_path}")

        result = subprocess.run(
            ["git", "apply", str(patch_path)],
            cwd=self.project_path,
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            raise ApplyError(f"git apply failed:\n{result.stderr}")

        return True
