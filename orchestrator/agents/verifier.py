#!/usr/bin/env python3
"""
verifier.py - Run Verification Pass

The Verifier is the "court clerk" that ensures:
  - All artifacts exist and match expected schemas
  - Hashes match referenced evidence files
  - Evidence IDs referenced by risks exist
  - No silent partial success

Philosophy: No false greens. Ever.

Status Determination Rules:
  ALL_CLEAR:
    - All tasks SUCCESS or acceptable SKIPPED_*
    - Zero CRITICAL/HIGH risks
    - Verification passed

  OK_WITH_WARNINGS:
    - All tasks completed
    - Only MEDIUM/LOW risks
    - Verification passed

  STOPPED:
    - Intentional stop condition triggered

  FAILED:
    - Any task FAILED
    - OR CRITICAL/HIGH risks found

  FAILED_VERIFY:
    - Verification failed
    - OR expected outputs missing
    - OR hash mismatch

Usage:
    from orchestrator.agents.verifier import RunVerifier

    verifier = RunVerifier(run_dir, plan, results, risks, evidence_index)
    status = verifier.verify()
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


# Acceptable skip statuses (don't count as failures)
ACCEPTABLE_SKIPS = {"SKIPPED_DEPENDENCY", "SKIPPED_POLICY"}

# Statuses that indicate success
SUCCESS_STATUSES = {"SUCCESS"}

# Statuses that indicate intentional stop
STOP_STATUSES = {"STOPPED_BY_CONDITION"}

# Statuses that indicate failure
FAILURE_STATUSES = {"FAILED", "FAILED_VERIFY", "TIMEOUT", "INCOMPLETE"}


@dataclass
class VerificationCheck:
    """A single verification check result."""
    check: str
    passed: bool
    details: str = ""


@dataclass
class RunStatus:
    """Final run status determination."""
    run_id: str
    final_status: str  # ALL_CLEAR, OK_WITH_WARNINGS, STOPPED, FAILED, FAILED_VERIFY
    status_reason: str
    verified_at: str
    task_summary: dict
    risk_summary: dict
    verification: dict

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "final_status": self.final_status,
            "status_reason": self.status_reason,
            "verified_at": self.verified_at,
            "task_summary": self.task_summary,
            "risk_summary": self.risk_summary,
            "verification": self.verification,
        }


class RunVerifier:
    """
    Run Verifier - The court clerk that prevents false greens.

    Trust but verify. Then verify again.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        run_dir: Path,
        plan: dict,
        results: list[dict],
        risks: dict = None,
        evidence_index: dict = None,
        execution_summary: dict = None
    ):
        self.run_dir = Path(run_dir)
        self.plan = plan
        self.results = results
        self.risks = risks or {"risks": [], "summary": {}}
        self.evidence_index = evidence_index or {"evidence": [], "summary": {}}
        self.execution_summary = execution_summary or {}

        self.checks: list[VerificationCheck] = []
        self.failed_checks: list[str] = []

    def _add_check(self, check: str, passed: bool, details: str = ""):
        """Record a verification check."""
        self.checks.append(VerificationCheck(check, passed, details))
        if not passed:
            self.failed_checks.append(f"{check}: {details}")

    def verify_artifacts_exist(self) -> bool:
        """Verify all expected artifacts exist."""
        all_exist = True

        # Check PLAN.json
        plan_path = self.run_dir / "mq_planner" / "evidence" / "PLAN.json"
        if plan_path.exists():
            self._add_check("PLAN.json exists", True)
        else:
            self._add_check("PLAN.json exists", False, "Missing plan file")
            all_exist = False

        # Check each RESULT.json
        for result in self.results:
            task_id = result.get("task_id", "unknown")
            # Results are in bq_executor/evidence
            result_path = self.run_dir / "bq_executor" / "evidence" / f"RESULT_{task_id}.json"
            if result_path.exists():
                self._add_check(f"RESULT_{task_id}.json exists", True)
            else:
                self._add_check(f"RESULT_{task_id}.json exists", False, f"Missing result for {task_id}")
                all_exist = False

        # Check RISKS.json
        risks_path = self.run_dir / "ghost_archivist" / "evidence" / "RISKS.json"
        if risks_path.exists():
            self._add_check("RISKS.json exists", True)
        else:
            self._add_check("RISKS.json exists", False, "Missing risks file")
            all_exist = False

        # Check EVIDENCE_INDEX.json
        evidence_path = self.run_dir / "ghost_archivist" / "evidence" / "EVIDENCE_INDEX.json"
        if evidence_path.exists():
            self._add_check("EVIDENCE_INDEX.json exists", True)
        else:
            self._add_check("EVIDENCE_INDEX.json exists", False, "Missing evidence index")
            all_exist = False

        # Check FINAL_REPORT.md
        report_path = self.run_dir / "FINAL_REPORT.md"
        if report_path.exists():
            self._add_check("FINAL_REPORT.md exists", True)
        else:
            self._add_check("FINAL_REPORT.md exists", False, "Missing final report")
            all_exist = False

        return all_exist

    def verify_evidence_hashes(self) -> bool:
        """Verify evidence file hashes match index."""
        all_match = True

        for evidence in self.evidence_index.get("evidence", []):
            evidence_id = evidence.get("evidence_id", "")
            rel_path = evidence.get("path", "")
            expected_hash = evidence.get("hash", "")

            if not rel_path:
                continue

            full_path = self.run_dir / rel_path
            if not full_path.exists():
                self._add_check(
                    f"Evidence {evidence_id} exists",
                    False,
                    f"File not found: {rel_path}"
                )
                all_match = False
                continue

            if expected_hash:
                actual_hash = self._hash_file(full_path)
                if actual_hash == expected_hash:
                    self._add_check(f"Evidence {evidence_id} hash", True)
                else:
                    self._add_check(
                        f"Evidence {evidence_id} hash",
                        False,
                        f"Hash mismatch: expected {expected_hash[:20]}..., got {actual_hash[:20]}..."
                    )
                    all_match = False

        return all_match

    def verify_risk_evidence_links(self) -> bool:
        """Verify risks reference valid evidence IDs."""
        all_valid = True

        evidence_ids = {e.get("evidence_id") for e in self.evidence_index.get("evidence", [])}

        for risk in self.risks.get("risks", []):
            risk_id = risk.get("risk_id", "")
            for ev_id in risk.get("evidence_ids", []):
                if ev_id in evidence_ids:
                    self._add_check(f"Risk {risk_id} evidence link {ev_id}", True)
                else:
                    self._add_check(
                        f"Risk {risk_id} evidence link {ev_id}",
                        False,
                        f"Evidence {ev_id} not found in index"
                    )
                    all_valid = False

        return all_valid

    def verify_task_outputs(self) -> bool:
        """Verify each task produced its expected outputs."""
        all_valid = True

        for task in self.plan.get("tasks", []):
            task_id = task.get("task_id", "")
            expected_outputs = task.get("outputs_expected", [])

            # Find result for this task
            result = next((r for r in self.results if r.get("task_id") == task_id), None)
            if not result:
                self._add_check(f"Task {task_id} result exists", False, "No result found")
                all_valid = False
                continue

            # Check required outputs
            for exp in expected_outputs:
                if not exp.get("required", True):
                    continue

                artifact = exp.get("artifact", "")
                outputs = result.get("outputs", [])

                # Check if artifact was produced
                found = any(artifact.lower() in o.get("artifact", "").lower() for o in outputs)
                if found:
                    self._add_check(f"Task {task_id} output {artifact}", True)
                else:
                    self._add_check(
                        f"Task {task_id} output {artifact}",
                        False,
                        f"Required artifact not produced"
                    )
                    all_valid = False

        return all_valid

    def _hash_file(self, path: Path) -> str:
        """Generate SHA256 hash of a file."""
        if not path.exists():
            return ""

        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        return f"sha256:{sha256.hexdigest()}"

    def verify_approvals(self) -> bool:
        """
        Verify that APPLY tools have valid approvals.

        Checks:
        - Approval exists for each proposal
        - Approval request_hash matches proposal request_hash
        - Approval has not expired
        - Approval decision is "approved"
        """
        all_valid = True

        # Find proposals directory
        proposals_dir = self.run_dir / "proposals"
        if not proposals_dir.exists():
            # No proposals = no approvals needed
            self._add_check("Approvals directory", True, "No proposals found")
            return True

        # Find all proposals
        proposals = list(proposals_dir.glob("PROPOSAL-*.json"))
        if not proposals:
            self._add_check("Approvals check", True, "No proposals to verify")
            return True

        approvals_dir = self.run_dir / "approvals"

        for proposal_path in proposals:
            try:
                with open(proposal_path) as f:
                    proposal = json.load(f)

                proposal_id = proposal.get("proposal_id", "")
                request_hash = proposal.get("request_hash", "")
                status = proposal.get("status", "pending")

                # Only check proposals that were applied
                if status not in ["applied", "rolled_back"]:
                    self._add_check(
                        f"Proposal {proposal_id} approval",
                        True,
                        f"Not applied (status: {status})"
                    )
                    continue

                # Find approval
                approval_path = approvals_dir / f"APPROVAL-{proposal_id}.json"
                if not approval_path.exists():
                    self._add_check(
                        f"Proposal {proposal_id} approval",
                        False,
                        "Applied without approval"
                    )
                    all_valid = False
                    continue

                with open(approval_path) as f:
                    approval = json.load(f)

                # Verify request_hash match
                approval_hash = approval.get("request_hash", "")
                if approval_hash != request_hash:
                    self._add_check(
                        f"Proposal {proposal_id} request_hash",
                        False,
                        f"Hash mismatch: {approval_hash[:16]} != {request_hash[:16]}"
                    )
                    all_valid = False
                    continue

                # Verify run_id match (prevents cross-run approval reuse)
                proposal_run_id = proposal.get("plan_id", "").replace("PLAN-", "RUN-")
                approval_run_id = approval.get("run_id", "")
                if approval_run_id and approval_run_id != proposal_run_id:
                    self._add_check(
                        f"Proposal {proposal_id} run_id",
                        False,
                        f"Run ID mismatch: {approval_run_id} != {proposal_run_id}"
                    )
                    all_valid = False
                    continue

                # Verify task_id match
                proposal_task_id = proposal.get("task_id", "")
                approval_task_id = approval.get("task_id", "")
                if approval_task_id and approval_task_id != proposal_task_id:
                    self._add_check(
                        f"Proposal {proposal_id} task_id",
                        False,
                        f"Task ID mismatch: {approval_task_id} != {proposal_task_id}"
                    )
                    all_valid = False
                    continue

                # Verify proposal_hash (file integrity)
                expected_proposal_hash = approval.get("proposal_hash", "")
                if expected_proposal_hash:
                    actual_proposal_hash = self._hash_file(proposal_path)
                    if actual_proposal_hash != expected_proposal_hash:
                        self._add_check(
                            f"Proposal {proposal_id} file integrity",
                            False,
                            f"Proposal file modified after approval"
                        )
                        all_valid = False
                        continue

                # Verify decision
                decision = approval.get("decision", "")
                if decision != "approved":
                    self._add_check(
                        f"Proposal {proposal_id} approval decision",
                        False,
                        f"Decision is {decision}, not approved"
                    )
                    all_valid = False
                    continue

                # Verify not expired
                expires_at = approval.get("expires_at")
                if expires_at:
                    from datetime import datetime
                    expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    now = datetime.now(expiry.tzinfo)
                    if now > expiry:
                        self._add_check(
                            f"Proposal {proposal_id} approval expiry",
                            False,
                            f"Approval expired at {expires_at}"
                        )
                        all_valid = False
                        continue

                self._add_check(f"Proposal {proposal_id} approval", True, "Valid approval")

            except Exception as e:
                self._add_check(
                    f"Proposal {proposal_path.stem}",
                    False,
                    f"Error verifying: {e}"
                )
                all_valid = False

        return all_valid

    def _count_tasks_by_status(self) -> dict:
        """Count tasks by status."""
        counts = {
            "SUCCESS": 0,
            "FAILED": 0,
            "SKIPPED_DEPENDENCY": 0,
            "SKIPPED_POLICY": 0,
            "STOPPED_BY_CONDITION": 0,
            "FAILED_VERIFY": 0,
            "INCOMPLETE": 0,
            "TIMEOUT": 0,
        }

        for result in self.results:
            status = result.get("status", "INCOMPLETE").upper()
            # Normalize old status names
            status_map = {
                "SUCCESS": "SUCCESS",
                "PASS": "SUCCESS",
                "FAILED": "FAILED",
                "PARTIAL": "INCOMPLETE",
                "BLOCKED": "SKIPPED_DEPENDENCY",
                "TIMEOUT": "TIMEOUT",
                "SKIPPED": "SKIPPED_POLICY",
            }
            normalized = status_map.get(status, status)
            if normalized in counts:
                counts[normalized] += 1
            else:
                counts["INCOMPLETE"] += 1

        return counts

    def _count_risks_by_severity(self) -> dict:
        """Count risks by severity."""
        summary = self.risks.get("summary", {})
        by_severity = summary.get("by_severity", {})

        return {
            "total": summary.get("total_risks", len(self.risks.get("risks", []))),
            "critical": by_severity.get("CRITICAL", 0),
            "high": by_severity.get("HIGH", 0),
            "medium": by_severity.get("MEDIUM", 0),
            "low": by_severity.get("LOW", 0),
            "suppressed": summary.get("suppressed_count", 0),
        }

    def determine_status(self) -> tuple[str, str]:
        """
        Determine final run status based on tasks, risks, and verification.

        Returns (status, reason)
        """
        task_counts = self._count_tasks_by_status()
        risk_counts = self._count_risks_by_severity()
        verification_passed = len(self.failed_checks) == 0

        total_tasks = sum(task_counts.values())
        success_count = task_counts["SUCCESS"]
        failed_count = task_counts["FAILED"] + task_counts["FAILED_VERIFY"] + task_counts["TIMEOUT"]
        incomplete_count = task_counts["INCOMPLETE"]
        stopped_count = task_counts["STOPPED_BY_CONDITION"]
        skipped_count = task_counts["SKIPPED_DEPENDENCY"] + task_counts["SKIPPED_POLICY"]

        # Rule 1: Verification must pass
        if not verification_passed:
            return "FAILED_VERIFY", f"Verification failed: {len(self.failed_checks)} checks failed"

        # Rule 2: Check for hard failures
        if failed_count > 0:
            return "FAILED", f"{failed_count} task(s) failed"

        # Rule 3: Check for incomplete tasks
        if incomplete_count > 0:
            return "FAILED_VERIFY", f"{incomplete_count} task(s) incomplete"

        # Rule 4: Check for critical/high risks
        if risk_counts["critical"] > 0:
            return "FAILED", f"{risk_counts['critical']} CRITICAL risk(s) found"

        if risk_counts["high"] > 0:
            return "FAILED", f"{risk_counts['high']} HIGH risk(s) found"

        # Rule 5: Check for intentional stops (via execution summary or task status)
        if self.execution_summary.get("global_stop") and self.execution_summary.get("stop_type") == "intentional":
            return "STOPPED", f"Intentional stop: {self.execution_summary.get('stop_reason', 'stop condition triggered')}"

        if stopped_count > 0:
            return "STOPPED", f"{stopped_count} task(s) stopped by condition"

        # Rule 6: Check for warnings (MEDIUM/LOW risks)
        if risk_counts["medium"] > 0 or risk_counts["low"] > 0:
            warning_count = risk_counts["medium"] + risk_counts["low"]
            return "OK_WITH_WARNINGS", f"{warning_count} MEDIUM/LOW risk(s) found"

        # Rule 7: All clear - strict requirements
        # All tasks must be SUCCESS or acceptable skip
        acceptable_count = success_count + skipped_count
        if acceptable_count != total_tasks:
            return "FAILED_VERIFY", f"Only {acceptable_count}/{total_tasks} tasks completed acceptably"

        # If we get here, everything is truly clear
        return "ALL_CLEAR", f"All {success_count} task(s) successful, no risks found"

    def verify(self) -> RunStatus:
        """
        Run complete verification and determine final status.

        Returns RunStatus with deterministic final status.
        """
        # Run all verification checks
        self.verify_artifacts_exist()
        self.verify_evidence_hashes()
        self.verify_risk_evidence_links()
        self.verify_task_outputs()
        self.verify_approvals()  # Phase 2.3: Check proposal approvals

        # Determine final status
        final_status, status_reason = self.determine_status()

        # Build task summary
        task_counts = self._count_tasks_by_status()
        task_summary = {
            "total": sum(task_counts.values()),
            "by_status": task_counts,
            "acceptable_skips": [
                r.get("task_id") for r in self.results
                if r.get("status", "").upper() in ACCEPTABLE_SKIPS
            ]
        }

        # Build risk summary
        risk_summary = self._count_risks_by_severity()

        # Build verification summary
        verification = {
            "passed": len(self.failed_checks) == 0,
            "checks": [{"check": c.check, "passed": c.passed, "details": c.details} for c in self.checks],
            "failed_checks": self.failed_checks,
        }

        run_id = self.plan.get("plan_id", "UNKNOWN").replace("PLAN-", "RUN-")

        status = RunStatus(
            run_id=run_id,
            final_status=final_status,
            status_reason=status_reason,
            verified_at=datetime.utcnow().isoformat() + "Z",
            task_summary=task_summary,
            risk_summary=risk_summary,
            verification=verification,
        )

        # Write RUN_STATUS.json
        status_path = self.run_dir / "RUN_STATUS.json"
        with open(status_path, "w") as f:
            json.dump(status.to_dict(), f, indent=2)

        return status


def verify_run(
    run_dir: Path,
    plan: dict,
    results: list[dict],
    risks: dict = None,
    evidence_index: dict = None,
    execution_summary: dict = None
) -> RunStatus:
    """
    Convenience function to run verification.

    Returns RunStatus with final determination.
    """
    # Load execution summary if not provided
    if execution_summary is None:
        summary_path = Path(run_dir) / "bq_executor" / "evidence" / "EXECUTION_SUMMARY.json"
        if summary_path.exists():
            with open(summary_path) as f:
                execution_summary = json.load(f)
        else:
            execution_summary = {}

    verifier = RunVerifier(run_dir, plan, results, risks, evidence_index, execution_summary)
    return verifier.verify()
