#!/usr/bin/env python3
"""
ghost_archivist.py - Ghost Archivist

The Ghost Archivist collects all task results and evidence, generating:
  - RISKS.json: Aggregated risks from all tasks
  - EVIDENCE_INDEX.json: Catalog of all evidence artifacts
  - FINAL_REPORT.md: Human-readable summary

Ghost observes everything but touches nothing (except reports).

Protocol:
  1. Collect all RESULT.json from tasks
  2. Extract risks from findings
  3. Catalog all evidence with hashes
  4. Generate RISKS.json with severity summary
  5. Generate EVIDENCE_INDEX.json with linkages
  6. Produce FINAL_REPORT.md

Usage:
    from orchestrator.agents.ghost_archivist import GhostArchivist

    ghost = GhostArchivist(run_dir, plan, results)
    ghost.archive()
"""

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class Risk:
    """A risk finding."""
    risk_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str = ""
    category: str = "unknown"
    evidence_ids: list[str] = field(default_factory=list)
    source_task: str = ""
    location: dict = field(default_factory=dict)
    confidence: str = "MEDIUM"
    recommendation: str = ""
    auto_fixable: bool = False


@dataclass
class Evidence:
    """An evidence artifact."""
    evidence_id: str
    path: str
    type: str
    format: str
    description: str = ""
    source_task: str = ""
    source_tool: str = ""
    generated_at: str = ""
    size_bytes: int = 0
    hash: str = ""
    linked_risks: list[str] = field(default_factory=list)
    retention: str = "run_lifetime"


class GhostArchivist:
    """
    Ghost Archivist - Collects, catalogs, and reports.

    Ghost sees all. Ghost remembers all. Ghost judges none.
    """

    VERSION = "1.0.0"

    def __init__(self, run_dir: Path, plan: dict, results: list[dict]):
        self.run_dir = Path(run_dir)
        self.plan = plan
        self.results = results  # List of TaskResult dicts

        self.risks: list[Risk] = []
        self.evidence: list[Evidence] = []
        self.suppressed_risks: list[dict] = []

        # Create ghost evidence directory
        self.evidence_dir = self.run_dir / "ghost_archivist" / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Track evidence ID counter
        self._evidence_counter = 0
        self._risk_counter = 0

    def _next_evidence_id(self) -> str:
        """Generate next evidence ID."""
        self._evidence_counter += 1
        return f"E{self._evidence_counter:04d}"

    def _next_risk_id(self) -> str:
        """Generate next risk ID."""
        self._risk_counter += 1
        return f"R{self._risk_counter:04d}"

    def _hash_file(self, path: Path) -> str:
        """Generate SHA256 hash of a file."""
        if not path.exists():
            return ""

        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        return f"sha256:{sha256.hexdigest()}"

    def collect_evidence(self):
        """
        Collect all evidence artifacts from task results.
        """
        for result in self.results:
            task_id = result.get("task_id", "")
            tool = result.get("tool", "")

            for output in result.get("outputs", []):
                path_str = output.get("path", "")
                if not path_str:
                    continue

                # Resolve path relative to run_dir
                if Path(path_str).is_absolute():
                    path = Path(path_str)
                else:
                    path = self.run_dir / path_str

                if not path.exists():
                    continue

                # Determine evidence type
                artifact = output.get("artifact", path.stem)
                ev_type = self._classify_evidence(artifact, tool)

                evidence = Evidence(
                    evidence_id=self._next_evidence_id(),
                    path=str(path.relative_to(self.run_dir)),
                    type=ev_type,
                    format=output.get("format", path.suffix.lstrip(".")),
                    description=f"{artifact} from {tool}",
                    source_task=task_id,
                    source_tool=tool,
                    generated_at=result.get("completed_at", ""),
                    size_bytes=output.get("size_bytes", path.stat().st_size if path.exists() else 0),
                    hash=output.get("hash", self._hash_file(path)),
                )

                self.evidence.append(evidence)

    def _classify_evidence(self, artifact: str, tool: str) -> str:
        """Classify evidence type based on artifact name and tool."""
        artifact_lower = artifact.lower()

        if "secret" in artifact_lower:
            return "secrets_findings"
        elif "rules" in artifact_lower:
            return "rules_analysis"
        elif "profile" in artifact_lower:
            return "scan_profile"
        elif "test" in artifact_lower:
            return "test_results"
        elif "console" in artifact_lower:
            return "console_output"
        elif "config" in artifact_lower:
            return "config_snapshot"
        elif "screenshot" in artifact_lower:
            return "screenshot"
        elif "log" in artifact_lower:
            return "log_extract"
        elif "audit" in artifact_lower:
            return "audit_trail"
        else:
            return "audit_trail"

    def extract_risks(self):
        """
        Extract risks from task results and evidence.
        """
        for result in self.results:
            task_id = result.get("task_id", "")
            tool = result.get("tool", "")

            # Look for findings in result metrics
            metrics = result.get("metrics", {})
            findings = metrics.get("findings", [])

            # Also check stats for severity counts
            stats = result.get("stats", {})
            by_severity = stats.get("findings_by_severity", {})

            # Extract risks from findings
            for finding in findings:
                risk = self._finding_to_risk(finding, task_id, tool)
                if risk:
                    self.risks.append(risk)

        # Also scan evidence files for findings
        self._scan_evidence_for_risks()

    def _finding_to_risk(self, finding: dict, task_id: str, tool: str) -> Optional[Risk]:
        """Convert a finding dict to a Risk object."""
        if not finding:
            return None

        severity = finding.get("severity", "MEDIUM")
        pattern_id = finding.get("pattern_id", finding.get("id", ""))
        file_path = finding.get("file", "")
        line = finding.get("line", 0)

        # Determine category from tool
        category = "configuration"
        if tool == "secrets_scanner":
            category = "secrets"
        elif tool == "rules_auditor":
            category = "access_control"
        elif "injection" in str(finding).lower():
            category = "injection"

        # Find linked evidence
        evidence_ids = []
        for ev in self.evidence:
            if ev.source_task == task_id:
                evidence_ids.append(ev.evidence_id)

        return Risk(
            risk_id=self._next_risk_id(),
            severity=severity,
            title=f"{pattern_id}: {finding.get('name', 'Unknown')}",
            description=finding.get("description", f"Found {pattern_id} in {file_path}"),
            category=category,
            evidence_ids=evidence_ids[:3],  # Limit to 3
            source_task=task_id,
            location={
                "file": file_path,
                "line": line,
                "snippet": finding.get("redacted", "")[:100],
            },
            confidence=finding.get("confidence", "MEDIUM"),
            recommendation=self._get_recommendation(category, severity),
        )

    def _scan_evidence_for_risks(self):
        """Scan evidence files for additional risks."""
        for ev in self.evidence:
            if ev.type != "secrets_findings":
                continue

            path = self.run_dir / ev.path
            if not path.exists() or ev.format != "json":
                continue

            try:
                with open(path) as f:
                    data = json.load(f)

                findings = data.get("findings", [])
                for finding in findings:
                    # Skip if already processed (by pattern_id + file + line)
                    if self._risk_exists(finding):
                        continue

                    risk = self._finding_to_risk(finding, ev.source_task, ev.source_tool)
                    if risk:
                        risk.evidence_ids.append(ev.evidence_id)
                        self.risks.append(risk)

            except (json.JSONDecodeError, IOError):
                continue

    def _risk_exists(self, finding: dict) -> bool:
        """Check if a risk already exists for this finding."""
        pattern_id = finding.get("pattern_id", "")
        file_path = finding.get("file", "")
        line = finding.get("line", 0)

        for risk in self.risks:
            loc = risk.location
            if loc.get("file") == file_path and loc.get("line") == line:
                if pattern_id in risk.title:
                    return True

        return False

    def _get_recommendation(self, category: str, severity: str) -> str:
        """Generate recommendation based on category and severity."""
        recommendations = {
            ("secrets", "CRITICAL"): "Immediately rotate the exposed credential and audit access logs.",
            ("secrets", "HIGH"): "Rotate credential and move to environment variables or secret manager.",
            ("secrets", "MEDIUM"): "Review if this secret needs to be in code; consider environment variables.",
            ("secrets", "LOW"): "Monitor for any exposure; no immediate action required.",
            ("access_control", "CRITICAL"): "Fix security rules immediately; data may be publicly accessible.",
            ("access_control", "HIGH"): "Review and tighten access rules; potential data exposure.",
            ("access_control", "MEDIUM"): "Review rule logic for edge cases.",
            ("injection", "CRITICAL"): "Sanitize all user inputs immediately.",
            ("injection", "HIGH"): "Implement input validation and output encoding.",
        }

        return recommendations.get(
            (category, severity),
            f"Review {category} finding and address based on severity."
        )

    def link_risks_to_evidence(self):
        """Create bidirectional links between risks and evidence."""
        for risk in self.risks:
            for ev_id in risk.evidence_ids:
                for ev in self.evidence:
                    if ev.evidence_id == ev_id:
                        if risk.risk_id not in ev.linked_risks:
                            ev.linked_risks.append(risk.risk_id)

    def generate_risks_json(self) -> dict:
        """Generate RISKS.json document."""
        run_id = self.plan.get("plan_id", "").replace("PLAN-", "RUN-")
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

        # Summary stats
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_category = {}
        actionable = 0

        for risk in self.risks:
            by_severity[risk.severity] = by_severity.get(risk.severity, 0) + 1
            by_category[risk.category] = by_category.get(risk.category, 0) + 1
            if risk.severity in ["CRITICAL", "HIGH"]:
                actionable += 1

        risks_doc = {
            "risks_id": f"RISKS-{self.plan.get('project', 'UNKNOWN').upper()}-{timestamp}",
            "plan_id": self.plan.get("plan_id", ""),
            "run_id": run_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "summary": {
                "total_risks": len(self.risks),
                "by_severity": by_severity,
                "by_category": by_category,
                "actionable_count": actionable,
                "suppressed_count": len(self.suppressed_risks),
            },
            "risks": [asdict(r) for r in self.risks],
            "suppressed": self.suppressed_risks,
        }

        # Write to evidence dir
        risks_path = self.evidence_dir / "RISKS.json"
        with open(risks_path, "w") as f:
            json.dump(risks_doc, f, indent=2)

        return risks_doc

    def generate_evidence_index(self) -> dict:
        """Generate EVIDENCE_INDEX.json document."""
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

        # Summary stats
        by_type = {}
        by_source = {}
        total_size = 0

        for ev in self.evidence:
            by_type[ev.type] = by_type.get(ev.type, 0) + 1
            by_source[ev.source_task] = by_source.get(ev.source_task, 0) + 1
            total_size += ev.size_bytes

        index_doc = {
            "index_id": f"EVIDENCE-{self.plan.get('project', 'UNKNOWN').upper()}-{timestamp}",
            "run_id": self.plan.get("plan_id", "").replace("PLAN-", "RUN-"),
            "plan_id": self.plan.get("plan_id", ""),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "base_path": str(self.run_dir),
            "summary": {
                "total_items": len(self.evidence),
                "total_size_bytes": total_size,
                "by_type": by_type,
                "by_source_task": by_source,
            },
            "evidence": [asdict(e) for e in self.evidence],
        }

        # Write to evidence dir
        index_path = self.evidence_dir / "EVIDENCE_INDEX.json"
        with open(index_path, "w") as f:
            json.dump(index_doc, f, indent=2)

        return index_doc

    def generate_final_report(self) -> str:
        """Generate FINAL_REPORT.md with human-readable summary."""
        plan_id = self.plan.get("plan_id", "UNKNOWN")
        mission = self.plan.get("mission", "")
        project = self.plan.get("project", "")

        # Calculate totals with proper status counting
        total_tasks = len(self.results)

        # Count by normalized status
        status_counts = {}
        for r in self.results:
            s = r.get("status", "INCOMPLETE").upper()
            # Normalize old status names
            s = {"SUCCESS": "SUCCESS", "PASS": "SUCCESS", "PARTIAL": "INCOMPLETE",
                 "BLOCKED": "SKIPPED", "FAILED": "FAILED"}.get(s, s)
            status_counts[s] = status_counts.get(s, 0) + 1

        successful = status_counts.get("SUCCESS", 0)
        failed = status_counts.get("FAILED", 0)
        incomplete = status_counts.get("INCOMPLETE", 0)
        skipped = status_counts.get("SKIPPED", 0) + status_counts.get("SKIPPED_DEPENDENCY", 0)

        # Risk summary
        critical = sum(1 for r in self.risks if r.severity == "CRITICAL")
        high = sum(1 for r in self.risks if r.severity == "HIGH")
        medium = sum(1 for r in self.risks if r.severity == "MEDIUM")
        low = sum(1 for r in self.risks if r.severity == "LOW")

        # Determine overall status using strict rules (no false greens)
        # Rule: ALL_CLEAR only if all tasks SUCCESS and no CRITICAL/HIGH risks
        if failed > 0 or incomplete > 0:
            status = "⚠️ FAILED - Tasks did not complete"
            status_emoji = "⚠️"
            final_status = "FAILED"
        elif critical > 0:
            status = "🔴 FAILED - CRITICAL ISSUES FOUND"
            status_emoji = "🔴"
            final_status = "FAILED"
        elif high > 0:
            status = "🟠 FAILED - HIGH PRIORITY ISSUES"
            status_emoji = "🟠"
            final_status = "FAILED"
        elif medium > 0 or low > 0:
            status = "🟡 OK WITH WARNINGS"
            status_emoji = "🟡"
            final_status = "OK_WITH_WARNINGS"
        elif successful + skipped == total_tasks and successful > 0:
            status = "✅ ALL CLEAR"
            status_emoji = "✅"
            final_status = "ALL_CLEAR"
        else:
            # Catch-all: if we can't confirm success, don't claim it
            status = "⚠️ FAILED_VERIFY - Status indeterminate"
            status_emoji = "⚠️"
            final_status = "FAILED_VERIFY"

        # Store for later use
        self._final_status = final_status

        report = f"""# BECCA Run Report

## Summary

| Field | Value |
|-------|-------|
| Plan ID | `{plan_id}` |
| Project | `{project}` |
| Mission | {mission} |
| Status | {status} |
| Generated | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC |

## Execution Summary

| Metric | Count |
|--------|-------|
| Tasks Executed | {total_tasks} |
| Successful | {successful} |
| Failed | {failed} |
| Evidence Items | {len(self.evidence)} |

## Risk Summary {status_emoji}

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | {critical} |
| 🟠 HIGH | {high} |
| 🟡 MEDIUM | {medium} |
| 🟢 LOW | {low} |
| **Total** | **{len(self.risks)}** |

"""

        # Add risk details if any
        if self.risks:
            report += "## Risk Details\n\n"

            # Group by severity
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                risks_at_level = [r for r in self.risks if r.severity == severity]
                if not risks_at_level:
                    continue

                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
                report += f"### {emoji} {severity}\n\n"

                for risk in risks_at_level[:10]:  # Limit to 10 per severity
                    location = risk.location
                    file_info = f"`{location.get('file', 'unknown')}:{location.get('line', 0)}`" if location else ""
                    report += f"**{risk.risk_id}**: {risk.title}\n"
                    report += f"- Category: {risk.category}\n"
                    if file_info:
                        report += f"- Location: {file_info}\n"
                    report += f"- Recommendation: {risk.recommendation}\n\n"

        # Add task details
        report += "## Task Results\n\n"
        report += "| Task | Tool | Status | Duration |\n"
        report += "|------|------|--------|----------|\n"

        for result in self.results:
            task_id = result.get("task_id", "")
            tool = result.get("tool", "")
            status = result.get("status", "unknown")
            timing = result.get("timing", {})
            duration = f"{timing.get('total_ms', 0):.0f}ms"

            status_icon = {
                "success": "✅",
                "partial": "⚠️",
                "failed": "❌",
                "blocked": "🚫",
                "timeout": "⏱️",
            }.get(status, "❓")

            report += f"| {task_id} | {tool} | {status_icon} {status} | {duration} |\n"

        # Add evidence section
        report += "\n## Evidence Artifacts\n\n"
        report += f"Total: {len(self.evidence)} items\n\n"

        for ev in self.evidence[:20]:  # Limit to 20
            report += f"- `{ev.path}` ({ev.type})\n"

        if len(self.evidence) > 20:
            report += f"\n*...and {len(self.evidence) - 20} more artifacts*\n"

        # Footer
        report += f"""
---

*Generated by BECCA Ghost Archivist v{self.VERSION}*
"""

        # Write report (use UTF-8 for emoji support)
        report_path = self.run_dir / "FINAL_REPORT.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)

        return report

    def generate_run_summary(self, risks_doc: dict, evidence_doc: dict) -> dict:
        """
        Generate RUN_SUMMARY.json for CI/dashboard consumption.

        Machine-readable summary with:
        - final status + reason
        - task counts by status
        - risk counts by severity
        - performance totals
        - links to key artifacts
        """
        plan_id = self.plan.get("plan_id", "UNKNOWN")
        project = self.plan.get("project", "")
        mission = self.plan.get("mission", "")

        # Count tasks by status (normalize to uppercase)
        task_counts = {}
        total_ms = 0
        for r in self.results:
            status = r.get("status", "INCOMPLETE").upper()
            # Normalize common variations
            if status == "PASS":
                status = "SUCCESS"
            task_counts[status] = task_counts.get(status, 0) + 1
            # Sum timing
            timing = r.get("timing", {})
            total_ms += timing.get("total_ms", 0)

        # Risk counts
        risk_counts = {
            "critical": sum(1 for r in self.risks if r.severity == "CRITICAL"),
            "high": sum(1 for r in self.risks if r.severity == "HIGH"),
            "medium": sum(1 for r in self.risks if r.severity == "MEDIUM"),
            "low": sum(1 for r in self.risks if r.severity == "LOW"),
        }

        # Determine status (same logic as generate_final_report)
        failed = task_counts.get("FAILED", 0)
        incomplete = task_counts.get("INCOMPLETE", 0)
        success = task_counts.get("SUCCESS", 0)

        if failed > 0 or incomplete > 0:
            final_status = "FAILED"
            status_reason = f"{failed + incomplete} task(s) did not complete"
        elif risk_counts["critical"] > 0:
            final_status = "FAILED"
            status_reason = f"{risk_counts['critical']} CRITICAL risk(s)"
        elif risk_counts["high"] > 0:
            final_status = "FAILED"
            status_reason = f"{risk_counts['high']} HIGH risk(s)"
        elif risk_counts["medium"] > 0 or risk_counts["low"] > 0:
            final_status = "OK_WITH_WARNINGS"
            status_reason = f"{risk_counts['medium'] + risk_counts['low']} warning(s)"
        elif success == len(self.results) and success > 0:
            final_status = "ALL_CLEAR"
            status_reason = f"All {success} task(s) successful"
        else:
            final_status = "FAILED_VERIFY"
            status_reason = "Status indeterminate"

        summary = {
            "schema_version": "1.0.0",
            "plan_id": plan_id,
            "project": project,
            "mission": mission,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "status": {
                "final": final_status,
                "reason": status_reason,
            },
            "tasks": {
                "total": len(self.results),
                "by_status": task_counts,
            },
            "risks": {
                "total": len(self.risks),
                "by_severity": risk_counts,
            },
            "performance": {
                "total_ms": total_ms,
                "total_seconds": round(total_ms / 1000, 2),
            },
            "artifacts": {
                "risks": "ghost_archivist/evidence/RISKS.json",
                "evidence_index": "ghost_archivist/evidence/EVIDENCE_INDEX.json",
                "final_report": "FINAL_REPORT.md",
                "plan": "mq_planner/evidence/PLAN.json",
            },
        }

        # Add proposal safety score if proposals exist
        proposals_dir = self.run_dir / "proposals"
        if proposals_dir.exists():
            proposals = list(proposals_dir.glob("PROPOSAL-*.json"))
            if proposals:
                summary["proposals"] = self._compute_proposal_safety(proposals)

        # Write summary
        summary_path = self.run_dir / "RUN_SUMMARY.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        return summary

    def _compute_proposal_safety(self, proposal_paths: list) -> dict:
        """
        Compute Patch Safety Score for proposals.

        Factors:
        - File count (fewer = safer)
        - File types (config < code)
        - Sensitive paths (auth, payments, deploy = risky)
        - Tests suggested (yes = safer)
        """
        SENSITIVE_PATHS = [
            "auth", "login", "password", "credential",
            "payment", "billing", "checkout", "stripe",
            "deploy", "ci", "workflow", ".github",
            "firestore.rules", "storage.rules",
            ".env", "secret", "key"
        ]

        SAFE_EXTENSIONS = {".md", ".txt", ".json", ".yaml", ".yml", ".toml"}
        CODE_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rs"}

        total_score = 0
        proposals_info = []

        for proposal_path in proposal_paths:
            try:
                with open(proposal_path) as f:
                    proposal = json.load(f)

                files = proposal.get("files", [])
                tests = proposal.get("tests_to_run", [])
                risk_class = proposal.get("risk_classification", "medium")

                # Start with base score
                score = 100

                # Penalty for file count
                file_count = len(files)
                if file_count > 10:
                    score -= 30
                elif file_count > 5:
                    score -= 15
                elif file_count > 3:
                    score -= 5

                # Check file types and sensitive paths
                sensitive_hits = 0
                code_files = 0

                for file_info in files:
                    path = file_info.get("path", "").lower()
                    ext = Path(path).suffix.lower()

                    # Check sensitive paths
                    for sensitive in SENSITIVE_PATHS:
                        if sensitive in path:
                            sensitive_hits += 1
                            break

                    # Categorize file type
                    if ext in CODE_EXTENSIONS:
                        code_files += 1

                # Penalties
                score -= sensitive_hits * 15  # Sensitive paths are risky
                score -= code_files * 5  # Code changes are riskier than config

                # Bonus for tests
                if tests:
                    score += min(10, len(tests) * 2)

                # Risk classification override
                if risk_class == "critical":
                    score = min(score, 30)
                elif risk_class == "high":
                    score = min(score, 50)

                # Clamp to 0-100
                score = max(0, min(100, score))
                total_score += score

                proposals_info.append({
                    "proposal_id": proposal.get("proposal_id", ""),
                    "safety_score": score,
                    "files_affected": file_count,
                    "sensitive_paths": sensitive_hits,
                    "has_tests": len(tests) > 0,
                    "risk_classification": risk_class,
                    "quick_approve": score >= 80  # Safe to approve quickly
                })

            except Exception:
                continue

        avg_score = total_score // len(proposals_info) if proposals_info else 0

        return {
            "count": len(proposals_info),
            "average_safety_score": avg_score,
            "quick_approve_count": sum(1 for p in proposals_info if p.get("quick_approve")),
            "needs_review_count": sum(1 for p in proposals_info if not p.get("quick_approve")),
            "proposals": proposals_info
        }

    def archive(self) -> dict:
        """
        Run complete archive process.

        Returns dict with paths to all generated artifacts.
        """
        print(f"      Ghost Archivist: Collecting evidence...")

        # Collect all evidence
        self.collect_evidence()
        print(f"          Evidence items: {len(self.evidence)}")

        # Extract risks
        self.extract_risks()
        print(f"          Risks found: {len(self.risks)}")

        # Link risks to evidence
        self.link_risks_to_evidence()

        # Generate artifacts
        risks_doc = self.generate_risks_json()
        evidence_doc = self.generate_evidence_index()
        report = self.generate_final_report()
        run_summary = self.generate_run_summary(risks_doc, evidence_doc)

        print(f"          RISKS.json: {risks_doc['summary']['total_risks']} risks")
        print(f"          EVIDENCE_INDEX.json: {evidence_doc['summary']['total_items']} items")
        print(f"          FINAL_REPORT.md: Generated")
        print(f"          RUN_SUMMARY.json: {run_summary['status']['final']}")

        return {
            "risks_path": str(self.evidence_dir / "RISKS.json"),
            "evidence_path": str(self.evidence_dir / "EVIDENCE_INDEX.json"),
            "report_path": str(self.run_dir / "FINAL_REPORT.md"),
            "summary_path": str(self.run_dir / "RUN_SUMMARY.json"),
            "risks_summary": risks_doc["summary"],
            "evidence_summary": evidence_doc["summary"],
            "run_summary": run_summary,
        }


def run_ghost_archivist(run_dir: Path, plan: dict, results: list[dict]) -> dict:
    """
    Convenience function to run Ghost Archivist.

    Args:
        run_dir: Run directory
        plan: Plan dict (from MQ)
        results: List of result dicts (from BQ)

    Returns:
        Dict with paths to generated artifacts
    """
    ghost = GhostArchivist(run_dir, plan, results)
    return ghost.archive()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ghost Archivist - Collect and Report")
    parser.add_argument("--run-dir", required=True, help="Run directory")
    parser.add_argument("--plan", required=True, help="Path to PLAN.json")
    parser.add_argument("--results", required=True, help="Path to results directory or JSON")

    args = parser.parse_args()

    run_dir = Path(args.run_dir)

    # Load plan
    with open(args.plan) as f:
        plan = json.load(f)

    # Load results
    results_path = Path(args.results)
    if results_path.is_dir():
        results = []
        for rp in results_path.glob("RESULT_*.json"):
            with open(rp) as f:
                results.append(json.load(f))
    else:
        with open(results_path) as f:
            results = json.load(f)

    output = run_ghost_archivist(run_dir, plan, results)

    print(f"\nArchive complete:")
    print(f"  Risks: {output['risks_path']}")
    print(f"  Evidence: {output['evidence_path']}")
    print(f"  Report: {output['report_path']}")
