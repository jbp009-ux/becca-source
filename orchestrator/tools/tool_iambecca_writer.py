#!/usr/bin/env python3
"""
tool_iambecca_writer.py - Evidence-backed Report Writer

Writes truth-backed reports to the IAMBecca (control-plane) repository.
Every write includes evidence references - no claims without proof.

Writes to:
  - governance/state/STATUS.json (truth cache)
  - governance/runs/RUN_LEDGER.jsonl (append-only log)
  - governance/reports/<project>/<run_id>.md (human-readable)

This tool enforces the "scientist, not storyteller" principle:
  - Every claim must cite evidence
  - Unknown data must be explicitly marked
  - No fake progress numbers
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any


# Paths relative to becca-kernel root
BECCA_ROOT = Path(__file__).parent.parent.parent
STATE_FILE = BECCA_ROOT / "governance" / "state" / "STATUS.json"
LEDGER_FILE = BECCA_ROOT / "governance" / "command-center" / "ledger" / "RUN_LEDGER.jsonl"
REPORTS_DIR = BECCA_ROOT / "governance" / "reports"


@dataclass
class TruthModeResponse:
    """
    A response that follows the Truth Mode contract.

    Every BECCA Online response must be structured this way.
    """
    claims: List[str]
    evidence: List[Dict[str, str]]  # [{id, source, description}]
    unknown: List[str]
    next_action: str
    project_id: Optional[str] = None
    run_id: Optional[str] = None
    timestamp: Optional[str] = None

    def to_markdown(self) -> str:
        """Format as Truth Mode markdown."""
        lines = []

        lines.append("## CLAIMS")
        for claim in self.claims:
            lines.append(f"- {claim}")
        lines.append("")

        lines.append("## EVIDENCE")
        for ev in self.evidence:
            ev_id = ev.get("id", "?")
            source = ev.get("source", "unknown")
            desc = ev.get("description", "")
            url = ev.get("url", "")
            if url:
                lines.append(f"- [{ev_id}] {source}: {desc} ([link]({url}))")
            else:
                lines.append(f"- [{ev_id}] {source}: {desc}")
        lines.append("")

        lines.append("## UNKNOWN")
        if self.unknown:
            for item in self.unknown:
                lines.append(f"- {item}")
        else:
            lines.append("- (nothing unknown at this time)")
        lines.append("")

        lines.append("## NEXT ACTION")
        lines.append(f"- {self.next_action}")
        lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        return asdict(self)


def update_status_json(project_id: str, github_truth: Optional[Dict] = None,
                       bridge_truth: Optional[Dict] = None) -> bool:
    """
    Update the STATUS.json truth cache for a project.

    Only updates fields that have new evidence.
    Returns True if update succeeded.
    """
    if not STATE_FILE.exists():
        return False

    with open(STATE_FILE, "r", encoding="utf-8") as f:
        status = json.load(f)

    now = datetime.now(timezone.utc).isoformat()

    if project_id not in status.get("projects", {}):
        status["projects"][project_id] = {
            "updatedAt": None,
            "sources": [],
            "github": {},
            "bridge": {},
            "notes": ""
        }

    proj = status["projects"][project_id]
    proj["updatedAt"] = now
    sources = set(proj.get("sources", []))

    # Update from GitHub truth
    if github_truth:
        sources.add("github")
        proj["github"] = {
            "latestCommit": github_truth.get("latest_commit"),
            "latestCommitMessage": github_truth.get("latest_commit_message"),
            "latestCommitDate": github_truth.get("latest_commit_date"),
            "openPRs": github_truth.get("open_prs"),
            "openIssues": github_truth.get("open_issues"),
            "latestWorkflow": github_truth.get("latest_workflow")
        }

    # Update from bridge truth
    if bridge_truth:
        sources.add("bridge")
        proj["bridge"] = {
            "connected": True,
            "lastConnectedAt": now,
            "gitDirty": bridge_truth.get("git_dirty"),
            "lastTestRun": bridge_truth.get("last_test_run")
        }

    proj["sources"] = list(sources)

    # Build notes from evidence
    notes_parts = []
    if github_truth:
        notes_parts.append(f"GitHub: {github_truth.get('open_prs', 0)} open PRs")
        if github_truth.get("latest_workflow"):
            wf = github_truth["latest_workflow"]
            notes_parts.append(f"CI: {wf.get('conclusion', 'unknown')}")
    if bridge_truth:
        dirty = "dirty" if bridge_truth.get("git_dirty") else "clean"
        notes_parts.append(f"Local: {dirty}")

    proj["notes"] = " | ".join(notes_parts) if notes_parts else "Updated with new evidence"

    status["generatedAt"] = now

    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(status, f, indent=2)

    return True


def append_to_ledger(run_id: str, project_id: str, state: str, tool: str,
                     action: str, status: str, artifacts: List[str] = None,
                     evidence_refs: List[str] = None) -> bool:
    """
    Append an entry to the global RUN_LEDGER.jsonl.

    This is append-only - never modify existing entries.
    """
    LEDGER_FILE.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "project": project_id,
        "state": state,
        "tool": tool,
        "action": action,
        "status": status,
        "artifacts": artifacts or [],
        "evidenceRefs": evidence_refs or []
    }

    with open(LEDGER_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    return True


def write_report(project_id: str, run_id: str, truth_response: TruthModeResponse,
                 github_truth: Optional[Dict] = None,
                 bridge_truth: Optional[Dict] = None) -> Path:
    """
    Write a Truth Mode report to the reports directory.

    Returns the path to the created report.
    """
    report_dir = REPORTS_DIR / project_id
    report_dir.mkdir(parents=True, exist_ok=True)

    report_file = report_dir / f"{run_id}.md"

    now = datetime.now(timezone.utc)

    lines = [
        f"# BECCA Status Report: {project_id}",
        f"**Run ID:** {run_id}",
        f"**Generated:** {now.isoformat()}",
        "",
        "---",
        "",
        truth_response.to_markdown(),
        "---",
        "",
        "## Raw Evidence",
        ""
    ]

    # Include GitHub summary if available
    if github_truth:
        lines.append("### GitHub Truth")
        lines.append("```json")
        lines.append(json.dumps({
            "repo": github_truth.get("repo"),
            "latest_commit": github_truth.get("latest_commit"),
            "open_prs": github_truth.get("open_prs"),
            "open_issues": github_truth.get("open_issues"),
            "ci_status": github_truth.get("latest_workflow", {}).get("conclusion") if github_truth.get("latest_workflow") else None
        }, indent=2))
        lines.append("```")
        lines.append("")

    # Include bridge summary if available
    if bridge_truth:
        lines.append("### Bridge Truth")
        lines.append("```json")
        lines.append(json.dumps(bridge_truth, indent=2))
        lines.append("```")
        lines.append("")

    lines.append("---")
    lines.append(f"*Generated by BECCA Online - Evidence Count: {len(truth_response.evidence)}*")

    with open(report_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return report_file


def build_truth_response(project_id: str, github_truth: Optional[Dict] = None,
                         bridge_truth: Optional[Dict] = None) -> TruthModeResponse:
    """
    Build a Truth Mode response from available evidence.

    This is the core function that ensures no claims without evidence.
    """
    claims = []
    evidence = []
    unknown = []
    next_action = "Collect more evidence"

    evidence_count = 0

    # Process GitHub truth
    if github_truth:
        # Latest commit claim
        if github_truth.get("latest_commit"):
            claims.append(f"Latest commit is {github_truth['latest_commit'][:7]}: \"{github_truth.get('latest_commit_message', 'N/A')}\"")
            evidence.append({
                "id": f"E{evidence_count + 1}",
                "source": "github",
                "description": f"commit {github_truth['latest_commit'][:7]} at {github_truth.get('latest_commit_date', 'unknown')}",
                "url": f"https://github.com/{github_truth.get('repo')}/commit/{github_truth['latest_commit']}"
            })
            evidence_count += 1

        # PR count claim
        if github_truth.get("open_prs") is not None:
            claims.append(f"{github_truth['open_prs']} open pull requests")
            evidence.append({
                "id": f"E{evidence_count + 1}",
                "source": "github",
                "description": f"PR count from GitHub API",
                "url": f"https://github.com/{github_truth.get('repo')}/pulls"
            })
            evidence_count += 1

        # Issue count claim
        if github_truth.get("open_issues") is not None:
            claims.append(f"{github_truth['open_issues']} open issues")
            evidence.append({
                "id": f"E{evidence_count + 1}",
                "source": "github",
                "description": f"Issue count from GitHub API",
                "url": f"https://github.com/{github_truth.get('repo')}/issues"
            })
            evidence_count += 1

        # CI status claim
        if github_truth.get("latest_workflow"):
            wf = github_truth["latest_workflow"]
            status = wf.get("conclusion") or wf.get("status")
            claims.append(f"CI ({wf.get('name', 'workflow')}): {status}")
            evidence.append({
                "id": f"E{evidence_count + 1}",
                "source": "github",
                "description": f"workflow run {wf.get('databaseId')}",
                "url": f"https://github.com/{github_truth.get('repo')}/actions/runs/{wf.get('databaseId')}"
            })
            evidence_count += 1
    else:
        unknown.append("GitHub state not fetched (computer may be offline or gh CLI not configured)")

    # Process bridge truth
    if bridge_truth:
        if bridge_truth.get("connected"):
            dirty = bridge_truth.get("git_dirty")
            if dirty is not None:
                status = "uncommitted changes" if dirty else "clean"
                claims.append(f"Local working directory is {status}")
                evidence.append({
                    "id": f"E{evidence_count + 1}",
                    "source": "bridge",
                    "description": f"git status at {bridge_truth.get('timestamp', 'recently')}"
                })
                evidence_count += 1

            if bridge_truth.get("last_test_run"):
                test = bridge_truth["last_test_run"]
                claims.append(f"Last test run: {test.get('status', 'unknown')}")
                evidence.append({
                    "id": f"E{evidence_count + 1}",
                    "source": "bridge",
                    "description": f"{test.get('command', 'tests')} at {test.get('timestamp', 'recently')}"
                })
                evidence_count += 1
    else:
        unknown.append("Local bridge not connected (development machine may be offline)")

    # Determine next action
    if not claims:
        next_action = "Run `gh auth login` to enable GitHub API access, or start the local bridge"
    elif unknown:
        if "bridge" in str(unknown):
            next_action = "Start local bridge to get live development status"
        else:
            next_action = "Configure GitHub CLI to get remote repository status"
    else:
        next_action = "All evidence sources connected. Run specific analysis if needed."

    return TruthModeResponse(
        claims=claims,
        evidence=evidence,
        unknown=unknown,
        next_action=next_action,
        project_id=project_id,
        timestamp=datetime.now(timezone.utc).isoformat()
    )


def run_iambecca_writer(run_id: str, project_id: str, github_truth: Optional[Dict] = None,
                        bridge_truth: Optional[Dict] = None) -> dict:
    """
    Main entry point for the IAMBecca writer tool.

    Writes:
      1. STATUS.json update
      2. RUN_LEDGER.jsonl append
      3. Report markdown

    Returns ARTIFACT_SPEC compliant output.
    """
    started_at = datetime.now(timezone.utc)
    artifacts = []
    errors = []

    # 1. Build truth response
    truth_response = build_truth_response(project_id, github_truth, bridge_truth)
    truth_response.run_id = run_id

    # 2. Update STATUS.json
    try:
        update_status_json(project_id, github_truth, bridge_truth)
        artifacts.append(str(STATE_FILE))
    except Exception as e:
        errors.append(f"Failed to update STATUS.json: {e}")

    # 3. Append to ledger
    try:
        evidence_refs = [e.get("id") for e in truth_response.evidence]
        append_to_ledger(
            run_id=run_id,
            project_id=project_id,
            state="COMPLETE",
            tool="iambecca_writer",
            action="write_report",
            status="ok",
            artifacts=artifacts,
            evidence_refs=evidence_refs
        )
        artifacts.append(str(LEDGER_FILE))
    except Exception as e:
        errors.append(f"Failed to append to ledger: {e}")

    # 4. Write report
    try:
        report_path = write_report(project_id, run_id, truth_response, github_truth, bridge_truth)
        artifacts.append(str(report_path))
    except Exception as e:
        errors.append(f"Failed to write report: {e}")

    completed_at = datetime.now(timezone.utc)

    return {
        "tool_id": "tool_iambecca_writer",
        "run_id": run_id,
        "project_id": project_id,
        "status": "pass" if not errors else "partial",
        "truth_response": truth_response.to_dict(),
        "truth_response_markdown": truth_response.to_markdown(),
        "evidence_count": len(truth_response.evidence),
        "artifacts": artifacts,
        "errors": errors,
        "timing": {
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration_seconds": (completed_at - started_at).total_seconds()
        }
    }


# CLI for testing
if __name__ == "__main__":
    import sys

    run_id = f"RUN-TEST-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    project_id = sys.argv[1] if len(sys.argv) > 1 else "sonny"

    print(f"Testing IAMBecca writer for {project_id}...")

    # Simulate some truth data
    fake_github = {
        "repo": "anthropics/sonny",
        "latest_commit": "abc1234567890",
        "latest_commit_message": "Fix login bug",
        "latest_commit_date": "2026-02-03T20:00:00Z",
        "open_prs": 3,
        "open_issues": 12,
        "latest_workflow": {
            "name": "ci",
            "databaseId": 123456,
            "conclusion": "success"
        }
    }

    result = run_iambecca_writer(run_id, project_id, github_truth=fake_github)

    print("\n=== Truth Mode Response ===")
    print(result["truth_response_markdown"])
    print(f"\nEvidence count: {result['evidence_count']}")
    print(f"Artifacts: {result['artifacts']}")
