#!/usr/bin/env python3
"""
tool_github.py - GitHub Remote Truth Fetcher

Fetches project state from GitHub API when local machine is unavailable.
This tool is the foundation of "BECCA Online" - phone-accessible updates
that don't require the development machine to be running.

Evidence sources:
  - Commits (SHA, message, author, date)
  - Pull Requests (count, titles, states)
  - Issues (count, labels)
  - Workflow Runs (CI status)
  - Branch info

Every piece of data returned includes an evidence reference for traceability.
"""

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any


@dataclass
class EvidenceRef:
    """A traceable reference to evidence source."""
    source: str  # "github", "bridge", "local"
    type: str    # "commit", "pr", "issue", "workflow", "branch"
    id: str      # SHA, PR number, run ID, etc.
    url: Optional[str] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class GitHubTruth:
    """Truth snapshot from GitHub API."""
    project_id: str
    repo: str
    fetched_at: str

    # Commits
    latest_commit: Optional[str] = None
    latest_commit_message: Optional[str] = None
    latest_commit_date: Optional[str] = None
    recent_commits: List[Dict] = field(default_factory=list)

    # PRs
    open_prs: int = 0
    pr_titles: List[str] = field(default_factory=list)

    # Issues
    open_issues: int = 0

    # CI/Workflows
    latest_workflow: Optional[Dict] = None

    # Branches
    default_branch: str = "main"

    # Evidence trail
    evidence_refs: List[Dict] = field(default_factory=list)

    # Errors
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def run_gh_command(args: List[str], timeout: int = 30) -> tuple[bool, str]:
    """
    Run a GitHub CLI command safely.

    Returns (success, output_or_error).
    """
    try:
        result = subprocess.run(
            ["gh"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace"
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            return False, result.stderr.strip() or f"Exit code {result.returncode}"
    except FileNotFoundError:
        return False, "GitHub CLI (gh) not installed. Install from https://cli.github.com/"
    except subprocess.TimeoutExpired:
        return False, f"Command timed out after {timeout}s"
    except Exception as e:
        return False, str(e)


def fetch_commits(repo: str, branch: str = "main", limit: int = 10) -> tuple[List[Dict], List[EvidenceRef]]:
    """Fetch recent commits from GitHub."""
    commits = []
    evidence = []

    # Use gh api to get commits
    success, output = run_gh_command([
        "api",
        f"repos/{repo}/commits",
        "-q", f".[:{limit}] | .[] | {{sha: .sha, message: .commit.message, date: .commit.author.date, author: .commit.author.name}}"
    ])

    if success and output:
        # Parse JSONL output
        for line in output.strip().split("\n"):
            if line:
                try:
                    commit = json.loads(line)
                    commits.append(commit)
                    evidence.append(EvidenceRef(
                        source="github",
                        type="commit",
                        id=commit["sha"],
                        url=f"https://github.com/{repo}/commit/{commit['sha']}",
                        timestamp=commit.get("date")
                    ))
                except json.JSONDecodeError:
                    pass

    return commits, evidence


def fetch_prs(repo: str, state: str = "open") -> tuple[List[Dict], List[EvidenceRef], int]:
    """Fetch pull requests from GitHub."""
    prs = []
    evidence = []
    count = 0

    success, output = run_gh_command([
        "pr", "list",
        "--repo", repo,
        "--state", state,
        "--json", "number,title,state,headRefName,updatedAt",
        "--limit", "20"
    ])

    if success and output:
        try:
            prs = json.loads(output)
            count = len(prs)
            for pr in prs:
                evidence.append(EvidenceRef(
                    source="github",
                    type="pr",
                    id=str(pr["number"]),
                    url=f"https://github.com/{repo}/pull/{pr['number']}",
                    timestamp=pr.get("updatedAt")
                ))
        except json.JSONDecodeError:
            pass

    return prs, evidence, count


def fetch_issues(repo: str, state: str = "open") -> tuple[int, List[EvidenceRef]]:
    """Fetch issue count from GitHub."""
    evidence = []
    count = 0

    success, output = run_gh_command([
        "issue", "list",
        "--repo", repo,
        "--state", state,
        "--json", "number",
        "--limit", "100"
    ])

    if success and output:
        try:
            issues = json.loads(output)
            count = len(issues)
            evidence.append(EvidenceRef(
                source="github",
                type="issue_count",
                id=f"{state}:{count}",
                url=f"https://github.com/{repo}/issues?q=is%3A{state}"
            ))
        except json.JSONDecodeError:
            pass

    return count, evidence


def fetch_workflows(repo: str, limit: int = 5) -> tuple[Optional[Dict], List[EvidenceRef]]:
    """Fetch latest workflow runs from GitHub."""
    evidence = []
    latest = None

    success, output = run_gh_command([
        "run", "list",
        "--repo", repo,
        "--limit", str(limit),
        "--json", "databaseId,name,status,conclusion,createdAt,headBranch"
    ])

    if success and output:
        try:
            runs = json.loads(output)
            if runs:
                latest = runs[0]
                for run in runs:
                    evidence.append(EvidenceRef(
                        source="github",
                        type="workflow",
                        id=str(run["databaseId"]),
                        url=f"https://github.com/{repo}/actions/runs/{run['databaseId']}",
                        timestamp=run.get("createdAt")
                    ))
        except json.JSONDecodeError:
            pass

    return latest, evidence


def fetch_github_truth(project_id: str, repo: str, default_branch: str = "main") -> GitHubTruth:
    """
    Fetch complete truth snapshot from GitHub.

    This is the main entry point for remote truth fetching.
    Returns a GitHubTruth object with all evidence references.
    """
    now = datetime.now(timezone.utc).isoformat()

    truth = GitHubTruth(
        project_id=project_id,
        repo=repo,
        fetched_at=now,
        default_branch=default_branch
    )

    # 1. Fetch commits
    commits, commit_evidence = fetch_commits(repo, default_branch)
    if commits:
        truth.recent_commits = commits[:5]
        truth.latest_commit = commits[0]["sha"]
        truth.latest_commit_message = commits[0]["message"].split("\n")[0][:100]
        truth.latest_commit_date = commits[0].get("date")
        truth.evidence_refs.extend([e.to_dict() for e in commit_evidence])
    else:
        truth.errors.append("Failed to fetch commits")

    # 2. Fetch PRs
    prs, pr_evidence, pr_count = fetch_prs(repo)
    truth.open_prs = pr_count
    truth.pr_titles = [pr["title"] for pr in prs[:5]]
    truth.evidence_refs.extend([e.to_dict() for e in pr_evidence])

    # 3. Fetch issues
    issue_count, issue_evidence = fetch_issues(repo)
    truth.open_issues = issue_count
    truth.evidence_refs.extend([e.to_dict() for e in issue_evidence])

    # 4. Fetch workflows
    latest_workflow, workflow_evidence = fetch_workflows(repo)
    truth.latest_workflow = latest_workflow
    truth.evidence_refs.extend([e.to_dict() for e in workflow_evidence])

    return truth


def save_github_artifacts(truth: GitHubTruth, run_dir: Path) -> List[str]:
    """
    Save GitHub truth as artifacts for evidence trail.

    Returns list of artifact paths.
    """
    artifacts = []

    github_dir = run_dir / "tool_github" / "evidence"
    github_dir.mkdir(parents=True, exist_ok=True)

    # Save full truth snapshot
    truth_file = github_dir / "github_truth.json"
    with open(truth_file, "w", encoding="utf-8") as f:
        json.dump(truth.to_dict(), f, indent=2)
    artifacts.append(str(truth_file))

    # Save commits separately
    if truth.recent_commits:
        commits_file = github_dir / "commits.json"
        with open(commits_file, "w", encoding="utf-8") as f:
            json.dump(truth.recent_commits, f, indent=2)
        artifacts.append(str(commits_file))

    # Save evidence index
    evidence_file = github_dir / "evidence_refs.json"
    with open(evidence_file, "w", encoding="utf-8") as f:
        json.dump(truth.evidence_refs, f, indent=2)
    artifacts.append(str(evidence_file))

    return artifacts


def run_github_tool(project_id: str, repo: str, run_dir: Path, default_branch: str = "main") -> dict:
    """
    Main tool entry point for BECCA orchestrator.

    Returns ARTIFACT_SPEC compliant output.
    """
    started_at = datetime.now(timezone.utc)

    # Fetch truth
    truth = fetch_github_truth(project_id, repo, default_branch)

    # Save artifacts
    artifacts = save_github_artifacts(truth, run_dir)

    completed_at = datetime.now(timezone.utc)
    duration = (completed_at - started_at).total_seconds()

    # Build output
    output = {
        "tool_id": "tool_github",
        "project_id": project_id,
        "status": "pass" if not truth.errors else "partial",
        "state": "COMPLETE",
        "evidence": [
            {"type": "json", "path": p, "description": Path(p).name}
            for p in artifacts
        ],
        "evidence_refs": truth.evidence_refs,
        "changes": {
            "files_modified": 0,
            "files_created": len(artifacts)
        },
        "summary": {
            "repo": repo,
            "latest_commit": truth.latest_commit,
            "latest_commit_message": truth.latest_commit_message,
            "open_prs": truth.open_prs,
            "open_issues": truth.open_issues,
            "ci_status": truth.latest_workflow.get("conclusion") if truth.latest_workflow else None
        },
        "timing": {
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration_seconds": duration
        },
        "errors": truth.errors
    }

    return output


# CLI for testing
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python tool_github.py <owner/repo> [branch]")
        print("Example: python tool_github.py anthropics/sonny main")
        sys.exit(1)

    repo = sys.argv[1]
    branch = sys.argv[2] if len(sys.argv) > 2 else "main"

    print(f"Fetching GitHub truth for {repo}...")
    truth = fetch_github_truth("test", repo, branch)

    print(f"\n=== GitHub Truth ===")
    print(f"Latest commit: {truth.latest_commit}")
    print(f"Message: {truth.latest_commit_message}")
    print(f"Open PRs: {truth.open_prs}")
    print(f"Open Issues: {truth.open_issues}")
    if truth.latest_workflow:
        print(f"CI: {truth.latest_workflow.get('name')} - {truth.latest_workflow.get('conclusion')}")
    print(f"\nEvidence refs: {len(truth.evidence_refs)}")
    if truth.errors:
        print(f"Errors: {truth.errors}")
