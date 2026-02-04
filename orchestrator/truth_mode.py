#!/usr/bin/env python3
"""
truth_mode.py - Anti-Hallucination Response Formatter

The core module that enforces BECCA's "scientist, not storyteller" principle.
Every response must be structured with:
  - CLAIMS: Factual statements backed by evidence
  - EVIDENCE: Traceable references to data sources
  - UNKNOWN: What can't be verified yet
  - NEXT ACTION: Smallest action to gather more evidence

This module provides:
  1. TruthModeResponse dataclass
  2. Evidence collection and formatting
  3. Response validation (no claims without evidence)
  4. Markdown/JSON output formatters
"""

import json
import re
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from pathlib import Path


@dataclass
class Evidence:
    """A single piece of traceable evidence."""
    id: str                 # E1, E2, etc.
    source: str             # "github", "bridge", "local", "ledger"
    type: str               # "commit", "pr", "file", "command", "workflow"
    description: str        # Human-readable description
    url: Optional[str] = None
    timestamp: Optional[str] = None
    raw_data: Optional[Dict] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        if d.get("raw_data") is None:
            del d["raw_data"]
        return d

    def format_line(self) -> str:
        """Format as a single evidence line."""
        if self.url:
            return f"[{self.id}] {self.source}: {self.description} ([link]({self.url}))"
        return f"[{self.id}] {self.source}: {self.description}"


@dataclass
class TruthModeResponse:
    """
    A response that follows the Truth Mode anti-hallucination contract.

    Rules:
    1. Every claim must have at least one evidence reference
    2. Unknown data must be explicitly listed
    3. No numeric progress without evidence
    4. Always include next action
    """
    claims: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    unknown: List[str] = field(default_factory=list)
    next_action: str = "Collect more evidence"

    # Metadata
    project_id: Optional[str] = None
    run_id: Optional[str] = None
    generated_at: Optional[str] = None
    sources_used: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def add_claim(self, claim: str, evidence_ids: List[str] = None):
        """Add a claim with optional evidence references."""
        self.claims.append(claim)
        # Note: In strict mode, we'd validate that evidence_ids exist

    def add_evidence(self, source: str, type: str, description: str,
                     url: str = None, timestamp: str = None, raw_data: dict = None) -> str:
        """Add evidence and return its ID."""
        ev_id = f"E{len(self.evidence) + 1}"
        self.evidence.append(Evidence(
            id=ev_id,
            source=source,
            type=type,
            description=description,
            url=url,
            timestamp=timestamp,
            raw_data=raw_data
        ))
        if source not in self.sources_used:
            self.sources_used.append(source)
        return ev_id

    def add_unknown(self, item: str):
        """Add something that couldn't be verified."""
        self.unknown.append(item)

    def set_next_action(self, action: str):
        """Set the recommended next action."""
        self.next_action = action

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)

    @property
    def is_grounded(self) -> bool:
        """Check if response has at least some evidence."""
        return len(self.evidence) > 0

    def to_markdown(self) -> str:
        """Format as Truth Mode markdown."""
        lines = []

        # Header with evidence count
        lines.append(f"*Evidence Count: {self.evidence_count}*")
        lines.append("")

        # CLAIMS
        lines.append("## CLAIMS")
        if self.claims:
            for claim in self.claims:
                lines.append(f"- {claim}")
        else:
            lines.append("- (no verified claims available)")
        lines.append("")

        # EVIDENCE
        lines.append("## EVIDENCE")
        if self.evidence:
            for ev in self.evidence:
                lines.append(f"- {ev.format_line()}")
        else:
            lines.append("- (no evidence collected yet)")
        lines.append("")

        # UNKNOWN
        lines.append("## UNKNOWN")
        if self.unknown:
            for item in self.unknown:
                lines.append(f"- {item}")
        else:
            lines.append("- (nothing unknown at this time)")
        lines.append("")

        # NEXT ACTION
        lines.append("## NEXT ACTION")
        lines.append(f"- {self.next_action}")
        lines.append("")

        return "\n".join(lines)

    def to_chat_response(self) -> str:
        """Format for chat display (concise version)."""
        lines = []

        # Summary line
        if self.claims:
            lines.append(f"**{len(self.claims)} verified claims** (backed by {self.evidence_count} evidence items)")
        else:
            lines.append("**No verified claims** - need to collect evidence first")
        lines.append("")

        # Claims
        if self.claims:
            for claim in self.claims[:5]:  # Limit display
                lines.append(f"- {claim}")
            if len(self.claims) > 5:
                lines.append(f"- ... and {len(self.claims) - 5} more")
        lines.append("")

        # Unknown (if any)
        if self.unknown:
            lines.append(f"**Unknown:** {', '.join(self.unknown[:3])}")
            lines.append("")

        # Next action
        lines.append(f"**Next:** {self.next_action}")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "claims": self.claims,
            "evidence": [e.to_dict() for e in self.evidence],
            "unknown": self.unknown,
            "next_action": self.next_action,
            "project_id": self.project_id,
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "sources_used": self.sources_used,
            "evidence_count": self.evidence_count,
            "is_grounded": self.is_grounded
        }


class TruthModeValidator:
    """
    Validates responses against Truth Mode rules.

    HARD ENFORCEMENT: No claims without evidence. Period.
    """

    # Patterns that suggest fake progress (REJECTED)
    FAKE_PROGRESS_PATTERNS = [
        r'\b\d{1,3}%\s*(complete|done|finished|ready)',
        r'\b(almost|nearly|virtually|roughly|about)\s+(done|complete|finished)',
        r'\b(should be|will be|estimated|probably)\s+\d+\s*(hours|days|weeks)',
        r'\b(making good progress|going well|on track|ahead of schedule)',
        r'\b(i think|i believe|probably|likely|seems like)\s+\d+',
        r'\b(around|approximately|roughly)\s+\d+\s*(percent|%|files|items|tasks)',
    ]

    # Patterns that require numeric evidence
    NUMERIC_CLAIM_PATTERNS = [
        r'\b(\d+)\s*(PRs?|pull requests?|issues?|commits?|errors?|warnings?|files?)',
        r'\b(\d+)\s*(open|closed|merged|pending)',
    ]

    @classmethod
    def validate(cls, response: TruthModeResponse) -> List[str]:
        """
        Validate a response against Truth Mode rules.

        HARD RULES (violations = response rejected):
        1. Claims without evidence = REJECTED
        2. Fake progress patterns = REJECTED
        3. Numeric claims without numeric evidence = REJECTED
        4. No next action = REJECTED

        Returns list of violations (empty if valid).
        """
        violations = []

        # HARD RULE 1: Claims without evidence
        if response.claims and not response.evidence:
            violations.append("HARD VIOLATION: Claims made without any evidence. Move to UNKNOWN.")

        # HARD RULE 2: Check for fake progress patterns in claims
        for claim in response.claims:
            for pattern in cls.FAKE_PROGRESS_PATTERNS:
                if re.search(pattern, claim, re.IGNORECASE):
                    violations.append(f"HARD VIOLATION: Fake progress detected: '{claim[:50]}...'")

        # HARD RULE 3: Numeric claims must have evidence with matching numbers
        for claim in response.claims:
            for pattern in cls.NUMERIC_CLAIM_PATTERNS:
                match = re.search(pattern, claim, re.IGNORECASE)
                if match:
                    number = match.group(1)
                    # Check if any evidence contains this number
                    evidence_text = " ".join(e.description for e in response.evidence)
                    if number not in evidence_text:
                        violations.append(f"HARD VIOLATION: Numeric claim '{number}' has no matching evidence")

        # HARD RULE 4: Must have next action
        if not response.next_action or response.next_action.strip() == "":
            violations.append("HARD VIOLATION: No next action specified")

        # HARD RULE 5: If evidence is empty, claims must be empty
        if not response.evidence and response.claims:
            violations.append("HARD VIOLATION: Evidence is empty but claims exist. Use UNKNOWN instead.")

        return violations

    @classmethod
    def enforce(cls, response: TruthModeResponse) -> TruthModeResponse:
        """
        Enforce Truth Mode by moving invalid claims to UNKNOWN.

        This is the "hard guard" - it won't let bad data through.
        """
        violations = cls.validate(response)

        if not violations:
            return response

        # Create a corrected response
        corrected = TruthModeResponse(
            project_id=response.project_id,
            run_id=response.run_id,
            sources_used=response.sources_used
        )

        # Keep valid evidence
        corrected.evidence = response.evidence.copy() if response.evidence else []

        # If no evidence, ALL claims become unknown
        if not response.evidence:
            for claim in response.claims:
                corrected.add_unknown(f"Unverified: {claim}")
            corrected.set_next_action("Collect evidence before making claims")
        else:
            # Check each claim individually
            for claim in response.claims:
                is_valid = True

                # Check fake progress
                for pattern in cls.FAKE_PROGRESS_PATTERNS:
                    if re.search(pattern, claim, re.IGNORECASE):
                        corrected.add_unknown(f"Rejected (fake progress): {claim}")
                        is_valid = False
                        break

                # Check numeric claims have evidence
                if is_valid:
                    for pattern in cls.NUMERIC_CLAIM_PATTERNS:
                        match = re.search(pattern, claim, re.IGNORECASE)
                        if match:
                            number = match.group(1)
                            evidence_text = " ".join(e.description for e in response.evidence)
                            if number not in evidence_text:
                                corrected.add_unknown(f"Unverified (no evidence for '{number}'): {claim}")
                                is_valid = False
                                break

                if is_valid:
                    corrected.add_claim(claim)

        # Keep unknown items
        for item in response.unknown:
            corrected.add_unknown(item)

        # Set next action
        if response.next_action:
            corrected.set_next_action(response.next_action)
        else:
            corrected.set_next_action("Collect more evidence")

        return corrected


def build_status_response(project_id: str, github_data: dict = None,
                          bridge_data: dict = None) -> TruthModeResponse:
    """
    Build a Truth Mode response for a project status query.

    This is the main entry point for "What's the update on X?" queries.
    """
    response = TruthModeResponse(project_id=project_id)

    # Process GitHub data
    if github_data:
        # Latest commit
        if github_data.get("latest_commit"):
            ev_id = response.add_evidence(
                source="github",
                type="commit",
                description=f"commit {github_data['latest_commit'][:7]} at {github_data.get('latest_commit_date', 'unknown')}",
                url=f"https://github.com/{github_data.get('repo')}/commit/{github_data['latest_commit']}",
                timestamp=github_data.get("latest_commit_date")
            )
            msg = github_data.get('latest_commit_message', 'N/A')[:60]
            response.add_claim(f"Latest commit: {github_data['latest_commit'][:7]} - \"{msg}\"")

        # Open PRs
        if github_data.get("open_prs") is not None:
            ev_id = response.add_evidence(
                source="github",
                type="pr_count",
                description=f"{github_data['open_prs']} open PRs",
                url=f"https://github.com/{github_data.get('repo')}/pulls"
            )
            response.add_claim(f"{github_data['open_prs']} open pull requests")

        # Open issues
        if github_data.get("open_issues") is not None:
            ev_id = response.add_evidence(
                source="github",
                type="issue_count",
                description=f"{github_data['open_issues']} open issues",
                url=f"https://github.com/{github_data.get('repo')}/issues"
            )
            response.add_claim(f"{github_data['open_issues']} open issues")

        # CI status
        if github_data.get("latest_workflow"):
            wf = github_data["latest_workflow"]
            ev_id = response.add_evidence(
                source="github",
                type="workflow",
                description=f"workflow '{wf.get('name', 'CI')}' - {wf.get('conclusion', wf.get('status', 'unknown'))}",
                url=f"https://github.com/{github_data.get('repo')}/actions/runs/{wf.get('databaseId')}"
            )
            response.add_claim(f"CI status: {wf.get('conclusion', wf.get('status', 'unknown'))}")
    else:
        response.add_unknown("GitHub state not available (API not configured or offline)")

    # Process bridge data
    if bridge_data:
        if bridge_data.get("connected"):
            # Git status
            if bridge_data.get("git_dirty") is not None:
                status = "has uncommitted changes" if bridge_data["git_dirty"] else "clean"
                ev_id = response.add_evidence(
                    source="bridge",
                    type="git_status",
                    description=f"working directory {status}",
                    timestamp=bridge_data.get("timestamp")
                )
                response.add_claim(f"Local working directory is {status}")

            # Test results
            if bridge_data.get("last_test_run"):
                test = bridge_data["last_test_run"]
                ev_id = response.add_evidence(
                    source="bridge",
                    type="test_run",
                    description=f"{test.get('command', 'tests')}: {test.get('status', 'unknown')}",
                    timestamp=test.get("timestamp")
                )
                response.add_claim(f"Last test run: {test.get('status', 'unknown')}")
    else:
        response.add_unknown("Local bridge not connected (development machine may be offline)")

    # Set next action based on what's missing
    if not response.evidence:
        response.set_next_action("Run `gh auth login` to enable GitHub API, or start local bridge")
    elif response.unknown:
        if "GitHub" in str(response.unknown):
            response.set_next_action("Configure GitHub CLI: `gh auth login`")
        else:
            response.set_next_action("Start local bridge: `python bridge/becca_bridge.py`")
    else:
        response.set_next_action("All evidence sources connected. Run specific analysis if needed.")

    return response


# CLI for testing
if __name__ == "__main__":
    print("=== Truth Mode Test ===\n")

    # Create a response with some evidence
    response = TruthModeResponse(project_id="sonny")

    response.add_evidence(
        source="github",
        type="commit",
        description="commit abc1234 at 2026-02-03",
        url="https://github.com/test/sonny/commit/abc1234"
    )
    response.add_claim("Latest commit is abc1234: 'Fix login bug'")

    response.add_evidence(
        source="github",
        type="pr_count",
        description="3 open PRs"
    )
    response.add_claim("3 open pull requests")

    response.add_unknown("Local bridge not connected")
    response.set_next_action("Start local bridge to get development status")

    # Validate
    violations = TruthModeValidator.validate(response)
    if violations:
        print("VIOLATIONS:")
        for v in violations:
            print(f"  - {v}")
    else:
        print("No violations - response is valid\n")

    # Print formatted output
    print(response.to_markdown())

    # Test with fake progress (should fail validation)
    print("\n=== Testing Fake Progress Detection ===\n")
    bad_response = TruthModeResponse(project_id="test")
    bad_response.add_claim("We're about 80% complete on this feature")
    bad_response.add_claim("Should be done in 2-3 days")

    violations = TruthModeValidator.validate(bad_response)
    print(f"Violations found: {len(violations)}")
    for v in violations:
        print(f"  - {v}")
