#!/usr/bin/env python3
"""
tool_scout.py - Project Scout / Launch Readiness Assessment

A scout that actually reads files, analyzes code, and produces
EVIDENCE-BASED findings with:
- Real file paths and line numbers
- Actual code snippets
- Severity ratings
- Specific fix recommendations

This is NOT a template generator. It reads real code.

Usage:
    from tools.tool_scout import run_scout

    result = run_scout(
        project_path=Path("d:/projects/trainer-os"),
        mission="100K SaaS launch readiness",
        focus_areas=["security", "scalability", "testing"]
    )
"""

import json
import re
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

from tools.evidence_contract import validate_scout_output, format_validation_result


@dataclass
class ScoutFinding:
    """A single finding from the scout."""
    file_path: str
    line_number: int
    code_snippet: str
    severity: str  # BLOCKER, HIGH, MEDIUM, LOW
    type: str  # security, scalability, testing, architecture
    title: str
    description: str
    fix_recommendation: str
    verification: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScoutReport:
    """Complete scout report with evidence."""
    project_path: str
    mission: str
    scan_started_at: str
    scan_completed_at: str
    files_scanned: int
    findings: list[ScoutFinding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


# Patterns to look for by category
SECURITY_PATTERNS = [
    # Stripe webhook without signature
    {
        "pattern": r"stripeWebhook.*onRequest.*\n(?:(?!constructEvent|verifySignature).)*const\s+event\s*=\s*req\.body",
        "title": "Stripe webhook signature not verified",
        "severity": "BLOCKER",
        "type": "security",
        "fix": "Add stripe.webhooks.constructEvent(req.rawBody, sig, webhookSecret) before processing",
        "verify": "POST fake event - should return 400"
    },
    # Allow read: if true
    {
        "pattern": r"allow\s+read:\s*if\s+true",
        "title": "Firestore rule allows public read",
        "severity": "HIGH",
        "type": "security",
        "fix": "Add authentication check: if request.auth != null",
        "verify": "Unauthenticated read should fail"
    },
    # No rate limiting
    {
        "pattern": r"onCall\s*\(\s*async\s*\(data,\s*context\)",
        "title": "Cloud Function has no rate limiting",
        "severity": "MEDIUM",
        "type": "security",
        "fix": "Add Firebase App Check or custom rate limiting middleware",
        "verify": "Rapid repeated calls should be rejected"
    },
    # Hardcoded credentials
    {
        "pattern": r"(password|secret|api_key|apikey)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "title": "Potential hardcoded credential",
        "severity": "BLOCKER",
        "type": "security",
        "fix": "Move to environment variable or secret manager",
        "verify": "Value should not appear in source code"
    },
]

SCALABILITY_PATTERNS = [
    # Double reads in security rules
    {
        "pattern": r"get\s*\(\s*/databases/\$\(database\)/documents/users/\$\(request\.auth\.uid\)",
        "title": "Security rule does extra read per operation",
        "severity": "MEDIUM",
        "type": "scalability",
        "fix": "Use custom claims in auth token instead of profile reads",
        "verify": "Check Firestore read metrics after migration"
    },
    # 1st gen Cloud Functions
    {
        "pattern": r'"firebase-functions":\s*"\^?[34]\.',
        "title": "Using 1st gen Cloud Functions",
        "severity": "MEDIUM",
        "type": "scalability",
        "fix": "Migrate to firebase-functions/v2 for better scaling",
        "verify": "Package.json shows firebase-functions/v2"
    },
    # Mock/placeholder in production code
    {
        "pattern": r"//\s*(Mock|Placeholder|TODO).*\n.*=.*`(cus_|cs_|sub_)\$\{",
        "title": "Mock ID generation in production code",
        "severity": "BLOCKER",
        "type": "scalability",
        "fix": "Replace with actual Stripe API calls",
        "verify": "Stripe dashboard shows real customer IDs"
    },
]

TESTING_PATTERNS = [
    # Empty test directory
    {
        "pattern": None,  # Special case - check directory
        "check_type": "empty_dir",
        "dir_pattern": "tests/**/*.ts",
        "title": "Test directory is empty",
        "severity": "BLOCKER",
        "type": "testing",
        "fix": "Add E2E tests for critical user journeys",
        "verify": "npm test passes with >0 tests"
    },
]


def get_line_number(content: str, match_start: int) -> int:
    """Get line number from character position."""
    return content[:match_start].count('\n') + 1


def extract_snippet(content: str, match_start: int, match_end: int, context_lines: int = 3) -> str:
    """Extract code snippet with context."""
    lines = content.split('\n')
    match_line = get_line_number(content, match_start)

    start_line = max(0, match_line - context_lines - 1)
    end_line = min(len(lines), match_line + context_lines)

    snippet_lines = []
    for i in range(start_line, end_line):
        prefix = "→ " if i == match_line - 1 else "  "
        snippet_lines.append(f"{i+1:4d}{prefix}{lines[i]}")

    return '\n'.join(snippet_lines)


def scan_file(file_path: Path, patterns: list[dict]) -> list[ScoutFinding]:
    """Scan a single file for patterns."""
    findings = []

    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return findings

    for pattern_def in patterns:
        pattern = pattern_def.get("pattern")
        if not pattern:
            continue

        try:
            for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                line_num = get_line_number(content, match.start())
                snippet = extract_snippet(content, match.start(), match.end())

                finding = ScoutFinding(
                    file_path=str(file_path),
                    line_number=line_num,
                    code_snippet=snippet,
                    severity=pattern_def["severity"],
                    type=pattern_def["type"],
                    title=pattern_def["title"],
                    description=f"Found at line {line_num}",
                    fix_recommendation=pattern_def["fix"],
                    verification=pattern_def.get("verify", "")
                )
                findings.append(finding)
        except re.error:
            continue

    return findings


def check_directory_pattern(project_path: Path, dir_pattern: str) -> bool:
    """Check if a directory pattern has files."""
    import glob
    matches = list(project_path.glob(dir_pattern))
    return len(matches) > 0


def run_scout(
    project_path: Path,
    mission: str,
    focus_areas: list[str] = None,
    evidence_dir: Path = None
) -> dict:
    """
    Run scout reconnaissance on a project.

    Args:
        project_path: Path to the project to scout
        mission: Description of the mission (e.g., "100K SaaS launch readiness")
        focus_areas: List of areas to focus on (security, scalability, testing)
        evidence_dir: Optional directory to write evidence files

    Returns:
        Tool output dict with findings and evidence paths
    """
    started_at = datetime.utcnow()
    focus_areas = focus_areas or ["security", "scalability", "testing"]

    print(f"      Scout: {project_path}")
    print(f"      Mission: {mission}")
    print(f"      Focus: {focus_areas}")

    all_findings: list[ScoutFinding] = []
    files_scanned = 0

    # Build pattern list based on focus areas
    patterns_to_scan = []
    if "security" in focus_areas:
        patterns_to_scan.extend(SECURITY_PATTERNS)
    if "scalability" in focus_areas:
        patterns_to_scan.extend(SCALABILITY_PATTERNS)

    # Scan relevant files
    scan_globs = [
        "**/*.ts",
        "**/*.tsx",
        "**/*.js",
        "**/*.jsx",
        "**/*.rules",
        "**/package.json",
        "**/firestore.rules",
    ]

    skip_dirs = ["node_modules", ".git", "dist", "build", ".next"]

    for glob_pattern in scan_globs:
        for file_path in project_path.glob(glob_pattern):
            # Skip excluded directories
            if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
                continue

            files_scanned += 1
            file_findings = scan_file(file_path, patterns_to_scan)

            # Convert absolute paths to relative
            for finding in file_findings:
                try:
                    finding.file_path = str(file_path.relative_to(project_path))
                except ValueError:
                    pass

            all_findings.extend(file_findings)

    # Check for empty test directory
    if "testing" in focus_areas:
        test_dirs = ["tests", "test", "__tests__", "spec"]
        has_tests = False

        for test_dir in test_dirs:
            test_path = project_path / test_dir
            if test_path.exists():
                test_files = list(test_path.glob("**/*.ts")) + list(test_path.glob("**/*.js"))
                if test_files:
                    has_tests = True
                    break

        if not has_tests:
            all_findings.append(ScoutFinding(
                file_path="tests/",
                line_number=0,
                code_snippet="(directory is empty or missing)",
                severity="BLOCKER",
                type="testing",
                title="No tests found",
                description="The tests directory is empty or missing. Cannot verify behavior.",
                fix_recommendation="Add E2E tests for critical user journeys: onboarding, subscription, core workflow",
                verification="npm test passes with >0 tests"
            ))

    completed_at = datetime.utcnow()

    # Build report
    report = ScoutReport(
        project_path=str(project_path),
        mission=mission,
        scan_started_at=started_at.isoformat() + "Z",
        scan_completed_at=completed_at.isoformat() + "Z",
        files_scanned=files_scanned,
        findings=all_findings
    )

    # Calculate summary
    severity_counts = {"BLOCKER": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    type_counts = {}

    for finding in all_findings:
        sev = finding.severity.upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

        ftype = finding.type
        type_counts[ftype] = type_counts.get(ftype, 0) + 1

    report.summary = {
        "total_findings": len(all_findings),
        "by_severity": severity_counts,
        "by_type": type_counts,
        "blockers": severity_counts["BLOCKER"],
        "launch_ready": severity_counts["BLOCKER"] == 0
    }

    # Calculate readiness score
    score = 100
    score -= severity_counts["BLOCKER"] * 25
    score -= severity_counts["HIGH"] * 10
    score -= severity_counts["MEDIUM"] * 5
    score -= severity_counts["LOW"] * 2
    report.summary["readiness_score"] = max(0, score)

    print(f"      Scanned: {files_scanned} files")
    print(f"      Findings: {len(all_findings)} ({severity_counts['BLOCKER']} blockers)")
    print(f"      Score: {report.summary['readiness_score']}/100")

    # Write evidence if directory provided
    evidence_paths = []
    if evidence_dir:
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Write JSON report
        json_path = evidence_dir / "SCOUT_REPORT.json"
        with open(json_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        evidence_paths.append(str(json_path))

        # Write Markdown report
        md_path = evidence_dir / "SCOUT_REPORT.md"
        md_content = generate_markdown_report(report)
        with open(md_path, "w") as f:
            f.write(md_content)
        evidence_paths.append(str(md_path))

    # Validate our own output (eat our own dogfood)
    output = {
        "status": "success" if severity_counts["BLOCKER"] == 0 else "partial",
        "evidence": evidence_paths,
        "findings": [f.to_dict() for f in all_findings],
        "stats": {
            "files_scanned": files_scanned,
            "findings_count": len(all_findings),
            "findings_by_severity": severity_counts
        },
        "summary": report.summary
    }

    # Self-validate against evidence contract
    validation = validate_scout_output(output, project_path, strict=False)
    if not validation.valid:
        print(f"      ⚠️ Evidence contract validation:")
        print(format_validation_result(validation))

    return output


def generate_markdown_report(report: ScoutReport) -> str:
    """Generate Markdown report from scout findings."""
    lines = [
        f"# Scout Report: {report.project_path}",
        f"",
        f"**Mission:** {report.mission}",
        f"**Scanned:** {report.files_scanned} files",
        f"**Time:** {report.scan_started_at} - {report.scan_completed_at}",
        f"",
        f"## Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Readiness Score | {report.summary.get('readiness_score', 0)}/100 |",
        f"| Total Findings | {report.summary.get('total_findings', 0)} |",
        f"| Blockers | {report.summary.get('blockers', 0)} |",
        f"| Launch Ready | {'✅ Yes' if report.summary.get('launch_ready') else '❌ No'} |",
        f"",
    ]

    # Group findings by severity
    by_severity = {"BLOCKER": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for finding in report.findings:
        sev = finding.severity.upper()
        if sev in by_severity:
            by_severity[sev].append(finding)

    # Output findings by severity
    severity_icons = {"BLOCKER": "🚨", "HIGH": "⚠️", "MEDIUM": "📝", "LOW": "💡"}

    for severity in ["BLOCKER", "HIGH", "MEDIUM", "LOW"]:
        findings = by_severity[severity]
        if not findings:
            continue

        icon = severity_icons[severity]
        lines.append(f"## {icon} {severity} ({len(findings)})")
        lines.append("")

        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. {f.title}")
            lines.append(f"")
            lines.append(f"**File:** `{f.file_path}:{f.line_number}`")
            lines.append(f"**Type:** {f.type}")
            lines.append(f"")
            lines.append(f"```")
            lines.append(f"{f.code_snippet}")
            lines.append(f"```")
            lines.append(f"")
            lines.append(f"**Fix:** {f.fix_recommendation}")
            if f.verification:
                lines.append(f"")
                lines.append(f"**Verify:** {f.verification}")
            lines.append(f"")

    return "\n".join(lines)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scout - Project Reconnaissance")
    parser.add_argument("--project", required=True, help="Path to project")
    parser.add_argument("--mission", default="Launch readiness assessment", help="Mission description")
    parser.add_argument("--focus", nargs="+", default=["security", "scalability", "testing"],
                        help="Focus areas")
    parser.add_argument("--output", help="Output directory for evidence")

    args = parser.parse_args()

    result = run_scout(
        project_path=Path(args.project),
        mission=args.mission,
        focus_areas=args.focus,
        evidence_dir=Path(args.output) if args.output else None
    )

    print(f"\nResult: {result['status']}")
    print(f"Findings: {len(result['findings'])}")
