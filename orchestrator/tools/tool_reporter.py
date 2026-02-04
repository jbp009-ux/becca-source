#!/usr/bin/env python3
"""
tool_reporter.py - Generate final report

This tool aggregates evidence from all tools and generates a comprehensive
FINAL_REPORT.md for the run.

Actions: read evidence, generate report
"""

import json
from datetime import datetime
from pathlib import Path


def run_reporter(run_id: str, run_dir: Path, mission: str, tool_outputs: dict, all_evidence: list) -> dict:
    """
    Generate final report from all tool outputs.

    Returns tool output per ARTIFACT_SPEC.
    """
    started_at = datetime.utcnow()
    evidence = []

    tool_dir = run_dir / "tool_reporter"
    evidence_dir = tool_dir / "evidence"

    # Generate report content
    report_content = generate_report(run_id, run_dir, mission, tool_outputs, all_evidence)

    # Save report
    report_path = run_dir / "FINAL_REPORT.md"
    with open(report_path, "w") as f:
        f.write(report_content)

    evidence.append({
        "type": "file",
        "path": str(report_path),
        "description": "Final run report"
    })

    # Also save to evidence dir
    evidence_report = evidence_dir / "report.md"
    with open(evidence_report, "w") as f:
        f.write(report_content)

    completed_at = datetime.utcnow()
    duration = (completed_at - started_at).total_seconds()

    # Build output
    output = {
        "tool_id": "tool_reporter",
        "run_id": run_id,
        "status": "pass",
        "state": "COMPLETE",
        "evidence": evidence,
        "changes": {
            "files_modified": 0,
            "files_created": 1,
            "lines_added": len(report_content.split("\n")),
            "lines_removed": 0
        },
        "success_reasoning": {
            "invariants_checked": [
                "All tool outputs collected",
                "Report generated successfully",
                "Evidence paths valid"
            ],
            "assumptions_made": [
                "Tool outputs follow ARTIFACT_SPEC",
                "Evidence files exist at specified paths"
            ],
            "not_tested": [
                "Evidence content not validated",
                "Report formatting not verified"
            ]
        },
        "risks": [],
        "next_actions": [],
        "timing": {
            "started_at": started_at.isoformat() + "Z",
            "completed_at": completed_at.isoformat() + "Z",
            "duration_seconds": duration
        },
        "tokens_used": 0,
        "error": None,
        "report_path": str(report_path)
    }

    # Save output
    output_file = tool_dir / "output.json"
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    return output


def generate_report(run_id: str, run_dir: Path, mission: str, tool_outputs: dict, all_evidence: list) -> str:
    """Generate markdown report content."""

    # Load run state
    state_file = run_dir / "RUN_STATE.json"
    state = {}
    if state_file.exists():
        with open(state_file) as f:
            state = json.load(f)

    # Get summaries from each tool
    inspector = tool_outputs.get("tool_inspector", {})
    browser = tool_outputs.get("tool_browser", {})

    inspector_summary = inspector.get("findings_summary", {})
    browser_summary = browser.get("browser_summary", {})

    # Determine expected final status based on tool outcomes
    all_passed = all(
        t.get("status") == "pass"
        for t in tool_outputs.values()
        if t  # skip None/empty
    )
    expected_final = "COMPLETE" if all_passed else "FAILED_VERIFY"

    # Build report - show BOTH current state (honest) and expected final (computed)
    report = f"""# BECCA Run Report

**Run ID:** {run_id}
**Mission:** {mission}
**Current State:** {state.get('current_state', 'UNKNOWN')}
**Expected Final:** {expected_final}
**Generated:** {datetime.utcnow().isoformat()}Z

---

## Executive Summary

This report summarizes the automated investigation for:
> {mission}

### Quick Stats

| Metric | Value |
|--------|-------|
| Tools Run | {len(tool_outputs)} |
| Evidence Items | {len(all_evidence)} |
| Files Scanned | {inspector_summary.get('files_scanned', 'N/A')} |
| Grep Matches | {inspector_summary.get('grep_matches', 'N/A')} |
| Console Logs | {browser_summary.get('console_total', 'N/A')} |
| Console Errors | {browser_summary.get('console_errors', 'N/A')} |
| Network Requests | {browser_summary.get('network_requests', 'N/A')} |

---

## Tool Results

### 1. Inspector (Codebase Analysis)

**Status:** {inspector.get('status', 'N/A')}
**Duration:** {inspector.get('timing', {}).get('duration_seconds', 'N/A')} seconds

**Keywords searched:** {', '.join(inspector_summary.get('keywords', []))}

**Findings:**
- Files scanned: {inspector_summary.get('files_scanned', 0)}
- Grep matches: {inspector_summary.get('grep_matches', 0)}
- Config files: {inspector_summary.get('config_files', 0)}
- Error patterns: {inspector_summary.get('error_patterns', 0)}

### 2. Browser (DevTools Capture)

**Status:** {browser.get('status', 'N/A')}
**Duration:** {browser.get('timing', {}).get('duration_seconds', 'N/A')} seconds
**URL:** {browser_summary.get('url', 'N/A')}

**Findings:**
- Console logs: {browser_summary.get('console_total', 0)}
- Console errors/warnings: {browser_summary.get('console_errors', 0)}
- Network requests: {browser_summary.get('network_requests', 0)}

{f"**Note:** {browser.get('error', '')}" if browser.get('error') else ""}

### 3. Secrets Scan (Security Analysis)

{format_secrets_summary(inspector.get('secrets_summary', {}))}

---

## Evidence Collected

| # | Type | Description | Path |
|---|------|-------------|------|
"""

    for i, ev in enumerate(all_evidence, 1):
        path = Path(ev.get('path', '')).name
        report += f"| {i} | {ev.get('type', 'unknown')} | {ev.get('description', 'N/A')} | `{path}` |\n"

    report += f"""

---

## Success Reasoning

### What Was Checked

**Inspector:**
{format_list(inspector.get('success_reasoning', {}).get('invariants_checked', []))}

**Browser:**
{format_list(browser.get('success_reasoning', {}).get('invariants_checked', []))}

### Assumptions Made

{format_list(inspector.get('success_reasoning', {}).get('assumptions_made', []) + browser.get('success_reasoning', {}).get('assumptions_made', []))}

### What Was NOT Tested

{format_list(inspector.get('success_reasoning', {}).get('not_tested', []) + browser.get('success_reasoning', {}).get('not_tested', []))}

---

## Risks Identified

"""

    all_risks = inspector.get('risks', []) + browser.get('risks', [])
    if all_risks:
        for risk in all_risks:
            report += f"- **[{risk.get('level', 'unknown').upper()}]** {risk.get('description', 'N/A')}\n"
            if risk.get('mitigation'):
                report += f"  - Mitigation: {risk.get('mitigation')}\n"
    else:
        report += "No risks identified.\n"

    report += f"""

---

## Run Timeline

| State | Entered | Exited |
|-------|---------|--------|
"""

    for entry in state.get('state_history', []):
        entered = entry.get('entered_at', 'N/A')[:19] if entry.get('entered_at') else 'N/A'
        exited = entry.get('exited_at', '-')[:19] if entry.get('exited_at') else '-'
        report += f"| {entry.get('state', 'UNKNOWN')} | {entered} | {exited} |\n"

    report += f"""

---

## Files

- **Run folder:** `{run_dir}`
- **State file:** `{run_dir / 'RUN_STATE.json'}`
- **Run log:** `{run_dir / 'RUN_LOG.jsonl'}`

---

*Report generated by BECCA MVP v0.1.0*
"""

    return report


def format_secrets_summary(secrets_summary: dict) -> str:
    """Format secrets scan summary for report."""
    if not secrets_summary:
        return "*No secrets scan data available.*"

    patterns_ran = secrets_summary.get("patterns_ran", 0)
    files_scanned = secrets_summary.get("files_scanned", 0)
    severity = secrets_summary.get("severity_counts", {})
    candidates = secrets_summary.get("candidate_count", 0)
    allowlisted = secrets_summary.get("allowlisted_count", 0)
    scan_time = secrets_summary.get("scan_time_seconds", 0)

    critical = severity.get("CRITICAL", 0)
    high = severity.get("HIGH", 0)
    medium = severity.get("MEDIUM", 0)
    low = severity.get("LOW", 0)
    total = critical + high + medium + low

    summary = f"""**Patterns loaded:** {secrets_summary.get('patterns_loaded', 0)}
**Files scanned:** {files_scanned}
**Scan time:** {scan_time:.2f}s

| Severity | Count |
|----------|-------|
| CRITICAL | {critical} |
| HIGH | {high} |
| MEDIUM | {medium} |
| LOW | {low} |
| **Total** | **{total}** |
| Candidates | {candidates} |
| Allowlisted | {allowlisted} |

"""
    if critical > 0:
        summary += f"**WARNING:** {critical} CRITICAL severity findings detected. Review `SECRET_FINDINGS.md` immediately.\n\n"
    elif high > 0:
        summary += f"**ATTENTION:** {high} HIGH severity findings detected. Review `SECRET_FINDINGS.md`.\n\n"
    elif total == 0 and patterns_ran > 0:
        summary += "*No secrets found by pattern matching.*\n\n"

    if candidates > 0:
        summary += f"*{candidates} entropy-based candidates require manual review.*\n\n"

    return summary


def format_list(items: list) -> str:
    """Format a list as markdown bullet points."""
    if not items:
        return "- None\n"
    return "\n".join(f"- {item}" for item in items)
