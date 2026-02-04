#!/usr/bin/env python3
"""
becca_audit.py - BECCA PR Audit Script

Runs secrets and profit guardrails scans for CI.
Outputs results to RUN_SUMMARY.json and FINAL_REPORT.md
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def main():
    run_id = os.environ.get('RUN_ID', 'RUN-LOCAL')
    run_dir = Path(os.environ.get('RUN_DIR', '.becca/runs/local'))
    profile = os.environ.get('BECCA_PROFILE', 'fast')

    run_dir.mkdir(parents=True, exist_ok=True)

    results = {
        'run_id': run_id,
        'profile': profile,
        'status': 'ALL_CLEAR',
        'proposals': [],
        'total_findings': 0,
        'critical_count': 0,
        'high_count': 0,
        'medium_count': 0,
        'low_count': 0,
        'secrets_findings': 0,
        'cost_findings': 0,
        'profit_grade': 'A',
        'profit_score': 0,
        'monthly_risk': '$0',
        'touches_critical_paths': False,
        'top_risks': [],
    }

    # Check critical paths
    try:
        with open('governance/specs/CRITICAL_PATHS.json') as f:
            cp_config = json.load(f)
            critical_patterns = []
            for cp in cp_config.get('critical_paths', []):
                critical_patterns.extend(cp.get('patterns', []))

        diff_result = subprocess.run(
            ['git', 'diff', '--name-only', 'origin/main...HEAD'],
            capture_output=True, text=True, timeout=30
        )
        changed_files = diff_result.stdout.strip().split('\n') if diff_result.stdout.strip() else []

        for f in changed_files:
            for pattern in critical_patterns:
                regex = pattern.replace('**/', '.*').replace('*', '[^/]*')
                if re.match(regex, f):
                    results['touches_critical_paths'] = True
                    break
    except Exception as e:
        print(f"Critical paths check: {e}")

    # Run secrets scan
    print("Running secrets scan...")
    try:
        from tools.propose_secrets_remediation import SecretsRemediationProposer

        secrets_proposer = SecretsRemediationProposer(
            project_path=Path('.'),
            run_dir=run_dir,
            plan_id=f'PLAN-{run_id}',
            task_id='T001-SECRETS'
        )
        secrets_result = secrets_proposer.run()

        if secrets_proposer.findings:
            for f in secrets_proposer.findings:
                if f.severity == 'critical':
                    results['critical_count'] += 1
                    results['top_risks'].append(f'CRITICAL: {f.secret_type} in {f.file_path}:{f.line_number}')
                elif f.severity == 'high':
                    results['high_count'] += 1
                    if len(results['top_risks']) < 3:
                        results['top_risks'].append(f'HIGH: {f.secret_type} in {f.file_path}')
                elif f.severity == 'medium':
                    results['medium_count'] += 1
                else:
                    results['low_count'] += 1

            results['secrets_findings'] = len(secrets_proposer.findings)
            results['total_findings'] += len(secrets_proposer.findings)
            print(f"  Found {len(secrets_proposer.findings)} secret(s)")
    except Exception as e:
        print(f"  Secrets scan error: {e}")

    # Run profit guardrails scan
    print("Running profit guardrails scan...")
    try:
        from tools.propose_profit_guardrails import ProfitGuardrailsProposer

        profit_proposer = ProfitGuardrailsProposer(
            project_path=Path('.'),
            run_dir=run_dir,
            plan_id=f'PLAN-{run_id}',
            task_id='T002-PROFIT'
        )
        profit_result = profit_proposer.run()
        risk_score = profit_proposer._calculate_risk_score()

        results['profit_grade'] = risk_score.get('grade', 'A')
        results['profit_score'] = risk_score.get('score', 0)
        results['monthly_risk'] = risk_score.get('monthly_risk', '$0')

        unprotected = [f for f in profit_proposer.findings if not f.has_quota_check]
        if unprotected:
            results['cost_findings'] = len(unprotected)
            results['total_findings'] += len(unprotected)
            print(f"  Found {len(unprotected)} unprotected cost vector(s)")
    except Exception as e:
        print(f"  Profit scan error: {e}")

    # Determine status
    if results['critical_count'] > 0:
        results['status'] = 'CRITICAL_FINDINGS'
    elif results['high_count'] > 0:
        results['status'] = 'NEEDS_REVIEW'
    elif results['total_findings'] > 0:
        results['status'] = 'OK_WITH_WARNINGS'
    else:
        results['status'] = 'ALL_CLEAR'

    results['top_risks'] = results['top_risks'][:3]

    # Write summary
    summary_path = run_dir / 'RUN_SUMMARY.json'
    with open(summary_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Wrote {summary_path}")

    # Generate report
    status_emoji = {
        'ALL_CLEAR': '✅',
        'OK_WITH_WARNINGS': '⚠️',
        'NEEDS_REVIEW': '🔶',
        'CRITICAL_FINDINGS': '🔴'
    }
    grade_emoji = {'A': '🟢', 'B': '🟡', 'C': '🟠', 'D': '🔶', 'F': '🔴'}

    report_lines = [
        f'## {status_emoji.get(results["status"], "❓")} BECCA: {results["status"].replace("_", " ")}',
        '',
        '| Metric | Value |',
        '|--------|-------|',
        f'| **Profit Risk** | {grade_emoji.get(results["profit_grade"], "⚪")} Grade {results["profit_grade"]} ({results["monthly_risk"]}) |',
        f'| **Critical** | {results["critical_count"]} |',
        f'| **High** | {results["high_count"]} |',
        f'| **Critical Paths?** | {"Yes ⚠️" if results["touches_critical_paths"] else "No"} |',
        '',
    ]

    if results['top_risks']:
        report_lines.extend(['### Top Risks', ''])
        for risk in results['top_risks']:
            report_lines.append(f'- {risk}')
        report_lines.append('')

    report_lines.extend([
        f'---',
        f'Run: `{run_id}`',
    ])

    report_path = run_dir / 'FINAL_REPORT.md'
    with open(report_path, 'w') as f:
        f.write('\n'.join(report_lines))
    print(f"Wrote {report_path}")

    # Set GitHub outputs if running in CI
    github_output = os.environ.get('GITHUB_OUTPUT')
    if github_output:
        with open(github_output, 'a') as f:
            f.write(f'status={results["status"]}\n')
            f.write(f'profit_grade={results["profit_grade"]}\n')
            f.write(f'total_findings={results["total_findings"]}\n')
            f.write(f'critical_count={results["critical_count"]}\n')
            f.write(f'has_secrets={"true" if results["secrets_findings"] > 0 else "false"}\n')
            f.write(f'has_cost_risk={"true" if results["profit_grade"] in ["D", "F"] else "false"}\n')
            f.write(f'touches_critical={"true" if results["touches_critical_paths"] else "false"}\n')

    # Exit with error if critical findings
    if results['critical_count'] > 0:
        print(f"::warning::Found {results['critical_count']} CRITICAL findings!")
        sys.exit(1)

    print(f"Audit complete: {results['status']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
