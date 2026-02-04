#!/usr/bin/env python3
"""
evidence_contract.py - Evidence Output Contract Validator

Ensures scout/inspection outputs contain REAL EVIDENCE, not templates.

Every finding MUST include:
1. file_path: Actual path to the file (not placeholder)
2. line_number: Specific line (if applicable)
3. code_snippet: Actual code showing the issue
4. severity: BLOCKER | HIGH | MEDIUM | LOW
5. fix_recommendation: Specific fix, not generic advice
6. verification: How to verify the fix worked

Rejects:
- Placeholder paths like "/project/root" or "path/to/file"
- Missing code snippets
- Generic recommendations like "fix this issue"
- Template outputs with no real file references
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


@dataclass
class EvidenceValidationResult:
    """Result of evidence contract validation."""
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    score: int = 0  # 0-100, where 100 is fully compliant


# Placeholder patterns that indicate fake/template evidence
PLACEHOLDER_PATTERNS = [
    r"^/project/root",
    r"^path/to/",
    r"^\.\.\./",
    r"^<.*>$",  # <file_path>
    r"^\[.*\]$",  # [file_path]
    r"^your[_-]?project",
    r"^example[_-]?",
    r"^sample[_-]?",
    r"^todo[_-]?",
    r"^placeholder",
]

# Generic recommendation patterns that indicate template output
GENERIC_RECOMMENDATION_PATTERNS = [
    r"^fix this",
    r"^update this",
    r"^change this",
    r"^modify as needed",
    r"^implement.*appropriate",
    r"^add.*necessary",
    r"^TODO",
    r"^\.\.\.$",
]


def is_placeholder_path(path: str) -> bool:
    """Check if a path is a placeholder/template."""
    if not path:
        return True

    path_lower = path.lower().strip()

    for pattern in PLACEHOLDER_PATTERNS:
        if re.match(pattern, path_lower, re.IGNORECASE):
            return True

    return False


def is_generic_recommendation(text: str) -> bool:
    """Check if a recommendation is too generic."""
    if not text:
        return True

    text_lower = text.lower().strip()

    # Too short is usually generic
    if len(text_lower) < 20:
        return True

    for pattern in GENERIC_RECOMMENDATION_PATTERNS:
        if re.match(pattern, text_lower, re.IGNORECASE):
            return True

    return False


def validate_finding(finding: dict, project_path: Path = None) -> tuple[bool, list[str]]:
    """
    Validate a single finding against the evidence contract.

    Returns (valid, errors)
    """
    errors = []

    # 1. Must have file_path
    file_path = finding.get("file_path") or finding.get("path") or finding.get("file")
    if not file_path:
        errors.append("MISSING: file_path")
    elif is_placeholder_path(file_path):
        errors.append(f"PLACEHOLDER_PATH: '{file_path}' is not a real file path")
    elif project_path:
        # Verify file actually exists
        full_path = project_path / file_path
        if not full_path.exists() and not Path(file_path).exists():
            errors.append(f"FILE_NOT_FOUND: '{file_path}' does not exist")

    # 2. Should have line_number (warning if missing, not error)
    line_num = finding.get("line_number") or finding.get("line") or finding.get("start_line")
    if not line_num and finding.get("type") != "schema":  # Schema findings may not have line numbers
        errors.append("MISSING: line_number (required for code findings)")

    # 3. Must have code_snippet for code-related findings
    snippet = finding.get("code_snippet") or finding.get("snippet") or finding.get("context") or finding.get("evidence")
    finding_type = finding.get("type", "code")
    if finding_type in ["code", "security", "rule", "function"] and not snippet:
        errors.append("MISSING: code_snippet (required for code findings)")

    # 4. Must have severity
    severity = finding.get("severity")
    valid_severities = ["BLOCKER", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if not severity:
        errors.append("MISSING: severity")
    elif severity.upper() not in valid_severities:
        errors.append(f"INVALID_SEVERITY: '{severity}' not in {valid_severities}")

    # 5. Should have fix_recommendation (warning if generic)
    recommendation = finding.get("fix_recommendation") or finding.get("recommendation") or finding.get("fix")
    if not recommendation:
        errors.append("MISSING: fix_recommendation")
    elif is_generic_recommendation(recommendation):
        errors.append(f"GENERIC_RECOMMENDATION: '{recommendation[:50]}...' is too vague")

    return len(errors) == 0, errors


def validate_scout_output(output: dict, project_path: Path = None, strict: bool = True) -> EvidenceValidationResult:
    """
    Validate an entire scout/inspection output against the evidence contract.

    Args:
        output: The tool output dict with findings
        project_path: Optional project path for file existence checks
        strict: If True, any error fails validation. If False, warnings only.

    Returns:
        EvidenceValidationResult with validity, errors, warnings, and score
    """
    result = EvidenceValidationResult(valid=True)

    findings = output.get("findings", [])

    # Must have at least one finding for a scout mission
    if not findings:
        # Check if this was intentional (no issues found)
        if output.get("status") == "success" and output.get("no_issues_found"):
            result.warnings.append("NO_FINDINGS: Scout found no issues (verify this is correct)")
        else:
            result.errors.append("NO_FINDINGS: Scout output has no findings - likely template output")
            result.valid = False
            result.score = 0
            return result

    # Validate each finding
    valid_findings = 0
    for i, finding in enumerate(findings):
        finding_valid, finding_errors = validate_finding(finding, project_path)

        if finding_valid:
            valid_findings += 1
        else:
            for error in finding_errors:
                if strict:
                    result.errors.append(f"Finding[{i}]: {error}")
                else:
                    result.warnings.append(f"Finding[{i}]: {error}")

    # Calculate score
    if findings:
        result.score = int((valid_findings / len(findings)) * 100)

    # Must have at least 70% valid findings in strict mode
    if strict and result.score < 70:
        result.valid = False
        result.errors.append(f"SCORE_TOO_LOW: {result.score}% valid findings (minimum 70%)")

    # Check for real file references (not just counts)
    real_files = 0
    for finding in findings:
        file_path = finding.get("file_path") or finding.get("path") or finding.get("file")
        if file_path and not is_placeholder_path(file_path):
            real_files += 1

    if real_files == 0 and findings:
        result.errors.append("NO_REAL_FILES: All file paths appear to be placeholders")
        result.valid = False

    # If we have errors in strict mode, mark as invalid
    if strict and result.errors:
        result.valid = False

    return result


def format_validation_result(result: EvidenceValidationResult) -> str:
    """Format validation result for display."""
    lines = []

    status = "✅ VALID" if result.valid else "❌ INVALID"
    lines.append(f"Evidence Contract: {status} (Score: {result.score}/100)")

    if result.errors:
        lines.append("\nErrors:")
        for error in result.errors[:10]:  # Limit to 10
            lines.append(f"  ❌ {error}")
        if len(result.errors) > 10:
            lines.append(f"  ... and {len(result.errors) - 10} more errors")

    if result.warnings:
        lines.append("\nWarnings:")
        for warning in result.warnings[:5]:  # Limit to 5
            lines.append(f"  ⚠️ {warning}")
        if len(result.warnings) > 5:
            lines.append(f"  ... and {len(result.warnings) - 5} more warnings")

    return "\n".join(lines)


# Example of what a VALID finding looks like
VALID_FINDING_EXAMPLE = {
    "file_path": "functions/src/billing/index.ts",
    "line_number": 196,
    "code_snippet": """export const stripeWebhook = functions.https.onRequest(async (req, res) => {
  // In production, verify webhook signature:
  // const sig = req.headers['stripe-signature'];
  const event = req.body as StripeEvent;  // ← NO SIGNATURE VERIFICATION""",
    "severity": "BLOCKER",
    "type": "security",
    "title": "Stripe webhook signature not verified",
    "description": "The stripeWebhook endpoint accepts raw request body without verifying Stripe's signature. Attackers can POST fake events.",
    "fix_recommendation": "Uncomment signature verification: stripe.webhooks.constructEvent(req.rawBody, sig, webhookSecret). Add STRIPE_WEBHOOK_SECRET to environment.",
    "verification": "POST a fake checkout.session.completed event - it should be rejected with 400 Bad Request"
}

# Example of what an INVALID finding looks like
INVALID_FINDING_EXAMPLE = {
    "file_path": "/project/root/file.ts",  # ← PLACEHOLDER
    "severity": "HIGH",
    "description": "Security issue found",  # ← TOO VAGUE
    "fix_recommendation": "Fix this issue"  # ← GENERIC
    # Missing: line_number, code_snippet, verification
}
