#!/usr/bin/env python3
"""
propose_secrets_remediation.py - PROPOSE tool for secrets remediation

Scans codebase for hardcoded secrets and generates proposals to:
  1. Replace secrets with environment variable references
  2. Add secrets to .env.example (without values)
  3. Update .gitignore if needed

Detection patterns:
  - API keys (various formats)
  - Passwords in config files
  - Private keys
  - Database connection strings with credentials
  - JWT secrets
  - AWS credentials

Usage:
    from tools.propose_secrets_remediation import SecretsRemediationProposer

    proposer = SecretsRemediationProposer(
        project_path=Path("./my-project"),
        run_dir=Path("./runs/RUN-001"),
        plan_id="PLAN-001",
        task_id="T001"
    )
    result = proposer.run()
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tools.propose_base import ProposeTool, FileChange


@dataclass
class SecretFinding:
    """A detected secret in the codebase."""
    file_path: str
    line_number: int
    secret_type: str  # api_key, password, private_key, jwt_secret, db_credential, aws_credential
    pattern_name: str
    matched_text: str  # The actual match (redacted for safety)
    context_line: str  # The line containing the secret
    suggested_env_var: str  # Suggested environment variable name
    severity: str  # critical, high, medium, low


# Detection patterns - ordered by severity
SECRET_PATTERNS = [
    # Critical: Private keys
    {
        "name": "private_key_header",
        "pattern": r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        "type": "private_key",
        "severity": "critical",
        "env_prefix": "PRIVATE_KEY",
    },
    {
        "name": "private_key_inline",
        "pattern": r"['\"]-----BEGIN[^'\"]+PRIVATE[^'\"]+-----['\"]",
        "type": "private_key",
        "severity": "critical",
        "env_prefix": "PRIVATE_KEY",
    },

    # Critical: AWS credentials
    {
        "name": "aws_access_key",
        "pattern": r"(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "type": "aws_credential",
        "severity": "critical",
        "env_prefix": "AWS_ACCESS_KEY_ID",
    },
    {
        "name": "aws_secret_key",
        "pattern": r"(?:aws_secret_access_key|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "type": "aws_credential",
        "severity": "critical",
        "env_prefix": "AWS_SECRET_ACCESS_KEY",
    },

    # High: API keys
    {
        "name": "generic_api_key",
        "pattern": r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
        "type": "api_key",
        "severity": "high",
        "env_prefix": "API_KEY",
    },
    {
        "name": "bearer_token",
        "pattern": r"Bearer\s+[A-Za-z0-9_\-\.]{20,}",
        "type": "api_key",
        "severity": "high",
        "env_prefix": "AUTH_TOKEN",
    },
    {
        "name": "firebase_key",
        "pattern": r"AIza[A-Za-z0-9_\-]{35}",
        "type": "api_key",
        "severity": "high",
        "env_prefix": "FIREBASE_API_KEY",
    },
    {
        "name": "stripe_key",
        "pattern": r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}",
        "type": "api_key",
        "severity": "high",
        "env_prefix": "STRIPE_KEY",
    },
    {
        "name": "openai_key",
        "pattern": r"sk-[A-Za-z0-9]{48}",
        "type": "api_key",
        "severity": "high",
        "env_prefix": "OPENAI_API_KEY",
    },
    {
        "name": "github_token",
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}",
        "type": "api_key",
        "severity": "high",
        "env_prefix": "GITHUB_TOKEN",
    },

    # High: JWT secrets
    {
        "name": "jwt_secret",
        "pattern": r"(?:jwt[_-]?secret|secret[_-]?key)\s*[=:]\s*['\"]([^'\"]{16,})['\"]",
        "type": "jwt_secret",
        "severity": "high",
        "env_prefix": "JWT_SECRET",
    },

    # High: Database credentials
    {
        "name": "db_connection_string",
        "pattern": r"(?:mongodb|postgres|mysql|redis)://[^:]+:[^@]+@[^\s'\"]+",
        "type": "db_credential",
        "severity": "high",
        "env_prefix": "DATABASE_URL",
    },
    {
        "name": "db_password",
        "pattern": r"(?:db[_-]?password|database[_-]?password)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        "type": "db_credential",
        "severity": "high",
        "env_prefix": "DB_PASSWORD",
    },

    # Medium: Generic passwords
    {
        "name": "password_assignment",
        "pattern": r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "type": "password",
        "severity": "medium",
        "env_prefix": "PASSWORD",
    },

    # Medium: Webhook URLs with tokens
    {
        "name": "webhook_url",
        "pattern": r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
        "type": "api_key",
        "severity": "medium",
        "env_prefix": "SLACK_WEBHOOK_URL",
    },
    {
        "name": "discord_webhook",
        "pattern": r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
        "type": "api_key",
        "severity": "medium",
        "env_prefix": "DISCORD_WEBHOOK_URL",
    },
]

# Files/directories to skip (use [/\\] for cross-platform path separators)
SKIP_PATTERNS = [
    r"\.git[/\\]",
    r"node_modules[/\\]",
    r"__pycache__[/\\]",
    r"\.pyc$",
    r"\.env\.example$",
    r"\.env\.template$",
    r"package-lock\.json$",
    r"yarn\.lock$",
    r"\.min\.js$",
    r"\.map$",
    r"dist[/\\]",
    r"build[/\\]",
    r"\.pytest_cache[/\\]",
    r"\.mypy_cache[/\\]",
]

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".json", ".yaml", ".yml", ".toml",
    ".env", ".env.local", ".env.development", ".env.production",
    ".config", ".cfg", ".ini",
    ".sh", ".bash",
    ".java", ".kt", ".go", ".rs", ".rb",
    ".php", ".cs", ".swift",
}


class SecretsRemediationProposer(ProposeTool):
    """
    PROPOSE tool that scans for hardcoded secrets and generates remediation proposals.
    """

    TOOL_NAME = "propose_secrets_remediation"
    VERSION = "1.0.0"

    def __init__(
        self,
        project_path: Path,
        run_dir: Path,
        plan_id: str,
        task_id: str,
        evidence_dir: Path = None,
        scan_paths: list[str] = None,
        exclude_patterns: list[str] = None,
        severity_threshold: str = "low",  # Only report findings >= this severity
    ):
        super().__init__(project_path, run_dir, plan_id, task_id, evidence_dir)
        self.scan_paths = scan_paths or ["."]
        self.exclude_patterns = exclude_patterns or []
        self.severity_threshold = severity_threshold
        self.findings: list[SecretFinding] = []

    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped."""
        path_str = str(file_path)

        # Check built-in skip patterns
        for pattern in SKIP_PATTERNS:
            if re.search(pattern, path_str):
                return True

        # Check custom exclude patterns
        for pattern in self.exclude_patterns:
            if re.search(pattern, path_str):
                return True

        # Check extension
        if file_path.suffix.lower() not in SCAN_EXTENSIONS:
            # Allow files without extension that might be config files
            if file_path.suffix:
                return True

        return False

    def _severity_rank(self, severity: str) -> int:
        """Get numeric rank for severity comparison."""
        ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return ranks.get(severity, 0)

    def _redact_secret(self, text: str) -> str:
        """Redact a secret for safe logging."""
        if len(text) <= 8:
            return "*" * len(text)
        return text[:4] + "*" * (len(text) - 8) + text[-4:]

    def _generate_env_var_name(self, finding: SecretFinding) -> str:
        """Generate appropriate environment variable name."""
        # Extract context from file path
        file_name = Path(finding.file_path).stem.upper()
        file_name = re.sub(r"[^A-Z0-9]", "_", file_name)

        base_prefix = finding.suggested_env_var

        # Make unique by combining with file context
        if file_name not in base_prefix:
            return f"{base_prefix}_{file_name}"
        return base_prefix

    def _scan_file(self, file_path: Path) -> list[SecretFinding]:
        """Scan a single file for secrets."""
        findings = []
        relative_path = str(file_path.relative_to(self.project_path))

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            return findings

        for pattern_info in SECRET_PATTERNS:
            # Skip if below severity threshold
            if self._severity_rank(pattern_info["severity"]) < self._severity_rank(self.severity_threshold):
                continue

            pattern = re.compile(pattern_info["pattern"], re.IGNORECASE)

            for line_num, line in enumerate(lines, 1):
                # Skip comment lines (basic check)
                stripped = line.strip()
                if stripped.startswith(("#", "//", "*", "/*")):
                    continue

                matches = pattern.finditer(line)
                for match in matches:
                    matched_text = match.group(0)

                    # Skip if it looks like a placeholder
                    if any(placeholder in matched_text.lower() for placeholder in
                           ["your_", "xxx", "example", "placeholder", "<", ">"]):
                        continue

                    finding = SecretFinding(
                        file_path=relative_path,
                        line_number=line_num,
                        secret_type=pattern_info["type"],
                        pattern_name=pattern_info["name"],
                        matched_text=self._redact_secret(matched_text),
                        context_line=line[:100] + ("..." if len(line) > 100 else ""),
                        suggested_env_var=pattern_info["env_prefix"],
                        severity=pattern_info["severity"],
                    )
                    findings.append(finding)

        return findings

    def _scan_codebase(self) -> list[SecretFinding]:
        """Scan entire codebase for secrets."""
        all_findings = []

        for scan_path in self.scan_paths:
            base_path = self.project_path / scan_path
            if not base_path.exists():
                continue

            if base_path.is_file():
                if not self._should_skip_file(base_path):
                    all_findings.extend(self._scan_file(base_path))
            else:
                for file_path in base_path.rglob("*"):
                    if file_path.is_file() and not self._should_skip_file(file_path):
                        all_findings.extend(self._scan_file(file_path))

        # Deduplicate findings
        seen = set()
        unique_findings = []
        for f in all_findings:
            key = (f.file_path, f.line_number, f.pattern_name)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def _generate_replacement(self, finding: SecretFinding) -> tuple[str, str, str]:
        """
        Generate replacement code for a secret.

        Returns: (env_var_name, original_line, new_line)
        """
        env_var = self._generate_env_var_name(finding)
        original_line = finding.context_line

        # Determine language from file extension
        ext = Path(finding.file_path).suffix.lower()

        if ext in {".py"}:
            # Python: os.environ.get() or os.getenv()
            new_line = re.sub(
                SECRET_PATTERNS[0]["pattern"],  # Will be replaced per-pattern
                f'os.environ.get("{env_var}")',
                original_line,
                flags=re.IGNORECASE
            )
        elif ext in {".js", ".ts", ".jsx", ".tsx"}:
            # JavaScript/TypeScript: process.env.VAR
            new_line = re.sub(
                SECRET_PATTERNS[0]["pattern"],
                f"process.env.{env_var}",
                original_line,
                flags=re.IGNORECASE
            )
        else:
            # Generic: ${VAR} or environment variable reference
            new_line = f"${{{env_var}}}"

        return env_var, original_line, new_line

    def generate_changes(self) -> list[FileChange]:
        """
        Generate file changes for secrets remediation.

        Scans codebase, identifies secrets, generates patches.
        """
        self.findings = self._scan_codebase()

        if not self.findings:
            return []

        changes = []
        env_vars_needed = set()

        # Group findings by file
        findings_by_file: dict[str, list[SecretFinding]] = {}
        for finding in self.findings:
            if finding.file_path not in findings_by_file:
                findings_by_file[finding.file_path] = []
            findings_by_file[finding.file_path].append(finding)

        # Generate changes per file
        for file_path, file_findings in findings_by_file.items():
            full_path = self.project_path / file_path
            if not full_path.exists():
                continue

            try:
                original_content = full_path.read_text(encoding="utf-8")
                lines = original_content.splitlines()
            except Exception:
                continue

            modified = False
            for finding in file_findings:
                line_idx = finding.line_number - 1
                if line_idx >= len(lines):
                    continue

                env_var = self._generate_env_var_name(finding)
                env_vars_needed.add(env_var)

                # We document the finding but don't auto-replace
                # (secrets remediation requires human review)
                modified = True

            if modified:
                # Create a comment-based change documenting the secrets found
                # Real replacement requires human review
                change = FileChange(
                    path=file_path,
                    action="modify",
                    before_content=original_content,
                    after_content=original_content,  # No auto-modify for safety
                )
                changes.append(change)

        # Generate .env.example additions
        env_example_path = self.project_path / ".env.example"
        existing_env_example = ""
        if env_example_path.exists():
            existing_env_example = env_example_path.read_text(encoding="utf-8")

        new_env_vars = []
        for env_var in sorted(env_vars_needed):
            if env_var not in existing_env_example:
                new_env_vars.append(f"{env_var}=")

        if new_env_vars:
            new_content = existing_env_example.rstrip()
            if new_content:
                new_content += "\n\n# Added by secrets remediation\n"
            else:
                new_content = "# Environment variables (secrets remediation)\n"
            new_content += "\n".join(new_env_vars) + "\n"

            changes.append(FileChange(
                path=".env.example",
                action="create" if not env_example_path.exists() else "modify",
                before_content=existing_env_example if env_example_path.exists() else None,
                after_content=new_content,
            ))

        return changes

    def get_title(self) -> str:
        """Return proposal title."""
        count = len(self.findings)
        severity_counts = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        severity_summary = ", ".join(f"{c} {s}" for s, c in sorted(
            severity_counts.items(),
            key=lambda x: -self._severity_rank(x[0])
        ))

        return f"Remediate {count} hardcoded secrets ({severity_summary})"

    def get_description(self) -> str:
        """Return detailed description."""
        if not self.findings:
            return "No hardcoded secrets detected in the scanned codebase."

        lines = [
            f"Detected {len(self.findings)} potential hardcoded secrets in the codebase.",
            "",
            "**Findings by severity:**",
        ]

        # Group by severity
        by_severity: dict[str, list[SecretFinding]] = {}
        for f in self.findings:
            if f.severity not in by_severity:
                by_severity[f.severity] = []
            by_severity[f.severity].append(f)

        for severity in ["critical", "high", "medium", "low"]:
            if severity in by_severity:
                lines.append(f"- **{severity.upper()}**: {len(by_severity[severity])} findings")

        lines.extend([
            "",
            "**Files affected:**",
        ])

        files = set(f.file_path for f in self.findings)
        for file_path in sorted(files)[:10]:
            count = len([f for f in self.findings if f.file_path == file_path])
            lines.append(f"- `{file_path}` ({count} secrets)")

        if len(files) > 10:
            lines.append(f"- ... and {len(files) - 10} more files")

        return "\n".join(lines)

    def get_rationale(self) -> str:
        """Return rationale for remediation."""
        return """Hardcoded secrets in source code pose significant security risks:

1. **Exposure via version control**: Secrets in code are pushed to repositories
   where they can be accessed by unauthorized parties or leaked in breaches.

2. **No rotation capability**: Hardcoded secrets cannot be rotated without
   code changes and deployment.

3. **Environment coupling**: Hardcoded secrets tie code to specific environments,
   breaking the twelve-factor app principle.

4. **Audit trail**: Secret access cannot be logged or audited when hardcoded.

**Remediation approach:**
- Replace hardcoded values with environment variable references
- Add environment variable templates to .env.example
- Document required secrets in deployment documentation
- Use secret management services in production (e.g., AWS Secrets Manager,
  HashiCorp Vault, GCP Secret Manager)

**IMPORTANT**: This proposal identifies secrets but does NOT auto-replace them.
Human review is required before applying any changes to ensure:
- Correct environment variable naming
- Proper secret management setup
- No false positives removed"""

    def get_risk_classification(self) -> str:
        """Return risk classification based on findings."""
        if not self.findings:
            return "low"

        # Check for critical findings
        critical_count = len([f for f in self.findings if f.severity == "critical"])
        high_count = len([f for f in self.findings if f.severity == "high"])

        if critical_count > 0:
            return "critical"  # Any critical secrets = critical proposal
        elif high_count > 5:
            return "high"
        elif high_count > 0:
            return "medium"
        return "low"

    def get_tests_to_run(self) -> list[str]:
        """Return tests to verify remediation."""
        return [
            "grep -r 'process.env\\|os.environ' --include='*.py' --include='*.js' --include='*.ts'",
            "test -f .env.example && cat .env.example",
        ]

    def get_evidence_ids(self) -> list[str]:
        """Return evidence IDs supporting this proposal."""
        return [f"SECRET-SCAN-{self.task_id}"]

    def _generate_findings_report(self) -> str:
        """Generate detailed findings report."""
        if not self.findings:
            return "No secrets detected."

        lines = [
            "# Secrets Scan Report",
            "",
            f"**Scan Date:** {self.proposal.created_at if self.proposal else 'N/A'}",
            f"**Total Findings:** {len(self.findings)}",
            "",
            "---",
            "",
        ]

        # Group by file
        by_file: dict[str, list[SecretFinding]] = {}
        for f in self.findings:
            if f.file_path not in by_file:
                by_file[f.file_path] = []
            by_file[f.file_path].append(f)

        for file_path in sorted(by_file.keys()):
            file_findings = by_file[file_path]
            lines.extend([
                f"## `{file_path}`",
                "",
            ])

            for finding in sorted(file_findings, key=lambda x: x.line_number):
                severity_emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢"
                }.get(finding.severity, "⚪")

                lines.extend([
                    f"### Line {finding.line_number} {severity_emoji} {finding.severity.upper()}",
                    "",
                    f"**Type:** {finding.secret_type}",
                    f"**Pattern:** {finding.pattern_name}",
                    f"**Suggested ENV:** `{self._generate_env_var_name(finding)}`",
                    "",
                    "```",
                    finding.context_line,
                    "```",
                    "",
                ])

        return "\n".join(lines)

    def write_artifacts(self) -> dict:
        """Write proposal artifacts including findings report."""
        artifacts = super().write_artifacts()

        # Also write findings report
        if self.proposal and self.findings:
            report_path = self.evidence_dir / f"{self.proposal.proposal_id}-findings.md"
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(self._generate_findings_report())
            artifacts["findings_report"] = str(report_path)

        return artifacts
