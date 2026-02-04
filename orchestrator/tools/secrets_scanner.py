#!/usr/bin/env python3
"""
secrets_scanner.py - Security-grade secrets detection

This module scans files for hardcoded secrets using pattern matching
and entropy detection. It NEVER stores raw secrets - only redacted versions.

Key principles:
- Raw secrets stay in memory only long enough to redact
- All outputs are safe to write to disk
- Findings include redacted match + context
- Allowlist contexts reduce false positives
"""

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, List


# Load patterns from spec file
BECCA_ROOT = Path(__file__).parent.parent.parent
PATTERNS_FILE = BECCA_ROOT / "governance" / "specs" / "SECRETS_PATTERNS.json"


@dataclass
class SecretFinding:
    """A single secret finding (safe to serialize - no raw secrets)."""
    finding_id: str
    pattern_id: str
    pattern_name: str
    severity: str
    file: str
    line: int
    match_redacted: str
    context_redacted: str
    confidence: float
    allowlisted: bool
    allowlist_reason: Optional[str] = None
    notes: str = ""


@dataclass
class ScanProfile:
    """Timing profile for scan performance analysis."""
    enumerate_ms: float = 0.0
    open_read_ms: float = 0.0
    regex_scan_ms: float = 0.0
    entropy_ms: float = 0.0
    filters_ms: float = 0.0
    write_ms: float = 0.0
    files_read: int = 0
    files_skipped: int = 0
    bytes_read: int = 0


@dataclass
class ScanResult:
    """Result of scanning a codebase for secrets."""
    findings: list = field(default_factory=list)
    candidates: list = field(default_factory=list)  # Entropy-based candidates
    patterns_loaded: int = 0
    patterns_ran: int = 0
    files_scanned: int = 0
    severity_counts: dict = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
    })
    candidate_count: int = 0
    allowlisted_count: int = 0
    scan_time_seconds: float = 0.0
    profile: ScanProfile = field(default_factory=ScanProfile)


class SecretsScanner:
    """Scans files for hardcoded secrets using pattern matching."""

    def __init__(self, patterns_file: Path = None, suppressions_file: Path = None):
        self.patterns_file = patterns_file or PATTERNS_FILE
        self.suppressions_file = suppressions_file
        self.patterns = []
        self.compiled_patterns = {}
        self.entropy_config = {}
        self.file_targets = {}
        self.suppressions = {"pattern_ids": [], "files": [], "hashes": []}
        self.finding_counter = 0
        self._load_patterns()
        self._load_suppressions()

    def _load_patterns(self):
        """Load and compile patterns from SECRETS_PATTERNS.json."""
        if not self.patterns_file.exists():
            print(f"      WARNING: Patterns file not found: {self.patterns_file}")
            return

        with open(self.patterns_file) as f:
            config = json.load(f)

        self.patterns = config.get("patterns", [])
        self.entropy_config = config.get("entropy_detection", {})
        self.file_targets = config.get("file_targets", {})

        # Pre-compile regex patterns for performance
        for pattern in self.patterns:
            try:
                self.compiled_patterns[pattern["id"]] = re.compile(pattern["regex"])
            except re.error as e:
                print(f"      WARNING: Invalid regex for {pattern['id']}: {e}")

    def _load_suppressions(self):
        """Load suppressions from repo-local .becca_suppressions.json."""
        if not self.suppressions_file or not self.suppressions_file.exists():
            return

        try:
            with open(self.suppressions_file) as f:
                config = json.load(f)

            self.suppressions = {
                "pattern_ids": config.get("suppress_patterns", []),
                "files": config.get("suppress_files", []),
                "hashes": config.get("suppress_hashes", []),
            }
        except Exception as e:
            print(f"      WARNING: Could not load suppressions: {e}")

    def _is_suppressed(self, pattern_id: str, file_path: str, line: int) -> tuple:
        """Check if a finding is suppressed. Returns (is_suppressed, reason)."""
        # Check pattern suppression
        if pattern_id in self.suppressions["pattern_ids"]:
            return True, f"Pattern '{pattern_id}' suppressed in .becca_suppressions.json"

        # Check file suppression (supports glob patterns)
        import fnmatch
        for suppressed_file in self.suppressions["files"]:
            if fnmatch.fnmatch(file_path, suppressed_file):
                return True, f"File '{file_path}' matches suppression pattern"

        # Check hash suppression (stable ID: file:line:pattern)
        finding_hash = hashlib.md5(f"{file_path}:{line}:{pattern_id}".encode()).hexdigest()[:12]
        if finding_hash in self.suppressions["hashes"]:
            return True, f"Finding hash '{finding_hash}' suppressed"

        return False, None

    def scan_file(self, file_path: Path, project_path: Path, content: str = None) -> list:
        """Scan a single file for secrets. Returns list of SecretFinding.

        Args:
            content: If provided, use this content instead of reading the file.
                     This avoids double-reads when scanning multiple files.
        """
        findings = []
        rel_path = str(file_path.relative_to(project_path))

        if content is None:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return findings

        lines = content.split('\n')

        # Pre-compute lowercase content once for context checks
        content_lower = content.lower()

        # Scan with each pattern
        for pattern in self.patterns:
            pattern_id = pattern["id"]
            compiled = self.compiled_patterns.get(pattern_id)
            if not compiled:
                continue

            # Check if pattern requires specific context (file-level check, done once)
            requires_context = pattern.get("requires_context", [])
            if requires_context:
                has_context = any(ctx.lower() in content_lower for ctx in requires_context)
                if not has_context:
                    continue

            for line_num, line in enumerate(lines, 1):
                matches = compiled.finditer(line)
                for match in matches:
                    raw_match = match.group(0)

                    # Check exclude patterns (reduce false positives)
                    exclude_patterns = pattern.get("exclude_patterns", [])
                    if self._matches_exclude(line, exclude_patterns):
                        continue

                    # Check allowlist contexts
                    allowlisted, allowlist_reason = self._check_allowlist(
                        raw_match, line, rel_path, pattern.get("allowlist_context", [])
                    )

                    # Check repo-local suppressions (skip finding entirely)
                    suppressed, suppress_reason = self._is_suppressed(pattern_id, rel_path, line_num)
                    if suppressed:
                        continue  # Don't report suppressed findings at all

                    # Redact the match (NEVER store raw)
                    redacted_match = self._redact(raw_match, pattern.get("redaction", {}))
                    redacted_context = self._redact_line(line, raw_match, redacted_match)

                    # Generate finding
                    self.finding_counter += 1
                    finding = SecretFinding(
                        finding_id=f"SEC-{self.finding_counter:06d}",
                        pattern_id=pattern_id,
                        pattern_name=pattern.get("name", pattern_id),
                        severity=pattern.get("severity", "MEDIUM"),
                        file=rel_path,
                        line=line_num,
                        match_redacted=redacted_match,
                        context_redacted=redacted_context[:200],
                        confidence=self._calculate_confidence(pattern, raw_match, line),
                        allowlisted=allowlisted,
                        allowlist_reason=allowlist_reason,
                        notes=f"Matched {pattern.get('name', pattern_id)} pattern"
                    )
                    findings.append(finding)

        return findings

    def scan_for_entropy(self, file_path: Path, project_path: Path, content: str = None) -> list:
        """Scan for high-entropy strings that might be secrets.

        Args:
            content: If provided, use this content instead of reading the file.
        """
        candidates = []

        if not self.entropy_config.get("enabled", False):
            return candidates

        rel_path = str(file_path.relative_to(project_path))
        min_length = self.entropy_config.get("min_length", 32)
        min_entropy = self.entropy_config.get("min_entropy", 4.5)
        context_words = self.entropy_config.get("context_words", [])

        if content is None:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return candidates

        lines = content.split('\n')

        # Pattern for candidate strings (alphanumeric, base64-ish)
        candidate_pattern = re.compile(r'[A-Za-z0-9+/=_-]{32,}')

        for line_num, line in enumerate(lines, 1):
            # Only check lines with suspicious context words nearby
            has_context = any(word.lower() in line.lower() for word in context_words)
            if not has_context:
                continue

            matches = candidate_pattern.finditer(line)
            for match in matches:
                candidate = match.group(0)

                # Calculate Shannon entropy
                entropy = self._shannon_entropy(candidate)
                if entropy < min_entropy:
                    continue

                # Skip if it looks like a known safe pattern
                if self._is_safe_pattern(candidate):
                    continue

                # Redact the candidate
                redacted = self._redact(candidate, {"strategy": "prefix_suffix", "show_prefix": 6, "show_suffix": 4})
                redacted_line = self._redact_line(line, candidate, redacted)

                self.finding_counter += 1
                finding = SecretFinding(
                    finding_id=f"ENT-{self.finding_counter:06d}",
                    pattern_id="ENTROPY_CANDIDATE",
                    pattern_name="High Entropy String",
                    severity="LOW",  # Candidates are low severity until verified
                    file=rel_path,
                    line=line_num,
                    match_redacted=redacted,
                    context_redacted=redacted_line[:200],
                    confidence=min(0.3 + (entropy - min_entropy) * 0.1, 0.7),  # 0.3-0.7 range
                    allowlisted=False,
                    notes=f"High entropy string (entropy={entropy:.2f}) near context word"
                )
                candidates.append(finding)

        return candidates

    def _matches_exclude(self, line: str, exclude_patterns: list) -> bool:
        """Check if line matches any exclude patterns (false positive filters)."""
        for pattern in exclude_patterns:
            try:
                if re.search(pattern, line):
                    return True
            except re.error:
                # Invalid regex, treat as literal string match
                if pattern in line:
                    return True
        return False

    def _check_allowlist(self, raw_match: str, line: str, file_path: str, allowlist_contexts: list) -> tuple:
        """Check if a match should be allowlisted. Returns (is_allowlisted, reason)."""
        # Check path-based allowlist
        path_lower = file_path.lower()
        for ctx in allowlist_contexts:
            if ctx.lower() in path_lower:
                return True, f"Path contains '{ctx}'"

        # Check match-based allowlist
        for ctx in allowlist_contexts:
            if ctx.lower() in raw_match.lower():
                return True, f"Match contains '{ctx}'"

        # Check line-based allowlist
        line_lower = line.lower()
        for ctx in allowlist_contexts:
            if ctx.lower() in line_lower:
                return True, f"Line contains '{ctx}'"

        return False, None

    def _redact(self, raw: str, redaction_config: dict) -> str:
        """Redact a raw secret. NEVER returns the full secret."""
        strategy = redaction_config.get("strategy", "prefix_suffix")

        if strategy == "prefix_suffix":
            prefix_len = redaction_config.get("show_prefix", 4)
            suffix_len = redaction_config.get("show_suffix", 4)
            if len(raw) <= prefix_len + suffix_len + 3:
                return "*" * len(raw)
            return f"{raw[:prefix_len]}...{raw[-suffix_len:]}"

        elif strategy == "header_only":
            show_chars = redaction_config.get("show_chars", 20)
            if len(raw) <= show_chars:
                return raw[:show_chars // 2] + "..."
            return raw[:show_chars] + "..."

        elif strategy == "context_only":
            show_chars = redaction_config.get("show_chars", 50)
            return raw[:show_chars] + "..." if len(raw) > show_chars else "[REDACTED]"

        elif strategy == "mask_credentials":
            # For URLs like postgres://user:pass@host/db
            # Keep scheme and host, mask credentials
            url_pattern = re.compile(r'([a-z]+://)([^:]+):([^@]+)@(.+)')
            match = url_pattern.match(raw)
            if match:
                return f"{match.group(1)}****:****@{match.group(4)}"
            return "[REDACTED_URL]"

        elif strategy == "none":
            return raw  # Some patterns (like project IDs) don't need redaction

        else:
            # Default: show first 4 and last 4
            if len(raw) <= 11:
                return "*" * len(raw)
            return f"{raw[:4]}...{raw[-4:]}"

    def _redact_line(self, line: str, raw_match: str, redacted_match: str) -> str:
        """Redact a line, replacing the raw match with its redacted form."""
        return line.replace(raw_match, redacted_match)

    def _calculate_confidence(self, pattern: dict, raw_match: str, line: str) -> float:
        """Calculate confidence score for a finding."""
        base_confidence = 0.8

        # Known high-confidence patterns
        if pattern.get("severity") == "CRITICAL":
            base_confidence = 0.95
        elif pattern.get("severity") == "HIGH":
            base_confidence = 0.85

        # Lower confidence if near allowlist words
        line_lower = line.lower()
        for word in ["example", "test", "mock", "fake", "placeholder", "sample"]:
            if word in line_lower:
                base_confidence *= 0.7
                break

        return min(base_confidence, 1.0)

    def _shannon_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0.0

        # Count character frequencies
        freq = {}
        for char in string:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        length = len(string)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    def _is_safe_pattern(self, candidate: str) -> bool:
        """Check if a candidate is a known safe pattern (not a secret)."""
        # All same character
        if len(set(candidate)) == 1:
            return True

        # Looks like a hash (common in build artifacts)
        if re.match(r'^[a-f0-9]{32,}$', candidate.lower()):
            # Could be a hash, but also could be a secret - flag for review
            return False

        # Looks like base64 padding only
        if candidate.endswith("===="):
            return True

        return False

    def scan_files_profiled(self, files: List[Path], project_path: Path, run_entropy: bool = True) -> ScanResult:
        """
        Scan multiple files with timing instrumentation.
        Returns ScanResult with profile data.
        """
        profile = ScanProfile()
        all_findings = []
        all_candidates = []

        # Track total scan start
        total_start = time.perf_counter()

        for file_path in files:
            # Time file read
            read_start = time.perf_counter()
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                profile.bytes_read += len(content.encode('utf-8'))
                profile.files_read += 1
            except Exception:
                profile.files_skipped += 1
                continue
            profile.open_read_ms += (time.perf_counter() - read_start) * 1000

            # Time regex scan (pass content to avoid re-reading)
            regex_start = time.perf_counter()
            findings = self.scan_file(file_path, project_path, content=content)
            profile.regex_scan_ms += (time.perf_counter() - regex_start) * 1000
            all_findings.extend(findings)

            # Time entropy scan (if enabled)
            if run_entropy:
                entropy_start = time.perf_counter()
                candidates = self.scan_for_entropy(file_path, project_path, content=content)
                profile.entropy_ms += (time.perf_counter() - entropy_start) * 1000
                all_candidates.extend(candidates)

        total_time = time.perf_counter() - total_start

        # Count severities
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        allowlisted_count = 0
        for f in all_findings:
            if f.allowlisted:
                allowlisted_count += 1
            else:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return ScanResult(
            findings=all_findings,
            candidates=all_candidates,
            patterns_loaded=len(self.patterns),
            patterns_ran=len(self.compiled_patterns),
            files_scanned=profile.files_read,
            severity_counts=severity_counts,
            candidate_count=len(all_candidates),
            allowlisted_count=allowlisted_count,
            scan_time_seconds=total_time,
            profile=profile
        )


def generate_scan_profile(profile: ScanProfile, output_path: Path, scan_mode: str = "fast"):
    """Generate SCAN_PROFILE.json artifact for performance analysis."""
    total_ms = (profile.enumerate_ms + profile.open_read_ms + profile.regex_scan_ms +
                profile.entropy_ms + profile.filters_ms + profile.write_ms)

    # Performance thresholds by mode
    thresholds = {
        "fast": {"total_ms": 30000, "regex_ms": 5000, "files_max": 1000},
        "deep": {"total_ms": 120000, "regex_ms": 60000, "files_max": 2000},
        "release": {"total_ms": 300000, "regex_ms": 120000, "files_max": 5000},
    }
    mode_threshold = thresholds.get(scan_mode, thresholds["fast"])

    # Check for regression warnings
    warnings = []
    if total_ms > mode_threshold["total_ms"]:
        warnings.append(f"Total time ({total_ms/1000:.1f}s) exceeds {scan_mode} threshold ({mode_threshold['total_ms']/1000}s)")
    if profile.regex_scan_ms > mode_threshold["regex_ms"]:
        warnings.append(f"Regex scan ({profile.regex_scan_ms/1000:.1f}s) exceeds threshold ({mode_threshold['regex_ms']/1000}s)")
    if profile.files_read > mode_threshold["files_max"]:
        warnings.append(f"Files scanned ({profile.files_read}) exceeds expected max ({mode_threshold['files_max']})")

    output = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "scan_mode": scan_mode,
        "timings_ms": {
            "enumerate_ms": profile.enumerate_ms,
            "open_read_ms": profile.open_read_ms,
            "regex_scan_ms": profile.regex_scan_ms,
            "entropy_ms": profile.entropy_ms,
            "filters_ms": profile.filters_ms,
            "write_ms": profile.write_ms,
            "total_ms": total_ms
        },
        "stats": {
            "files_read": profile.files_read,
            "files_skipped": profile.files_skipped,
            "bytes_read": profile.bytes_read,
            "mb_read": round(profile.bytes_read / (1024 * 1024), 2)
        },
        "breakdown_pct": {},
        "performance": {
            "status": "OK" if not warnings else "WARN",
            "warnings": warnings,
            "thresholds": mode_threshold
        }
    }

    # Calculate percentage breakdown
    if total_ms > 0:
        for key, value in output["timings_ms"].items():
            if key != "total_ms":
                output["breakdown_pct"][key.replace("_ms", "_pct")] = round(value / total_ms * 100, 1)

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)


def generate_findings_json(result: ScanResult, output_path: Path):
    """Generate SECRET_FINDINGS.json artifact."""
    output = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "patterns_loaded": result.patterns_loaded,
            "patterns_ran": result.patterns_ran,
            "files_scanned": result.files_scanned,
            "total_findings": len(result.findings),
            "severity_counts": result.severity_counts,
            "candidate_count": result.candidate_count,
            "allowlisted_count": result.allowlisted_count,
            "scan_time_seconds": result.scan_time_seconds
        },
        "findings": [
            {
                "finding_id": f.finding_id,
                "pattern_id": f.pattern_id,
                "pattern_name": f.pattern_name,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "match_redacted": f.match_redacted,
                "context_redacted": f.context_redacted,
                "confidence": f.confidence,
                "allowlisted": f.allowlisted,
                "allowlist_reason": f.allowlist_reason,
                "notes": f.notes
            }
            for f in result.findings
            if not f.allowlisted  # Don't include allowlisted in main findings
        ],
        "allowlisted": [
            {
                "finding_id": f.finding_id,
                "pattern_id": f.pattern_id,
                "file": f.file,
                "line": f.line,
                "match_redacted": f.match_redacted,
                "allowlist_reason": f.allowlist_reason
            }
            for f in result.findings
            if f.allowlisted
        ],
        "candidates": [
            {
                "finding_id": f.finding_id,
                "file": f.file,
                "line": f.line,
                "match_redacted": f.match_redacted,
                "confidence": f.confidence,
                "notes": f.notes
            }
            for f in result.candidates
        ]
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)


def generate_findings_md(result: ScanResult, output_path: Path):
    """Generate SECRET_FINDINGS.md artifact."""
    md = f"""# Secrets Scan Findings

**Generated:** {datetime.utcnow().isoformat()}Z
**Files Scanned:** {result.files_scanned}
**Patterns Loaded:** {result.patterns_loaded}
**Scan Time:** {result.scan_time_seconds:.2f}s

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | {result.severity_counts.get('CRITICAL', 0)} |
| HIGH | {result.severity_counts.get('HIGH', 0)} |
| MEDIUM | {result.severity_counts.get('MEDIUM', 0)} |
| LOW | {result.severity_counts.get('LOW', 0)} |
| **Total Findings** | **{len([f for f in result.findings if not f.allowlisted])}** |
| Candidates (entropy) | {result.candidate_count} |
| Allowlisted | {result.allowlisted_count} |

---

## Critical & High Findings

"""
    critical_high = [f for f in result.findings if f.severity in ("CRITICAL", "HIGH") and not f.allowlisted]

    if critical_high:
        for finding in critical_high[:20]:  # Cap at 20
            md += f"""### {finding.finding_id} [{finding.severity}]

- **Pattern:** {finding.pattern_name} (`{finding.pattern_id}`)
- **File:** `{finding.file}:{finding.line}`
- **Match:** `{finding.match_redacted}`
- **Context:** `{finding.context_redacted}`
- **Confidence:** {finding.confidence:.0%}

"""
        if len(critical_high) > 20:
            md += f"\n*...and {len(critical_high) - 20} more critical/high findings (see JSON for full list)*\n\n"
    else:
        md += "*No critical or high severity findings.*\n\n"

    md += """---

## Medium & Low Findings

"""
    medium_low = [f for f in result.findings if f.severity in ("MEDIUM", "LOW") and not f.allowlisted]

    if medium_low:
        md += f"*{len(medium_low)} medium/low severity findings. See JSON for details.*\n\n"
        # Show first 5
        for finding in medium_low[:5]:
            md += f"- `{finding.file}:{finding.line}` - {finding.pattern_name} (confidence: {finding.confidence:.0%})\n"
        if len(medium_low) > 5:
            md += f"- *...and {len(medium_low) - 5} more*\n"
    else:
        md += "*No medium or low severity findings.*\n\n"

    md += """---

## Entropy Candidates (Review Required)

"""
    if result.candidates:
        md += f"*{len(result.candidates)} high-entropy strings found near suspicious context words.*\n\n"
        for candidate in result.candidates[:10]:
            md += f"- `{candidate.file}:{candidate.line}` - `{candidate.match_redacted}` (entropy-based)\n"
        if len(result.candidates) > 10:
            md += f"- *...and {len(result.candidates) - 10} more candidates*\n"
    else:
        md += "*No entropy-based candidates found.*\n\n"

    md += """---

## Allowlisted Matches

"""
    allowlisted = [f for f in result.findings if f.allowlisted]
    if allowlisted:
        md += f"*{len(allowlisted)} matches were allowlisted (likely test/example data).*\n\n"
        for finding in allowlisted[:10]:
            md += f"- `{finding.file}:{finding.line}` - {finding.pattern_name}: {finding.allowlist_reason}\n"
    else:
        md += "*No allowlisted matches.*\n\n"

    md += """---

## Notes

- Findings are redacted to prevent accidental exposure
- High-confidence findings (>80%) should be reviewed immediately
- Entropy candidates require manual verification
- Allowlisted matches are excluded from severity counts

*Report generated by BECCA Secrets Scanner v1.0.0*
"""

    with open(output_path, "w") as f:
        f.write(md)
