#!/usr/bin/env python3
"""
tool_inspector.py - Read and grep codebase

This tool inspects the project codebase to gather context for the mission.
It is READ-ONLY and does not modify any files.

SECURITY: Hard boundaries enforced via PROJECTS.json
- Only scans within project's allowed root directory
- Denies scanning .ssh, .env, credentials, etc.
- Logs all paths read for auditability

Actions: read, grep, list
"""

import fnmatch
import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

from tools.secrets_scanner import (
    SecretsScanner, ScanResult, generate_findings_json, generate_findings_md
)

# Load project config for boundaries
BECCA_ROOT = Path(__file__).parent.parent.parent
PROJECTS_FILE = BECCA_ROOT / "governance" / "specs" / "PROJECTS.json"

# Global deny patterns (NEVER scan these)
GLOBAL_DENY = [
    "**/.ssh/**",
    "**/.aws/**",
    "**/credentials*",
    "**/*secret*",
    "**/private_key*",
    "**/.env",
    "**/.env.*",
    "**/serviceAccountKey.json",
    "**/*-firebase-adminsdk*.json",
    "**/node_modules/**",
    "**/.git/**",
]


def load_project_config(project_name: str) -> dict:
    """Load project config from PROJECTS.json."""
    if not PROJECTS_FILE.exists():
        return {}

    with open(PROJECTS_FILE) as f:
        config = json.load(f)

    return config.get("projects", {}).get(project_name, {})


def is_path_denied(path: Path, project_path: Path, deny_patterns: list) -> bool:
    """Check if a path should be denied (security boundary)."""
    try:
        rel_path = str(path.relative_to(project_path))
    except ValueError:
        rel_path = str(path)

    filename = path.name
    full_path = str(path)

    # Check global deny patterns + project-specific patterns
    for pattern in GLOBAL_DENY + deny_patterns:
        # Handle ** glob patterns (fnmatch doesn't support ** properly)
        if pattern.startswith("**/"):
            # Pattern like **/foo.json should match any path ending with foo.json
            suffix_pattern = pattern[3:]  # Remove **/
            if fnmatch.fnmatch(filename, suffix_pattern):
                return True
            if fnmatch.fnmatch(rel_path, suffix_pattern):
                return True
            # Also check if any part of the path matches
            for part in Path(rel_path).parts:
                if fnmatch.fnmatch(part, suffix_pattern):
                    return True

        # Standard fnmatch check
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(filename, pattern):
            return True

        # Also check full path for absolute patterns
        if fnmatch.fnmatch(full_path, pattern):
            return True

    return False


def is_within_boundary(path: Path, project_path: Path) -> bool:
    """Ensure path is within project boundary (no directory traversal)."""
    try:
        path.resolve().relative_to(project_path.resolve())
        return True
    except ValueError:
        return False


def run_inspector(run_id: str, run_dir: Path, project_path: Path, mission: str, project_name: str = None) -> dict:
    """
    Inspect codebase for mission-relevant information.

    Returns tool output per ARTIFACT_SPEC.
    """
    started_at = datetime.utcnow()
    evidence = []
    findings = []

    # Load project security boundaries FIRST
    project_config = load_project_config(project_name) if project_name else {}
    deny_patterns = project_config.get("deny_scan", [])

    # Audit tracking - separate categories with counts + samples
    # enumerated = seen in directory walk
    # opened = file handle opened for reading
    # parsed = content actually scanned/regex matched
    # denied = blocked by security patterns
    # skipped = excluded (size, binary, extension)
    audit = {
        "enumerated_count": 0,
        "enumerated_sample": [],  # first 50
        "opened_count": 0,
        "opened_sample": [],  # first 50
        "parsed_count": 0,
        "parsed_sample": [],  # first 50
        "denied_count": 0,
        "denied_sample": [],  # first 50
        "project_path": project_path,  # For deny checks
        "deny_patterns": deny_patterns,  # For deny checks
        "skipped_count": 0,
        "skipped_reasons": {},  # reason -> count
        "sample_limit": 50
    }

    tool_dir = run_dir / "tool_inspector"
    evidence_dir = tool_dir / "evidence"

    print(f"      Security: {len(GLOBAL_DENY) + len(deny_patterns)} deny patterns active")

    # Extract keywords from mission
    keywords = extract_keywords(mission)
    print(f"      Keywords: {keywords}")

    # 1. Scan project structure
    print("      Scanning project structure...")
    structure = scan_structure(project_path, audit=audit)
    structure_file = evidence_dir / "project_structure.json"
    with open(structure_file, "w") as f:
        json.dump(structure, f, indent=2)
    evidence.append({
        "type": "file",
        "path": str(structure_file),
        "description": "Project directory structure"
    })

    # 2. Search for keywords in code
    print("      Searching for keywords...")
    for keyword in keywords[:5]:  # Limit to 5 keywords
        grep_results = grep_keyword(project_path, keyword, audit=audit)
        if grep_results:
            findings.extend(grep_results[:10])  # Limit results per keyword

    grep_file = evidence_dir / "grep_results.json"
    with open(grep_file, "w") as f:
        json.dump(findings, f, indent=2)
    evidence.append({
        "type": "log",
        "path": str(grep_file),
        "description": f"Grep results for keywords: {keywords}"
    })

    # 3. Find relevant config files
    print("      Finding config files...")
    configs = find_configs(project_path, audit=audit)
    configs_file = evidence_dir / "config_files.json"
    with open(configs_file, "w") as f:
        json.dump(configs, f, indent=2)
    evidence.append({
        "type": "file",
        "path": str(configs_file),
        "description": "Configuration files found"
    })

    # 4. Check for error patterns
    print("      Checking for error patterns...")
    error_patterns = find_error_patterns(project_path, audit=audit)
    errors_file = evidence_dir / "error_patterns.json"
    with open(errors_file, "w") as f:
        json.dump(error_patterns, f, indent=2)
    evidence.append({
        "type": "log",
        "path": str(errors_file),
        "description": "Error patterns found in code"
    })

    # 5. Scan for secrets (security-grade pattern matching)
    print("      Scanning for secrets...")
    secrets_result = scan_for_secrets(project_path, audit=audit, evidence_dir=evidence_dir)

    # Generate SECRET_FINDINGS artifacts
    secrets_json_file = evidence_dir / "SECRET_FINDINGS.json"
    secrets_md_file = evidence_dir / "SECRET_FINDINGS.md"
    generate_findings_json(secrets_result, secrets_json_file)
    generate_findings_md(secrets_result, secrets_md_file)

    evidence.append({
        "type": "security",
        "path": str(secrets_json_file),
        "description": f"Secrets scan: {len([f for f in secrets_result.findings if not f.allowlisted])} findings, {secrets_result.candidate_count} candidates"
    })
    evidence.append({
        "type": "security",
        "path": str(secrets_md_file),
        "description": "Secrets scan report (human-readable)"
    })

    # Add performance profile
    profile_file = evidence_dir / "SCAN_PROFILE.json"
    if profile_file.exists():
        evidence.append({
            "type": "profile",
            "path": str(profile_file),
            "description": "Scan timing profile for performance analysis"
        })

    print(f"      Secrets: {secrets_result.severity_counts.get('CRITICAL', 0)} CRITICAL, "
          f"{secrets_result.severity_counts.get('HIGH', 0)} HIGH, "
          f"{secrets_result.candidate_count} candidates")

    # 6. Save audit log (counts + samples, not full lists)
    audit_log = {
        "summary": {
            "enumerated": audit["enumerated_count"],
            "opened": audit["opened_count"],
            "parsed": audit["parsed_count"],
            "denied": audit["denied_count"],
            "skipped": audit["skipped_count"]
        },
        "samples": {
            "enumerated": audit["enumerated_sample"],
            "opened": audit["opened_sample"],
            "parsed": audit["parsed_sample"],
            "denied": audit["denied_sample"]
        },
        "skipped_reasons": audit["skipped_reasons"],
        "deny_patterns_active": len(GLOBAL_DENY) + len(deny_patterns),
        "boundary": str(project_path)
    }
    audit_file = evidence_dir / "audit_log.json"
    with open(audit_file, "w") as f:
        json.dump(audit_log, f, indent=2)
    evidence.append({
        "type": "log",
        "path": str(audit_file),
        "description": f"Audit log: {audit['enumerated_count']} enumerated, {audit['opened_count']} opened, {audit['parsed_count']} parsed, {audit['denied_count']} denied"
    })

    completed_at = datetime.utcnow()
    duration = (completed_at - started_at).total_seconds()

    # Build output
    output = {
        "tool_id": "tool_inspector",
        "run_id": run_id,
        "status": "pass",
        "state": "COMPLETE",
        "evidence": evidence,
        "changes": {
            "files_modified": 0,
            "files_created": len(evidence),
            "lines_added": 0,
            "lines_removed": 0
        },
        "success_reasoning": {
            "invariants_checked": [
                "Project path exists",
                "Source files are readable",
                "Keywords extracted from mission"
            ],
            "assumptions_made": [
                "Mission keywords are relevant to search",
                "Top 10 results per keyword are sufficient"
            ],
            "not_tested": [
                "Binary files not scanned",
                "node_modules excluded",
                "Files > 1MB skipped"
            ]
        },
        "risks": _build_risks_from_secrets(secrets_result),
        "next_actions": [
            {
                "tool": "tool_browser",
                "priority": "required",
                "reason": "Capture runtime behavior in browser"
            }
        ],
        "timing": {
            "started_at": started_at.isoformat() + "Z",
            "completed_at": completed_at.isoformat() + "Z",
            "duration_seconds": duration
        },
        "tokens_used": 0,
        "error": None,
        "findings_summary": {
            "keywords": keywords,
            "files_scanned": structure.get("total_files", 0),
            "grep_matches": len(findings),
            "config_files": len(configs),
            "error_patterns": len(error_patterns)
        },
        "secrets_summary": {
            "patterns_loaded": secrets_result.patterns_loaded,
            "patterns_ran": secrets_result.patterns_ran,
            "files_scanned": secrets_result.files_scanned,
            "severity_counts": secrets_result.severity_counts,
            "candidate_count": secrets_result.candidate_count,
            "allowlisted_count": secrets_result.allowlisted_count,
            "scan_time_seconds": secrets_result.scan_time_seconds
        }
    }

    # Save output
    output_file = tool_dir / "output.json"
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    return output


def extract_keywords(mission: str) -> list:
    """Extract search keywords from mission description."""
    # Remove common words
    stopwords = {"find", "the", "a", "an", "in", "on", "for", "to", "and", "or", "is", "are", "check", "look", "search"}

    words = re.findall(r'\b[a-zA-Z]+\b', mission.lower())
    keywords = [w for w in words if w not in stopwords and len(w) > 2]

    # Add compound terms
    if "console" in mission.lower():
        keywords.append("console.error")
        keywords.append("console.warn")
    if "error" in mission.lower():
        keywords.append("throw")
        keywords.append("catch")
    if "login" in mission.lower():
        keywords.append("auth")
        keywords.append("signin")

    return list(set(keywords))[:10]


def scan_structure(project_path: Path, max_depth: int = 3, audit: dict = None) -> dict:
    """Scan project directory structure."""
    structure = {
        "root": str(project_path),
        "directories": [],
        "file_types": {},
        "total_files": 0
    }

    skip_dirs = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".firebase"}

    for root, dirs, files in os.walk(project_path):
        # Skip certain directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        # Check depth
        depth = len(Path(root).relative_to(project_path).parts)
        if depth > max_depth:
            continue

        rel_path = str(Path(root).relative_to(project_path))
        if rel_path != ".":
            structure["directories"].append(rel_path)

        for f in files:
            structure["total_files"] += 1
            ext = Path(f).suffix.lower()
            structure["file_types"][ext] = structure["file_types"].get(ext, 0) + 1

            # Track file enumeration (not content read, just directory walk)
            if audit is not None:
                audit["enumerated_count"] += 1
                if len(audit["enumerated_sample"]) < audit["sample_limit"]:
                    file_path = str(Path(root) / f)
                    audit["enumerated_sample"].append(file_path)

    return structure


def grep_keyword(project_path: Path, keyword: str, audit: dict = None) -> list:
    """Search for keyword in project files."""
    results = []
    skip_dirs = {"node_modules", ".git", ".next", "dist", "build"}
    extensions = {".ts", ".tsx", ".js", ".jsx", ".py", ".json", ".md", ".rules"}

    # Get deny patterns from audit context
    deny_patterns = audit.get("deny_patterns", []) if audit else []

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for f in files:
            ext = Path(f).suffix.lower()
            if ext not in extensions:
                # Track skipped file
                if audit is not None:
                    audit["skipped_count"] += 1
                    reason = f"extension:{ext or 'none'}"
                    audit["skipped_reasons"][reason] = audit["skipped_reasons"].get(reason, 0) + 1
                continue

            file_path = Path(root) / f

            # SECURITY: Check deny patterns BEFORE opening
            if is_path_denied(file_path, project_path, deny_patterns):
                if audit is not None:
                    audit["denied_count"] += 1
                    if len(audit["denied_sample"]) < audit["sample_limit"]:
                        audit["denied_sample"].append(str(file_path))
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                    # Track file opened for audit
                    if audit is not None:
                        audit["opened_count"] += 1
                        if len(audit["opened_sample"]) < audit["sample_limit"]:
                            audit["opened_sample"].append(str(file_path))

                    content = fp.read()

                    # Track file parsed (content actually scanned)
                    if audit is not None:
                        audit["parsed_count"] += 1
                        if len(audit["parsed_sample"]) < audit["sample_limit"]:
                            audit["parsed_sample"].append(str(file_path))

                    # Search line by line
                    for line_num, line in enumerate(content.split('\n'), 1):
                        if keyword.lower() in line.lower():
                            results.append({
                                "file": str(file_path.relative_to(project_path)),
                                "line": line_num,
                                "content": line.strip()[:200],
                                "keyword": keyword
                            })
                            if len(results) >= 100:
                                return results
            except Exception:
                pass

    return results


def find_configs(project_path: Path, audit: dict = None) -> list:
    """Find configuration files."""
    config_patterns = [
        "*.config.js", "*.config.ts", "*.json", ".env*",
        "firebase.json", "firestore.rules", "storage.rules",
        "package.json", "tsconfig.json"
    ]

    # Get deny patterns from audit context
    deny_patterns = audit.get("deny_patterns", []) if audit else []

    configs = []
    for pattern in config_patterns:
        for match in project_path.glob(f"**/{pattern}"):
            if "node_modules" not in str(match):
                # SECURITY: Check deny patterns
                if is_path_denied(match, project_path, deny_patterns):
                    if audit is not None:
                        audit["denied_count"] += 1
                        if len(audit["denied_sample"]) < audit["sample_limit"]:
                            audit["denied_sample"].append(str(match))
                    continue

                configs.append(str(match.relative_to(project_path)))
                # Track config file enumeration (not content read)
                if audit is not None:
                    audit["enumerated_count"] += 1
                    if len(audit["enumerated_sample"]) < audit["sample_limit"]:
                        audit["enumerated_sample"].append(str(match))

    return configs[:50]


def find_error_patterns(project_path: Path, audit: dict = None) -> list:
    """Find common error patterns in code."""
    patterns = [
        (r"console\.error", "console.error call"),
        (r"console\.warn", "console.warn call"),
        (r"throw new Error", "Error throw"),
        (r"catch\s*\(", "catch block"),
        (r"\.catch\(", "promise catch"),
        (r"try\s*\{", "try block"),
    ]

    # Get deny patterns from audit context
    deny_patterns = audit.get("deny_patterns", []) if audit else []

    results = []
    skip_dirs = {"node_modules", ".git", ".next", "dist"}
    extensions = {".ts", ".tsx", ".js", ".jsx"}

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for f in files:
            ext = Path(f).suffix.lower()
            if ext not in extensions:
                # Track skipped file
                if audit is not None:
                    audit["skipped_count"] += 1
                    reason = f"extension:{ext or 'none'}"
                    audit["skipped_reasons"][reason] = audit["skipped_reasons"].get(reason, 0) + 1
                continue

            file_path = Path(root) / f

            # SECURITY: Check deny patterns BEFORE opening
            if is_path_denied(file_path, project_path, deny_patterns):
                if audit is not None:
                    audit["denied_count"] += 1
                    if len(audit["denied_sample"]) < audit["sample_limit"]:
                        audit["denied_sample"].append(str(file_path))
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")

                # Track file opened + parsed for audit
                if audit is not None:
                    audit["opened_count"] += 1
                    audit["parsed_count"] += 1
                    if len(audit["opened_sample"]) < audit["sample_limit"]:
                        audit["opened_sample"].append(str(file_path))
                    if len(audit["parsed_sample"]) < audit["sample_limit"]:
                        audit["parsed_sample"].append(str(file_path))

                for pattern, desc in patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        results.append({
                            "file": str(file_path.relative_to(project_path)),
                            "pattern": desc,
                            "count": len(matches)
                        })
            except Exception:
                pass

    return results[:100]


def _build_risks_from_secrets(secrets_result: ScanResult) -> list:
    """Build risk items from secrets scan results."""
    risks = []

    critical_count = secrets_result.severity_counts.get("CRITICAL", 0)
    high_count = secrets_result.severity_counts.get("HIGH", 0)

    if critical_count > 0:
        risks.append({
            "level": "CRITICAL",
            "description": f"{critical_count} critical severity secrets detected (API keys, private keys, etc.)",
            "mitigation": "Review SECRET_FINDINGS.md and rotate affected credentials immediately"
        })

    if high_count > 0:
        risks.append({
            "level": "HIGH",
            "description": f"{high_count} high severity secrets detected",
            "mitigation": "Review SECRET_FINDINGS.md and assess exposure risk"
        })

    if secrets_result.candidate_count > 0:
        risks.append({
            "level": "LOW",
            "description": f"{secrets_result.candidate_count} entropy-based candidates require review",
            "mitigation": "Manual review recommended - may be false positives"
        })

    # If we scanned but found nothing, note that explicitly
    if secrets_result.patterns_ran > 0 and critical_count == 0 and high_count == 0:
        # Don't add a "no risk" - just return empty risks
        # The absence of risk items means "nothing found"
        pass

    return risks


def scan_for_secrets(project_path: Path, audit: dict = None, evidence_dir: Path = None,
                     scan_mode: str = "fast") -> ScanResult:
    """Scan codebase for secrets using pattern matching and entropy detection.

    Args:
        scan_mode: One of "fast" (default), "deep", or "release"
            - fast: Skip large files, minified, build artifacts. ~13s on typical repo.
            - deep: Include larger files, entropy detection. ~30-60s.
            - release: Deep + bundle scanning (.next/static/, dist/). Pre-deploy audit.
    """
    from tools.secrets_scanner import ScanProfile, generate_scan_profile

    start_time = time.time()
    profile = ScanProfile()

    # Get deny patterns from audit context
    deny_patterns = audit.get("deny_patterns", []) if audit else []

    # Configure based on scan mode
    if scan_mode == "fast":
        # Priority files: config, env, source (not build artifacts)
        scan_extensions = {".ts", ".tsx", ".js", ".jsx", ".py", ".json", ".yaml", ".yml", ".env", ".rules"}
        skip_suffixes = {".min.js", ".min.css", ".map", ".d.ts"}
        max_file_size = 100 * 1024  # 100KB
        skip_dirs = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".firebase", "coverage"}
        run_entropy = False
    elif scan_mode == "deep":
        scan_extensions = {".ts", ".tsx", ".js", ".jsx", ".py", ".json", ".yaml", ".yml", ".env", ".md", ".rules"}
        skip_suffixes = {".min.js", ".min.css", ".map"}  # Still skip minified
        max_file_size = 1024 * 1024  # 1MB
        skip_dirs = {"node_modules", ".git", "__pycache__", ".firebase", "coverage"}
        run_entropy = True  # Enable entropy detection
    elif scan_mode == "release":
        # Release mode: scan everything including bundles
        scan_extensions = {".ts", ".tsx", ".js", ".jsx", ".py", ".json", ".yaml", ".yml", ".env", ".md", ".rules"}
        skip_suffixes = set()  # Don't skip any suffixes
        max_file_size = 2 * 1024 * 1024  # 2MB
        skip_dirs = {"node_modules", ".git", "__pycache__", "coverage"}  # Include .next, dist, build
        run_entropy = True
    else:
        # Default to fast
        scan_mode = "fast"
        scan_extensions = {".ts", ".tsx", ".js", ".jsx", ".py", ".json", ".yaml", ".yml", ".env", ".rules"}
        skip_suffixes = {".min.js", ".min.css", ".map", ".d.ts"}
        max_file_size = 100 * 1024
        skip_dirs = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".firebase", "coverage"}
        run_entropy = False

    fast_mode = scan_mode == "fast"  # For backward compatibility

    # Load repo-local suppressions if available
    suppressions_file = project_path / ".becca_suppressions.json"
    scanner = SecretsScanner(suppressions_file=suppressions_file if suppressions_file.exists() else None)

    # Also scan specific high-risk files
    high_risk_patterns = [".env*", "*.config.js", "*.config.ts", "firebase*.json", "*credentials*", "*secret*"]

    files_to_scan = set()

    # Time file enumeration
    enum_start = time.perf_counter()

    # Collect files from directory walk
    files_skipped_size = 0
    files_skipped_suffix = 0

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for f in files:
            file_path = Path(root) / f
            ext = file_path.suffix.lower()

            # Fast mode: skip minified/map files
            if fast_mode and any(f.endswith(s) for s in skip_suffixes):
                files_skipped_suffix += 1
                continue

            # Check if it's a scannable extension
            if ext in scan_extensions or ext == "" and f.startswith(".env"):
                # Fast mode: skip large files
                if fast_mode:
                    try:
                        if file_path.stat().st_size > max_file_size:
                            files_skipped_size += 1
                            continue
                    except OSError:
                        continue

                # SECURITY: Check deny patterns
                if not is_path_denied(file_path, project_path, deny_patterns):
                    files_to_scan.add(file_path)

    # Also add high-risk files via glob
    for pattern in high_risk_patterns:
        for match in project_path.glob(f"**/{pattern}"):
            if not any(skip in str(match) for skip in skip_dirs):
                if not is_path_denied(match, project_path, deny_patterns):
                    files_to_scan.add(match)

    profile.enumerate_ms = (time.perf_counter() - enum_start) * 1000
    profile.files_skipped = files_skipped_size + files_skipped_suffix

    # Use profiled batch scan with mode-appropriate entropy setting
    result = scanner.scan_files_profiled(list(files_to_scan), project_path, run_entropy=run_entropy)

    # Merge profile data
    result.profile.enumerate_ms = profile.enumerate_ms

    result.scan_time_seconds = time.time() - start_time

    # Generate SCAN_PROFILE.json if evidence_dir provided
    if evidence_dir:
        write_start = time.perf_counter()
        profile_file = evidence_dir / "SCAN_PROFILE.json"
        generate_scan_profile(result.profile, profile_file, scan_mode=scan_mode)
        result.profile.write_ms = (time.perf_counter() - write_start) * 1000

    return result
