#!/usr/bin/env python3
"""
propose_profit_guardrails.py - PROPOSE tool for profit protection

Scans codebase for variable cost vectors and generates proposals to:
  1. Add per-tenant quotas (daily/monthly limits)
  2. Implement rate limiting / backoff
  3. Add "degraded mode" fallbacks
  4. Insert monitoring hooks (counters, alerts)

Cost Vectors Detected:
  - SMS (Twilio, etc.)
  - Email (SendGrid, SES, etc.)
  - Voice/TTS (ElevenLabs, Google TTS, etc.)
  - Push notifications
  - Third-party API calls with per-call pricing
  - AI/LLM calls (OpenAI, Anthropic, etc.)

Usage:
    from tools.propose_profit_guardrails import ProfitGuardrailsProposer

    proposer = ProfitGuardrailsProposer(
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


# Canonical vector types - the only valid normalized types
CANONICAL_VECTORS = {"voice", "sms", "llm", "email", "push", "webhook", "api"}

# Map detected patterns to canonical types
VECTOR_ALIASES = {
    "tts": "voice",
    "speech": "voice",
    "text_to_speech": "voice",
    "twilio_voice": "voice",
    "elevenlabs": "voice",
    "google_tts": "voice",
    "openai_tts": "voice",
    "twilio_sms": "sms",
    "sns_sms": "sms",
    "openai_chat": "llm",
    "anthropic": "llm",
    "gemini": "llm",
    "google_gemini": "llm",
    "sendgrid": "email",
    "ses": "email",
    "aws_ses": "email",
    "nodemailer": "email",
    "smtp": "email",
    "fcm": "push",
    "firebase_fcm": "push",
    "apns": "push",
    "apple_apns": "push",
    "onesignal": "push",
    "stripe": "api",
    "google_maps": "api",
    "google_places": "api",
}


def normalize_vector_type(raw_type: str, provider: str = None) -> str:
    """Normalize a detected vector type to a canonical type."""
    # First check if the raw type is already canonical
    if raw_type in CANONICAL_VECTORS:
        return raw_type

    # Check aliases for the raw type
    if raw_type in VECTOR_ALIASES:
        return VECTOR_ALIASES[raw_type]

    # Check aliases for the provider
    if provider and provider in VECTOR_ALIASES:
        return VECTOR_ALIASES[provider]

    # Default to 'api' for unknown types
    return "api"


@dataclass
class CostVector:
    """A detected variable cost call site."""
    file_path: str
    line_number: int
    cost_type: str  # raw detected type
    provider: str  # twilio, sendgrid, elevenlabs, openai, etc.
    pattern_name: str
    context_line: str
    estimated_cost_per_call: str  # e.g., "$0.0075/segment", "$0.01/email"
    has_rate_limit: bool = False
    has_quota_check: bool = False
    has_error_handling: bool = False
    risk_level: str = "medium"  # low, medium, high, critical
    guardrails_detected: list = field(default_factory=list)  # ["quota", "rate_limit", "backoff", "fallback"]

    @property
    def canonical_type(self) -> str:
        """Return the normalized canonical vector type."""
        return normalize_vector_type(self.cost_type, self.provider)

    @property
    def has_guardrail(self) -> bool:
        """Return True if any guardrail is in place."""
        return self.has_quota_check or self.has_rate_limit or len(self.guardrails_detected) > 0


# Cost vector detection patterns
COST_PATTERNS = [
    # SMS Providers
    {
        "name": "twilio_sms",
        "pattern": r"(?:twilio|client)\.messages\.create|sendSms|sendMessage.*twilio",
        "type": "sms",
        "provider": "twilio",
        "cost_estimate": "$0.0079/segment",
        "risk": "high",
    },
    {
        "name": "twilio_import",
        "pattern": r"from\s+twilio|require\(['\"]twilio|import.*Twilio",
        "type": "sms",
        "provider": "twilio",
        "cost_estimate": "$0.0079/segment",
        "risk": "medium",
    },
    {
        "name": "sns_sms",
        "pattern": r"sns\.publish.*PhoneNumber|SNS.*SMS",
        "type": "sms",
        "provider": "aws_sns",
        "cost_estimate": "$0.00645/message",
        "risk": "high",
    },

    # Email Providers
    {
        "name": "sendgrid_send",
        "pattern": r"sgMail\.send|sendgrid.*send|\.send\(.*SendGridAPIClient",
        "type": "email",
        "provider": "sendgrid",
        "cost_estimate": "$0.00035/email",
        "risk": "medium",
    },
    {
        "name": "sendgrid_import",
        "pattern": r"@sendgrid/mail|sendgrid|SendGridAPIClient",
        "type": "email",
        "provider": "sendgrid",
        "cost_estimate": "$0.00035/email",
        "risk": "low",
    },
    {
        "name": "ses_send",
        "pattern": r"ses\.sendEmail|SES\.send|sesClient\.send",
        "type": "email",
        "provider": "aws_ses",
        "cost_estimate": "$0.0001/email",
        "risk": "medium",
    },
    {
        "name": "nodemailer",
        "pattern": r"transporter\.sendMail|nodemailer.*send",
        "type": "email",
        "provider": "smtp",
        "cost_estimate": "varies",
        "risk": "medium",
    },

    # Voice/TTS Providers
    {
        "name": "elevenlabs_tts",
        "pattern": r"elevenlabs|eleven_labs|ElevenLabs|textToSpeech.*eleven",
        "type": "voice",
        "provider": "elevenlabs",
        "cost_estimate": "$0.30/1K chars",
        "risk": "critical",
    },
    {
        "name": "google_tts",
        "pattern": r"texttospeech\.TextToSpeechClient|google.*tts|synthesize_speech",
        "type": "voice",
        "provider": "google_tts",
        "cost_estimate": "$0.000004/char",
        "risk": "high",
    },
    {
        "name": "openai_tts",
        "pattern": r"openai.*audio.*speech|client\.audio\.speech",
        "type": "voice",
        "provider": "openai_tts",
        "cost_estimate": "$0.015/1K chars",
        "risk": "high",
    },
    {
        "name": "twilio_voice",
        "pattern": r"twilio.*calls\.create|makeCall.*twilio|Voice.*twilio",
        "type": "voice",
        "provider": "twilio_voice",
        "cost_estimate": "$0.014/min",
        "risk": "critical",
    },

    # Push Notifications
    {
        "name": "fcm_push",
        "pattern": r"firebase.*messaging|admin\.messaging|sendToDevice|sendMulticast",
        "type": "push",
        "provider": "firebase_fcm",
        "cost_estimate": "free (quota limits)",
        "risk": "low",
    },
    {
        "name": "apns_push",
        "pattern": r"apns|APNs|apple.*push",
        "type": "push",
        "provider": "apple_apns",
        "cost_estimate": "free",
        "risk": "low",
    },
    {
        "name": "onesignal",
        "pattern": r"onesignal|OneSignal",
        "type": "push",
        "provider": "onesignal",
        "cost_estimate": "$0.0005/notification",
        "risk": "medium",
    },

    # AI/LLM Providers
    {
        "name": "openai_chat",
        "pattern": r"openai.*chat\.completions|createChatCompletion|ChatCompletion\.create",
        "type": "llm",
        "provider": "openai",
        "cost_estimate": "$0.002-0.06/1K tokens",
        "risk": "high",
    },
    {
        "name": "openai_client",
        "pattern": r"new\s+OpenAI|OpenAI\(\)|from\s+openai",
        "type": "llm",
        "provider": "openai",
        "cost_estimate": "$0.002-0.06/1K tokens",
        "risk": "medium",
    },
    {
        "name": "anthropic_claude",
        "pattern": r"anthropic|Anthropic|claude.*messages|messages\.create.*claude",
        "type": "llm",
        "provider": "anthropic",
        "cost_estimate": "$0.003-0.075/1K tokens",
        "risk": "high",
    },
    {
        "name": "google_gemini",
        "pattern": r"gemini|GenerativeModel|google.*generative",
        "type": "llm",
        "provider": "google_gemini",
        "cost_estimate": "$0.00025-0.005/1K chars",
        "risk": "medium",
    },

    # Third-party APIs with per-call costs
    {
        "name": "stripe_api",
        "pattern": r"stripe\.charges|stripe\.paymentIntents|Stripe\(",
        "type": "api",
        "provider": "stripe",
        "cost_estimate": "2.9% + $0.30/txn",
        "risk": "critical",
    },
    {
        "name": "maps_api",
        "pattern": r"maps\.googleapis|google.*maps.*api|geocode|directions",
        "type": "api",
        "provider": "google_maps",
        "cost_estimate": "$0.005-0.02/request",
        "risk": "medium",
    },
    {
        "name": "places_api",
        "pattern": r"places\.googleapis|google.*places",
        "type": "api",
        "provider": "google_places",
        "cost_estimate": "$0.017/request",
        "risk": "medium",
    },
]

# Patterns that indicate existing guardrails
GUARDRAIL_PATTERNS = {
    "rate_limit": [
        r"rateLimit",
        r"rateLimiter",
        r"throttle",
        r"cooldown",
        r"backoff",
        r"retry.*delay",
        r"requestsPerMinute",
        r"tokensPerMinute",
    ],
    "quota": [
        r"quota",
        r"dailyLimit",
        r"monthlyLimit",
        r"usageLimit",
        r"maxMessages",
        r"maxEmails",
        r"maxCalls",
        r"checkUsage",
        r"withinBudget",
    ],
    "error_handling": [
        r"try\s*{|try:",
        r"catch\s*\(",
        r"except\s",
        r"\.catch\(",
        r"on_error",
        r"handleError",
    ],
}

# Files to skip
SKIP_PATTERNS = [
    r"\.git[/\\]",
    r"node_modules[/\\]",
    r"__pycache__[/\\]",
    r"\.test\.",
    r"\.spec\.",
    r"test[/\\]",
    r"tests[/\\]",
    r"__tests__[/\\]",
    r"\.mock\.",
    r"\.d\.ts$",
]

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".mjs", ".cjs",
}


class ProfitGuardrailsProposer(ProposeTool):
    """
    PROPOSE tool that scans for unprotected cost vectors and generates
    proposals to add quotas, rate limits, and monitoring.
    """

    TOOL_NAME = "propose_profit_guardrails"
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
        cost_threshold: str = "medium",  # Only report findings >= this risk
    ):
        super().__init__(project_path, run_dir, plan_id, task_id, evidence_dir)
        self.scan_paths = scan_paths or ["."]
        self.exclude_patterns = exclude_patterns or []
        self.cost_threshold = cost_threshold
        self.findings: list[CostVector] = []

    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped."""
        # Use relative path from project root for pattern matching
        try:
            relative_path = file_path.relative_to(self.project_path)
            path_str = str(relative_path)
        except ValueError:
            path_str = str(file_path)

        for pattern in SKIP_PATTERNS:
            if re.search(pattern, path_str):
                return True

        for pattern in self.exclude_patterns:
            if re.search(pattern, path_str):
                return True

        if file_path.suffix.lower() not in SCAN_EXTENSIONS:
            return True

        return False

    def _risk_rank(self, risk: str) -> int:
        """Get numeric rank for risk comparison."""
        ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return ranks.get(risk, 0)

    def _check_guardrails(self, content: str, line_start: int, line_end: int) -> dict:
        """Check if existing guardrails exist near the cost vector."""
        # Get context (20 lines before and after)
        lines = content.splitlines()
        context_start = max(0, line_start - 20)
        context_end = min(len(lines), line_end + 20)
        context = "\n".join(lines[context_start:context_end])

        results = {
            "has_rate_limit": False,
            "has_quota_check": False,
            "has_error_handling": False,
            "guardrails_detected": [],  # List of detected guardrail types
        }

        for guardrail_type, patterns in GUARDRAIL_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, context, re.IGNORECASE):
                    if guardrail_type == "rate_limit":
                        results["has_rate_limit"] = True
                        if "rate_limit" not in results["guardrails_detected"]:
                            results["guardrails_detected"].append("rate_limit")
                    elif guardrail_type == "quota":
                        results["has_quota_check"] = True
                        if "quota" not in results["guardrails_detected"]:
                            results["guardrails_detected"].append("quota")
                    elif guardrail_type == "error_handling":
                        results["has_error_handling"] = True
                        if "error_handling" not in results["guardrails_detected"]:
                            results["guardrails_detected"].append("error_handling")

        # Check for additional guardrail patterns
        if re.search(r"backoff|exponential.*retry|retry.*exponential", context, re.IGNORECASE):
            if "backoff" not in results["guardrails_detected"]:
                results["guardrails_detected"].append("backoff")

        if re.search(r"fallback|degraded|failover|alternative", context, re.IGNORECASE):
            if "fallback" not in results["guardrails_detected"]:
                results["guardrails_detected"].append("fallback")

        return results

    def _scan_file(self, file_path: Path) -> list[CostVector]:
        """Scan a single file for cost vectors."""
        findings = []
        relative_path = str(file_path.relative_to(self.project_path))

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            return findings

        for pattern_info in COST_PATTERNS:
            # Skip if below risk threshold
            if self._risk_rank(pattern_info["risk"]) < self._risk_rank(self.cost_threshold):
                continue

            pattern = re.compile(pattern_info["pattern"], re.IGNORECASE)

            for line_num, line in enumerate(lines, 1):
                # Skip comment lines
                stripped = line.strip()
                if stripped.startswith(("#", "//", "*", "/*")):
                    continue

                matches = pattern.finditer(line)
                for match in matches:
                    # Check for existing guardrails
                    guardrails = self._check_guardrails(content, line_num - 1, line_num)

                    finding = CostVector(
                        file_path=relative_path,
                        line_number=line_num,
                        cost_type=pattern_info["type"],
                        provider=pattern_info["provider"],
                        pattern_name=pattern_info["name"],
                        context_line=line[:150] + ("..." if len(line) > 150 else ""),
                        estimated_cost_per_call=pattern_info["cost_estimate"],
                        has_rate_limit=guardrails["has_rate_limit"],
                        has_quota_check=guardrails["has_quota_check"],
                        has_error_handling=guardrails["has_error_handling"],
                        risk_level=pattern_info["risk"],
                        guardrails_detected=guardrails["guardrails_detected"],
                    )
                    findings.append(finding)

        return findings

    def _scan_codebase(self) -> list[CostVector]:
        """Scan entire codebase for cost vectors."""
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

        # Deduplicate
        seen = set()
        unique_findings = []
        for f in all_findings:
            key = (f.file_path, f.line_number, f.pattern_name)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def _calculate_risk_score(self) -> dict:
        """Calculate overall cost risk score with cost-per-order narrative."""
        if not self.findings:
            return {
                "score": 0,
                "grade": "A",
                "monthly_risk": "$0",
                "cost_per_order": "$0.00",
                "worst_case_monthly": "$0",
                "cost_narrative": "No variable cost vectors detected.",
            }

        # Count unprotected vectors by risk level
        unprotected = [f for f in self.findings if not f.has_quota_check and not f.has_rate_limit]

        critical_count = len([f for f in unprotected if f.risk_level == "critical"])
        high_count = len([f for f in unprotected if f.risk_level == "high"])
        medium_count = len([f for f in unprotected if f.risk_level == "medium"])

        # Calculate score (0-100, higher = more risk)
        score = min(100, (critical_count * 25) + (high_count * 10) + (medium_count * 3))

        # Grade
        if score >= 70:
            grade = "F"
        elif score >= 50:
            grade = "D"
        elif score >= 30:
            grade = "C"
        elif score >= 15:
            grade = "B"
        else:
            grade = "A"

        # Cost-per-order estimation (assumes typical order flow)
        # These are rough per-call costs
        cost_per_call = {
            "sms": 0.01,          # ~$0.01/message (Twilio US)
            "email": 0.0004,      # ~$0.0004/email (SendGrid)
            "voice": 0.30,        # ~$0.30/1K chars ElevenLabs (~300 chars/greeting = $0.09)
            "llm": 0.02,          # ~$0.02/request (GPT-4, typical)
            "api": 0.01,          # varies widely
            "push": 0.0,          # free
        }

        # Estimate calls per order by type
        calls_per_order = {
            "sms": 2,             # confirmation + delivery update
            "email": 1,           # receipt
            "voice": 1,           # greeting/confirmation TTS
            "llm": 3,             # menu questions, order confirm, etc.
            "api": 1,             # payment
            "push": 2,            # updates
        }

        # Calculate cost per order from unprotected vectors
        order_cost = 0.0
        cost_breakdown = {}

        for f in unprotected:
            cost_type = f.cost_type
            per_call = cost_per_call.get(cost_type, 0.01)
            per_order = per_call * calls_per_order.get(cost_type, 1)

            if cost_type not in cost_breakdown:
                cost_breakdown[cost_type] = 0.0
            cost_breakdown[cost_type] += per_order
            order_cost += per_order

        # Monthly estimates at different volumes
        orders_per_month = {
            "low": 500,
            "medium": 2000,
            "high": 10000,
        }

        monthly_at_medium = order_cost * orders_per_month["medium"]

        # Worst case: unmetered runaway (10x normal + attack scenario)
        worst_case_multiplier = 50  # Bug or attack could cause 50x normal
        worst_case_monthly = order_cost * orders_per_month["high"] * worst_case_multiplier

        # Build cost narrative
        narrative_parts = []

        if critical_count > 0:
            narrative_parts.append(f"CRITICAL: {critical_count} unprotected high-cost vectors (voice/TTS, billing)")

        # Identify biggest cost driver
        if cost_breakdown:
            biggest_driver = max(cost_breakdown.items(), key=lambda x: x[1])
            driver_labels = {
                "voice": "Voice/TTS",
                "llm": "AI/LLM",
                "sms": "SMS",
                "email": "Email",
                "api": "Third-party API",
            }
            narrative_parts.append(
                f"Biggest cost driver: {driver_labels.get(biggest_driver[0], biggest_driver[0])} "
                f"(${biggest_driver[1]:.3f}/order)"
            )

        if worst_case_monthly > 1000:
            narrative_parts.append(
                f"WARNING RUNAWAY RISK: Unmetered vectors could cost ${worst_case_monthly:,.0f}/month if abused"
            )

        if not narrative_parts:
            narrative_parts.append("Low variable cost exposure.")

        return {
            "score": score,
            "grade": grade,
            "monthly_risk": f"${monthly_at_medium:,.0f}+ at 2K orders/mo",
            "cost_per_order": f"${order_cost:.3f}",
            "worst_case_monthly": f"${worst_case_monthly:,.0f}",
            "cost_breakdown": cost_breakdown,
            "unprotected_critical": critical_count,
            "unprotected_high": high_count,
            "unprotected_medium": medium_count,
            "cost_narrative": " | ".join(narrative_parts),
        }

    def generate_changes(self) -> list[FileChange]:
        """
        Generate file changes for profit guardrails.

        Identifies cost vectors and proposes guardrails.
        """
        self.findings = self._scan_codebase()

        if not self.findings:
            return []

        changes = []

        # Group findings by file
        findings_by_file: dict[str, list[CostVector]] = {}
        for finding in self.findings:
            if finding.file_path not in findings_by_file:
                findings_by_file[finding.file_path] = []
            findings_by_file[finding.file_path].append(finding)

        # For each file with unprotected cost vectors, create a change entry
        for file_path, file_findings in findings_by_file.items():
            unprotected = [f for f in file_findings if not f.has_quota_check]
            if not unprotected:
                continue

            full_path = self.project_path / file_path
            if not full_path.exists():
                continue

            try:
                original_content = full_path.read_text(encoding="utf-8")
            except Exception:
                continue

            # We document the findings but don't auto-modify
            # (cost guardrails require architectural decisions)
            change = FileChange(
                path=file_path,
                action="modify",
                before_content=original_content,
                after_content=original_content,  # No auto-modify
            )
            changes.append(change)

        return changes

    def get_title(self) -> str:
        """Return proposal title."""
        unprotected = [f for f in self.findings if not f.has_quota_check]
        risk_score = self._calculate_risk_score()

        return f"Add profit guardrails: {len(unprotected)} unprotected cost vectors (Grade: {risk_score['grade']})"

    def get_description(self) -> str:
        """Return detailed description."""
        if not self.findings:
            return "No variable cost vectors detected in the scanned codebase."

        risk_score = self._calculate_risk_score()
        unprotected = [f for f in self.findings if not f.has_quota_check]

        lines = [
            f"Detected {len(self.findings)} variable cost call sites, {len(unprotected)} without quota protection.",
            "",
            f"**Risk Score:** {risk_score['score']}/100 (Grade: {risk_score['grade']})",
            f"**Monthly Risk:** {risk_score['monthly_risk']}",
            "",
            "**Findings by cost type:**",
        ]

        # Group by type
        by_type: dict[str, list[CostVector]] = {}
        for f in self.findings:
            if f.cost_type not in by_type:
                by_type[f.cost_type] = []
            by_type[f.cost_type].append(f)

        type_labels = {
            "sms": "SMS",
            "email": "Email",
            "voice": "Voice/TTS",
            "llm": "AI/LLM",
            "api": "Third-Party API",
            "push": "Push Notifications",
        }

        for cost_type, type_findings in sorted(by_type.items(), key=lambda x: -len(x[1])):
            unprotected_count = len([f for f in type_findings if not f.has_quota_check])
            label = type_labels.get(cost_type, cost_type.upper())
            lines.append(f"- **{label}**: {len(type_findings)} sites ({unprotected_count} unprotected)")

        lines.extend([
            "",
            "**Files requiring attention:**",
        ])

        files = set(f.file_path for f in unprotected)
        for file_path in sorted(files)[:10]:
            count = len([f for f in unprotected if f.file_path == file_path])
            lines.append(f"- `{file_path}` ({count} unprotected)")

        if len(files) > 10:
            lines.append(f"- ... and {len(files) - 10} more files")

        return "\n".join(lines)

    def get_rationale(self) -> str:
        """Return rationale for guardrails."""
        return """Uncontrolled variable costs are a common profit killer for SaaS:

1. **Runaway costs**: A bug or attack can trigger thousands of SMS/voice calls,
   draining the account in hours.

2. **No visibility**: Without metering, you can't track per-tenant costs or
   identify abuse patterns.

3. **No graceful degradation**: When limits are hit, the system crashes instead
   of falling back to cheaper channels.

4. **Customer surprise bills**: If you pass costs through, customers get shocked.

**Recommended guardrails:**

1. **Per-tenant quotas** (daily/monthly limits by cost type)
   - SMS: 100/day, 1000/month
   - Email: 1000/day, 10000/month
   - Voice/TTS: 50/day, 500/month
   - LLM: Token budget per tenant

2. **Rate limiting** (requests per minute)
   - Prevent burst abuse
   - Implement exponential backoff

3. **Degraded mode fallbacks**
   - SMS blocked → fall back to email
   - Voice TTS blocked → fall back to browser TTS
   - Premium LLM blocked → fall back to smaller model

4. **Monitoring and alerts**
   - Track usage per tenant
   - Alert at 80% quota
   - Daily cost reports

**IMPORTANT**: This proposal identifies cost vectors but does NOT auto-implement
guardrails. Quota decisions require business input on acceptable limits."""

    def get_risk_classification(self) -> str:
        """Return risk classification based on findings."""
        risk_score = self._calculate_risk_score()

        if risk_score["score"] >= 50:
            return "critical"
        elif risk_score["score"] >= 30:
            return "high"
        elif risk_score["score"] >= 15:
            return "medium"
        return "low"

    def get_tests_to_run(self) -> list[str]:
        """Return tests to verify guardrails."""
        return [
            "grep -r 'quota\\|rateLimit\\|dailyLimit' --include='*.ts' --include='*.js'",
            "npm test -- --grep 'rate limit\\|quota'",
        ]

    def get_evidence_ids(self) -> list[str]:
        """Return evidence IDs supporting this proposal."""
        return [f"COST-SCAN-{self.task_id}"]

    def _generate_findings_report(self) -> str:
        """Generate detailed findings report."""
        if not self.findings:
            return "No cost vectors detected."

        risk_score = self._calculate_risk_score()

        lines = [
            "# Profit Guardrails Report",
            "",
            f"**Scan Date:** {self.proposal.created_at if self.proposal else 'N/A'}",
            f"**Total Cost Vectors:** {len(self.findings)}",
            f"**Risk Score:** {risk_score['score']}/100 (Grade: {risk_score['grade']})",
            f"**Monthly Risk:** {risk_score['monthly_risk']}",
            "",
            "---",
            "",
            "## Summary by Provider",
            "",
        ]

        # Group by provider
        by_provider: dict[str, list[CostVector]] = {}
        for f in self.findings:
            if f.provider not in by_provider:
                by_provider[f.provider] = []
            by_provider[f.provider].append(f)

        for provider, findings in sorted(by_provider.items(), key=lambda x: -len(x[1])):
            unprotected = len([f for f in findings if not f.has_quota_check])
            protected = len(findings) - unprotected

            lines.extend([
                f"### {provider.replace('_', ' ').title()}",
                "",
                f"- **Total sites:** {len(findings)}",
                f"- **Protected:** {protected}",
                f"- **Unprotected:** {unprotected}",
                f"- **Est. cost:** {findings[0].estimated_cost_per_call}",
                "",
            ])

        lines.extend([
            "---",
            "",
            "## Detailed Findings",
            "",
        ])

        # Group by file
        by_file: dict[str, list[CostVector]] = {}
        for f in self.findings:
            if f.file_path not in by_file:
                by_file[f.file_path] = []
            by_file[f.file_path].append(f)

        for file_path in sorted(by_file.keys()):
            file_findings = by_file[file_path]
            lines.extend([
                f"### `{file_path}`",
                "",
            ])

            for finding in sorted(file_findings, key=lambda x: x.line_number):
                risk_emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢"
                }.get(finding.risk_level, "⚪")

                protection_status = []
                if finding.has_quota_check:
                    protection_status.append("✅ quota")
                if finding.has_rate_limit:
                    protection_status.append("✅ rate-limit")
                if finding.has_error_handling:
                    protection_status.append("✅ error-handling")

                if not protection_status:
                    protection_status = ["❌ UNPROTECTED"]

                lines.extend([
                    f"**Line {finding.line_number}** {risk_emoji} {finding.risk_level.upper()}",
                    "",
                    f"- **Type:** {finding.cost_type}",
                    f"- **Provider:** {finding.provider}",
                    f"- **Est. cost:** {finding.estimated_cost_per_call}",
                    f"- **Protection:** {' | '.join(protection_status)}",
                    "",
                    "```",
                    finding.context_line,
                    "```",
                    "",
                ])

        # Recommendations
        lines.extend([
            "---",
            "",
            "## Recommended Actions",
            "",
            "### Immediate (Critical/High Risk)",
            "",
        ])

        critical_high = [f for f in self.findings
                        if f.risk_level in ("critical", "high") and not f.has_quota_check]

        if critical_high:
            for f in critical_high[:5]:
                lines.append(f"1. Add quota check to `{f.file_path}:{f.line_number}` ({f.provider})")
        else:
            lines.append("No critical/high risk unprotected vectors found.")

        lines.extend([
            "",
            "### Short-term (All Unprotected)",
            "",
            "1. Implement per-tenant usage tracking collection",
            "2. Add quota configuration to tenant settings",
            "3. Create quota enforcement middleware",
            "4. Set up usage alerts at 80% threshold",
            "",
            "### Long-term (Architecture)",
            "",
            "1. Centralize all external service calls through a cost-aware gateway",
            "2. Implement circuit breakers for cost protection",
            "3. Add degraded mode fallbacks for each cost vector",
            "4. Create cost dashboard for operations monitoring",
        ])

        return "\n".join(lines)

    def write_artifacts(self) -> dict:
        """Write proposal artifacts including findings report."""
        artifacts = super().write_artifacts()

        # Also write findings report
        if self.proposal and self.findings:
            report_path = self.evidence_dir / f"{self.proposal.proposal_id}-cost-report.md"
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(self._generate_findings_report())
            artifacts["cost_report"] = str(report_path)

        return artifacts
