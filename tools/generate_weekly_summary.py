#!/usr/bin/env python3
"""
Weekly Trend Summary Generator

Aggregates BECCA audit data to produce executive-level weekly metrics:
- Average scan time
- Profit risk grade distribution (A/B/C/D/F)
- Secrets findings count
- Top recurring cost vectors
- Week-over-week trends

Usage:
    python tools/generate_weekly_summary.py --project sonny
    python tools/generate_weekly_summary.py --project sonny --weeks 4
"""

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import defaultdict
from typing import Optional


class WeeklySummaryGenerator:
    """Generates weekly trend summaries from BECCA audit data."""

    def __init__(self, project_path: Path, weeks: int = 1):
        self.project_path = project_path
        self.weeks = weeks
        self.runs_dir = project_path / ".becca" / "runs"
        self.metrics_dir = project_path / "governance" / "metrics"

    def run(self) -> dict:
        """Generate weekly summary and return results."""
        # Ensure metrics directory exists
        self.metrics_dir.mkdir(parents=True, exist_ok=True)

        # Calculate date ranges
        now = datetime.now(timezone.utc)
        week_end = now
        week_start = now - timedelta(days=7 * self.weeks)

        # Collect all audit results in date range
        audits = self._collect_audits(week_start, week_end)

        if not audits:
            return self._empty_summary(week_start, week_end)

        # Aggregate metrics
        summary = self._aggregate_metrics(audits, week_start, week_end)

        # Calculate trends if we have previous data
        summary["trends"] = self._calculate_trends(summary)

        # Save summary
        output_path = self.metrics_dir / "weekly_summary.json"
        with open(output_path, "w") as f:
            json.dump(summary, f, indent=2)

        # Also save to history
        self._save_to_history(summary)

        return summary

    def _collect_audits(self, start: datetime, end: datetime) -> list:
        """Collect all audit results within date range."""
        audits = []

        if not self.runs_dir.exists():
            return audits

        for run_dir in self.runs_dir.iterdir():
            if not run_dir.is_dir():
                continue

            # Check for audit result files
            audit_file = run_dir / "AUDIT_RESULT.json"
            summary_file = run_dir / "RUN_SUMMARY.json"

            # Try to parse date from directory name (RUN-PROJECT-YYYYMMDD-HHMMSS)
            run_date = self._parse_run_date(run_dir.name)
            if run_date and start <= run_date <= end:
                audit_data = {}

                if audit_file.exists():
                    with open(audit_file) as f:
                        audit_data = json.load(f)
                        audit_data["_run_date"] = run_date.isoformat()
                        audit_data["_run_dir"] = str(run_dir)
                        audits.append(audit_data)
                elif summary_file.exists():
                    # Fall back to RUN_SUMMARY if no AUDIT_RESULT
                    with open(summary_file) as f:
                        summary_data = json.load(f)
                        audit_data = self._convert_summary_to_audit(summary_data)
                        audit_data["_run_date"] = run_date.isoformat()
                        audit_data["_run_dir"] = str(run_dir)
                        audits.append(audit_data)

        return audits

    def _parse_run_date(self, run_name: str) -> Optional[datetime]:
        """Parse datetime from run directory name."""
        # Format: RUN-PROJECT-YYYYMMDD-HHMMSS
        parts = run_name.split("-")
        if len(parts) >= 4:
            try:
                date_str = parts[-2]  # YYYYMMDD
                time_str = parts[-1]  # HHMMSS
                return datetime.strptime(f"{date_str}{time_str}", "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
            except (ValueError, IndexError):
                pass
        return None

    def _convert_summary_to_audit(self, summary: dict) -> dict:
        """Convert RUN_SUMMARY format to audit format."""
        return {
            "scan_time_ms": summary.get("performance", {}).get("total_ms", 0),
            "profit_risk": {
                "grade": "A",  # Default if not available
                "score": 0
            },
            "secrets": {
                "count": summary.get("risks", {}).get("total", 0)
            },
            "cost_vectors": []
        }

    def _aggregate_metrics(self, audits: list, start: datetime, end: datetime) -> dict:
        """Aggregate metrics from collected audits."""
        # Initialize counters
        total_scans = len(audits)
        scan_times = []
        grade_counts = defaultdict(int)
        total_secrets = 0
        vector_counts = defaultdict(int)

        for audit in audits:
            # Scan time
            scan_time = audit.get("scan_time_ms", 0)
            if scan_time > 0:
                scan_times.append(scan_time)

            # Profit risk grade
            profit_risk = audit.get("profit_risk", {})
            grade = profit_risk.get("grade", "A")
            grade_counts[grade] += 1

            # Secrets count
            secrets = audit.get("secrets", {})
            total_secrets += secrets.get("count", 0)

            # Cost vectors
            vectors = audit.get("cost_vectors", [])
            for vector in vectors:
                vector_type = vector.get("type", "unknown")
                vector_counts[vector_type] += 1

        # Calculate averages
        avg_scan_time = sum(scan_times) / len(scan_times) if scan_times else 0

        # Sort vectors by frequency
        top_vectors = sorted(
            vector_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        return {
            "schema_version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "period": {
                "start": start.isoformat() + "Z",
                "end": end.isoformat() + "Z",
                "weeks": self.weeks
            },
            "scan_metrics": {
                "total_scans": total_scans,
                "avg_scan_time_ms": round(avg_scan_time, 2),
                "avg_scan_time_seconds": round(avg_scan_time / 1000, 2)
            },
            "profit_risk_distribution": {
                "A": grade_counts.get("A", 0),
                "B": grade_counts.get("B", 0),
                "C": grade_counts.get("C", 0),
                "D": grade_counts.get("D", 0),
                "F": grade_counts.get("F", 0)
            },
            "secrets": {
                "total_findings": total_secrets,
                "per_scan_avg": round(total_secrets / total_scans, 2) if total_scans > 0 else 0
            },
            "top_cost_vectors": [
                {"type": v[0], "occurrences": v[1]} for v in top_vectors
            ],
            "health_score": self._calculate_health_score(
                grade_counts, total_secrets, total_scans
            )
        }

    def _calculate_health_score(
        self,
        grade_counts: dict,
        total_secrets: int,
        total_scans: int
    ) -> dict:
        """Calculate overall project health score (0-100)."""
        if total_scans == 0:
            return {"score": 100, "label": "No Data", "trend": "neutral"}

        # Weighted grade scoring
        grade_weights = {"A": 100, "B": 80, "C": 60, "D": 40, "F": 0}
        grade_total = sum(
            grade_weights.get(g, 0) * count
            for g, count in grade_counts.items()
        )
        grade_score = grade_total / total_scans if total_scans > 0 else 100

        # Penalty for secrets (5 points per secret, max 30 point penalty)
        secrets_penalty = min(total_secrets * 5, 30)

        # Final score
        final_score = max(0, min(100, grade_score - secrets_penalty))

        # Label
        if final_score >= 90:
            label = "Excellent"
        elif final_score >= 75:
            label = "Good"
        elif final_score >= 60:
            label = "Fair"
        elif final_score >= 40:
            label = "Needs Attention"
        else:
            label = "Critical"

        return {
            "score": round(final_score),
            "label": label,
            "components": {
                "grade_score": round(grade_score),
                "secrets_penalty": secrets_penalty
            }
        }

    def _calculate_trends(self, current: dict) -> dict:
        """Calculate week-over-week trends with confidence indicators."""
        history_file = self.metrics_dir / "weekly_history.json"

        # Determine sample size confidence
        current_scans = current["scan_metrics"]["total_scans"]
        if current_scans < 3:
            confidence = "low"
            confidence_note = f"Only {current_scans} scan(s) this week - trend confidence is low"
        elif current_scans < 5:
            confidence = "medium"
            confidence_note = f"{current_scans} scans this week - moderate confidence"
        else:
            confidence = "high"
            confidence_note = None

        if not history_file.exists():
            result = {
                "health_score": "neutral",
                "secrets": "neutral",
                "scan_count": "neutral",
                "confidence": confidence,
                "notes": "First week of data - no trend available"
            }
            if confidence_note:
                result["confidence_note"] = confidence_note
            return result

        with open(history_file) as f:
            history = json.load(f)

        if not history.get("summaries"):
            result = {
                "health_score": "neutral",
                "secrets": "neutral",
                "scan_count": "neutral",
                "confidence": confidence,
                "notes": "First week of data - no trend available"
            }
            if confidence_note:
                result["confidence_note"] = confidence_note
            return result

        # Get previous week
        prev = history["summaries"][-1]

        # Calculate trends
        def trend(current_val, prev_val, higher_is_better=True):
            if prev_val == 0:
                return "neutral"
            diff = current_val - prev_val
            if diff > 0:
                return "improving" if higher_is_better else "declining"
            elif diff < 0:
                return "declining" if higher_is_better else "improving"
            return "stable"

        current_health = current["health_score"]["score"]
        prev_health = prev.get("health_score", {}).get("score", 0)

        current_secrets = current["secrets"]["total_findings"]
        prev_secrets = prev.get("secrets", {}).get("total_findings", 0)

        prev_scans = prev.get("scan_metrics", {}).get("total_scans", 0)

        # Calculate 4-week moving average
        moving_avg = self._calculate_moving_average(history, current)

        result = {
            "health_score": trend(current_health, prev_health, higher_is_better=True),
            "health_delta": current_health - prev_health,
            "secrets": trend(current_secrets, prev_secrets, higher_is_better=False),
            "secrets_delta": current_secrets - prev_secrets,
            "scan_count": trend(current_scans, prev_scans, higher_is_better=True),
            "scan_delta": current_scans - prev_scans,
            "confidence": confidence,
            "moving_average_4wk": moving_avg,
            "previous_period": prev.get("period", {})
        }

        if confidence_note:
            result["confidence_note"] = confidence_note

        return result

    def _calculate_moving_average(self, history: dict, current: dict) -> dict:
        """Calculate 4-week moving average for health score."""
        summaries = history.get("summaries", [])

        # Include current week + up to 3 previous weeks
        recent_scores = [current["health_score"]["score"]]

        for summary in reversed(summaries[-3:]):
            score = summary.get("health_score", {}).get("score")
            if score is not None:
                recent_scores.append(score)

        if len(recent_scores) < 2:
            return {
                "health_score": current["health_score"]["score"],
                "weeks_included": 1,
                "note": "Insufficient history for moving average"
            }

        avg = sum(recent_scores) / len(recent_scores)

        return {
            "health_score": round(avg, 1),
            "weeks_included": len(recent_scores),
            "current_vs_avg": round(current["health_score"]["score"] - avg, 1)
        }

    def _save_to_history(self, summary: dict) -> None:
        """Save summary to historical record."""
        history_file = self.metrics_dir / "weekly_history.json"

        if history_file.exists():
            with open(history_file) as f:
                history = json.load(f)
        else:
            history = {
                "schema_version": "1.0.0",
                "summaries": []
            }

        # Keep only last 12 weeks
        history["summaries"].append({
            "generated_at": summary["generated_at"],
            "period": summary["period"],
            "scan_metrics": summary["scan_metrics"],
            "profit_risk_distribution": summary["profit_risk_distribution"],
            "secrets": summary["secrets"],
            "health_score": summary["health_score"]
        })
        history["summaries"] = history["summaries"][-12:]

        with open(history_file, "w") as f:
            json.dump(history, f, indent=2)

    def _empty_summary(self, start: datetime, end: datetime) -> dict:
        """Return empty summary when no data is available."""
        return {
            "schema_version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "period": {
                "start": start.isoformat() + "Z",
                "end": end.isoformat() + "Z",
                "weeks": self.weeks
            },
            "scan_metrics": {
                "total_scans": 0,
                "avg_scan_time_ms": 0,
                "avg_scan_time_seconds": 0
            },
            "profit_risk_distribution": {
                "A": 0, "B": 0, "C": 0, "D": 0, "F": 0
            },
            "secrets": {
                "total_findings": 0,
                "per_scan_avg": 0
            },
            "top_cost_vectors": [],
            "health_score": {
                "score": 100,
                "label": "No Data",
                "components": {"grade_score": 100, "secrets_penalty": 0}
            },
            "trends": {
                "health_score": "neutral",
                "secrets": "neutral",
                "scan_count": "neutral",
                "notes": "No audit data found for this period"
            }
        }

    def print_summary(self, summary: dict) -> None:
        """Print human-readable summary to console."""
        print("\n" + "=" * 60)
        print("BECCA WEEKLY TREND SUMMARY")
        print("=" * 60)

        period = summary["period"]
        print(f"\nPeriod: {period['start'][:10]} to {period['end'][:10]}")
        print(f"Generated: {summary['generated_at'][:19]}")

        # Health Score
        health = summary["health_score"]
        print(f"\n--- HEALTH SCORE ---")
        print(f"Score: {health['score']}/100 ({health['label']})")

        trends = summary.get("trends", {})
        if trends.get("health_delta"):
            delta = trends["health_delta"]
            direction = "+" if delta > 0 else ""
            print(f"Trend: {trends['health_score']} ({direction}{delta} from last week)")

        # Show 4-week moving average
        moving_avg = trends.get("moving_average_4wk", {})
        if moving_avg.get("weeks_included", 0) > 1:
            avg_score = moving_avg["health_score"]
            vs_avg = moving_avg.get("current_vs_avg", 0)
            vs_sign = "+" if vs_avg > 0 else ""
            print(f"4-Week Avg: {avg_score}/100 (current {vs_sign}{vs_avg} vs avg)")

        # Show confidence warning if low
        if trends.get("confidence") == "low":
            print(f"NOTE: {trends.get('confidence_note', 'Low sample size')}")

        # Scan Metrics
        scans = summary["scan_metrics"]
        print(f"\n--- SCAN METRICS ---")
        print(f"Total Scans: {scans['total_scans']}")
        print(f"Avg Scan Time: {scans['avg_scan_time_seconds']}s")

        # Profit Risk Distribution
        dist = summary["profit_risk_distribution"]
        print(f"\n--- PROFIT RISK GRADES ---")
        total = sum(dist.values())
        if total > 0:
            for grade in ["A", "B", "C", "D", "F"]:
                count = dist[grade]
                pct = (count / total * 100) if total > 0 else 0
                bar = "#" * int(pct / 5)
                print(f"  {grade}: {count:3d} ({pct:5.1f}%) {bar}")
        else:
            print("  No data")

        # Secrets
        secrets = summary["secrets"]
        print(f"\n--- SECRETS ---")
        print(f"Total Findings: {secrets['total_findings']}")
        print(f"Per-Scan Average: {secrets['per_scan_avg']}")

        if trends.get("secrets_delta"):
            delta = trends["secrets_delta"]
            direction = "+" if delta > 0 else ""
            status = "WARNING" if delta > 0 else "GOOD" if delta < 0 else ""
            print(f"Trend: {direction}{delta} from last week {status}")

        # Top Cost Vectors
        vectors = summary["top_cost_vectors"]
        print(f"\n--- TOP COST VECTORS ---")
        if vectors:
            for v in vectors:
                print(f"  {v['type']}: {v['occurrences']} occurrences")
        else:
            print("  None detected")

        print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Generate weekly trend summary from BECCA audit data"
    )
    parser.add_argument(
        "--project",
        type=str,
        default=".",
        help="Project path (default: current directory)"
    )
    parser.add_argument(
        "--weeks",
        type=int,
        default=1,
        help="Number of weeks to include (default: 1)"
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Output JSON only, no console summary"
    )

    args = parser.parse_args()

    project_path = Path(args.project).resolve()

    generator = WeeklySummaryGenerator(
        project_path=project_path,
        weeks=args.weeks
    )

    summary = generator.run()

    if args.json_only:
        print(json.dumps(summary, indent=2))
    else:
        generator.print_summary(summary)
        print(f"\nSaved to: {generator.metrics_dir / 'weekly_summary.json'}")


if __name__ == "__main__":
    main()
