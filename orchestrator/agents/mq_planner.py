#!/usr/bin/env python3
"""
mq_planner.py - MQ (Mission Queue) Planner

The MQ Planner converts missions into executable PLAN.json files.
It analyzes the mission, selects appropriate tools, and generates
task sequences with proper dependencies.

Protocol:
  1. Parse mission statement
  2. Extract intent and keywords
  3. Select tools and profiles (Ants)
  4. Generate ordered task list
  5. Define dependencies
  6. Set appropriate stop conditions
  7. Write PLAN.json

Supported Mission Types:
  - Security: secrets, access control, injection
  - Quality: errors, console, performance
  - Structure: architecture, dependencies, coverage

Usage:
    from orchestrator.agents.mq_planner import MQPlanner

    planner = MQPlanner(mission, project, run_id)
    plan = planner.generate_plan()
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class MissionIntent:
    """Parsed intent from a mission statement."""
    category: str  # security, quality, structure
    subcategory: str  # secrets, errors, architecture, etc.
    keywords: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)  # specific files/paths
    urgency: str = "normal"  # low, normal, high, critical


# Mission patterns for intent detection
MISSION_PATTERNS = {
    "security": {
        "secrets": [
            r"secret[s]?",
            r"api[\s-]?key[s]?",
            r"credential[s]?",
            r"password[s]?",
            r"token[s]?",
            r"private[\s-]?key[s]?",
            r"hardcoded",
            r"leak[s]?",
            r"exposure",
        ],
        "access_control": [
            r"firestore[\s-]?rules?",
            r"security[\s-]?rules?",
            r"permission[s]?",
            r"access[\s-]?control",
            r"authorization",
            r"authentication",
            r"tenant[\s-]?isolation",
        ],
        "injection": [
            r"injection",
            r"xss",
            r"sql[\s-]?injection",
            r"sanitiz",
            r"escap",
        ],
    },
    "quality": {
        "errors": [
            r"error[s]?",
            r"exception[s]?",
            r"console[\s-]?log",
            r"bug[s]?",
            r"crash",
            r"fail",
        ],
        "performance": [
            r"performance",
            r"slow",
            r"optimi[sz]",
            r"latency",
            r"bundle[\s-]?size",
        ],
        "testing": [
            r"test[s]?",
            r"coverage",
            r"unit[\s-]?test",
            r"integration[\s-]?test",
        ],
    },
    "structure": {
        "architecture": [
            r"architect",
            r"structure",
            r"pattern[s]?",
            r"design",
            r"refactor",
        ],
        "dependencies": [
            r"dependenc",
            r"import[s]?",
            r"package[s]?",
            r"node_modules",
            r"npm",
        ],
    },
    "scout": {
        "launch_readiness": [
            r"launch",
            r"ready",
            r"readiness",
            r"100k",
            r"scale",
            r"production",
            r"deploy",
            r"go[\s-]?live",
        ],
        "assessment": [
            r"scout",
            r"assess",
            r"audit",
            r"review",
            r"analyze",
            r"evaluation",
            r"reconnaissance",
            r"recon",
        ],
        "saas": [
            r"saas",
            r"multi[\s-]?tenant",
            r"tenant",
            r"subscription",
            r"billing",
            r"customer",
            r"client[\s-]?ready",
        ],
    },
}

# Tool selection based on intent
INTENT_TOOLS = {
    ("security", "secrets"): [
        {"tool": "secrets_scanner", "profile": "Fire Ant", "priority": 1},
        {"tool": "inspector", "profile": "Scout", "priority": 2},
    ],
    ("security", "access_control"): [
        {"tool": "rules_auditor", "profile": "Fire Ant", "priority": 1},
        {"tool": "inspector", "profile": "Scout", "priority": 2},
    ],
    ("security", "injection"): [
        {"tool": "inspector", "profile": "Fire Ant", "priority": 1},
    ],
    ("quality", "errors"): [
        {"tool": "inspector", "profile": "Mechanic", "priority": 1},
        {"tool": "browser", "profile": "Scout", "priority": 2},
    ],
    ("quality", "performance"): [
        {"tool": "inspector", "profile": "Mechanic", "priority": 1},
        {"tool": "browser", "profile": "Scout", "priority": 2},
    ],
    ("quality", "testing"): [
        {"tool": "test_runner", "profile": "Scout", "priority": 1},
        {"tool": "inspector", "profile": "Scout", "priority": 2},
    ],
    ("structure", "architecture"): [
        {"tool": "inspector", "profile": "Scout", "priority": 1},
    ],
    ("structure", "dependencies"): [
        {"tool": "inspector", "profile": "Scout", "priority": 1},
    ],
    # Scout missions - full project reconnaissance
    ("scout", "launch_readiness"): [
        {"tool": "scout", "profile": "Scout", "priority": 1},
        {"tool": "secrets_scanner", "profile": "Fire Ant", "priority": 2},
    ],
    ("scout", "assessment"): [
        {"tool": "scout", "profile": "Scout", "priority": 1},
    ],
    ("scout", "saas"): [
        {"tool": "scout", "profile": "Scout", "priority": 1},
        {"tool": "secrets_scanner", "profile": "Fire Ant", "priority": 2},
    ],
}

# Default stop conditions by category
DEFAULT_STOP_CONDITIONS = {
    "security": {
        "max_duration_ms": 120000,  # 2 min
        "on_critical": "escalate",
    },
    "quality": {
        "max_duration_ms": 60000,  # 1 min
        "on_critical": "continue",
    },
    "structure": {
        "max_duration_ms": 60000,  # 1 min
        "on_critical": "continue",
    },
    "scout": {
        "max_duration_ms": 300000,  # 5 min (scout needs more time)
        "on_critical": "continue",  # Report all findings
    },
}


class MQPlanner:
    """
    MQ (Mission Queue) Planner - Converts missions to executable plans.

    The Queen directs. MQ plans. BQ executes.
    """

    VERSION = "1.0.0"

    def __init__(self, mission: str, project: str, run_id: str):
        self.mission = mission
        self.project = project
        self.run_id = run_id
        self.intent: Optional[MissionIntent] = None
        self.plan: dict = {}

    def parse_intent(self) -> MissionIntent:
        """
        Parse mission statement to extract intent.

        Returns MissionIntent with category, subcategory, keywords.
        """
        mission_lower = self.mission.lower()
        keywords = []
        best_match = None
        best_score = 0

        # Score each category/subcategory
        for category, subcategories in MISSION_PATTERNS.items():
            for subcategory, patterns in subcategories.items():
                score = 0
                matched_keywords = []

                for pattern in patterns:
                    matches = re.findall(pattern, mission_lower)
                    if matches:
                        score += len(matches)
                        matched_keywords.extend(matches)

                if score > best_score:
                    best_score = score
                    best_match = (category, subcategory)
                    keywords = matched_keywords

        # Default to security/secrets if no clear match
        if not best_match:
            best_match = ("security", "secrets")

        # Extract targets (file paths mentioned)
        targets = re.findall(r'[\w/\\]+\.\w+', self.mission)

        # Detect urgency from keywords
        urgency = "normal"
        if any(word in mission_lower for word in ["urgent", "critical", "asap", "immediately"]):
            urgency = "critical"
        elif any(word in mission_lower for word in ["important", "priority"]):
            urgency = "high"

        self.intent = MissionIntent(
            category=best_match[0],
            subcategory=best_match[1],
            keywords=list(set(keywords)),
            targets=targets,
            urgency=urgency
        )

        return self.intent

    def select_tools(self) -> list[dict]:
        """
        Select tools based on intent.

        Returns list of tool configs with profiles.
        """
        if not self.intent:
            self.parse_intent()

        key = (self.intent.category, self.intent.subcategory)
        tools = INTENT_TOOLS.get(key, [{"tool": "inspector", "profile": "Scout", "priority": 1}])

        # Sort by priority
        return sorted(tools, key=lambda t: t.get("priority", 99))

    def generate_tasks(self) -> list[dict]:
        """
        Generate task list from selected tools.

        Returns list of task definitions.
        """
        tools = self.select_tools()
        tasks = []

        # Get default stop conditions for category
        stop_conditions = DEFAULT_STOP_CONDITIONS.get(
            self.intent.category,
            DEFAULT_STOP_CONDITIONS["quality"]
        ).copy()

        # Adjust for urgency
        if self.intent.urgency == "critical":
            stop_conditions["on_critical"] = "stop"

        for i, tool_config in enumerate(tools):
            task_id = f"T{(i + 1):03d}"
            tool = tool_config["tool"]
            profile = tool_config["profile"]

            task = {
                "task_id": task_id,
                "tool": tool,
                "profile": profile,
                "description": f"Run {tool} with {profile} profile",
                "inputs": self._build_inputs(tool),
                "stop_conditions": stop_conditions.copy(),
                "outputs_expected": self._expected_outputs(tool),
            }

            tasks.append(task)

        # Always add reporter as final task
        # Note: Ghost archivist handles actual report generation, so outputs are not required
        reporter_id = f"T{(len(tasks) + 1):03d}"
        tasks.append({
            "task_id": reporter_id,
            "tool": "reporter",
            "profile": "Ghost",
            "description": "Finalize report (delegated to Ghost archivist)",
            "inputs": {},
            "stop_conditions": {"max_duration_ms": 30000},
            "outputs_expected": [],  # Ghost handles reporting, no outputs required from this task
        })

        return tasks

    def _build_inputs(self, tool: str) -> dict:
        """Build tool-specific inputs based on intent."""
        inputs = {}

        if tool == "secrets_scanner":
            # Fast mode for normal, deep for critical
            inputs["scan_mode"] = "deep" if self.intent.urgency in ["high", "critical"] else "fast"

        elif tool == "inspector":
            inputs["focus_areas"] = self.intent.keywords
            if self.intent.targets:
                inputs["target_paths"] = self.intent.targets

        elif tool == "rules_auditor":
            inputs["rules_file"] = "firestore.rules"

        elif tool == "browser":
            inputs["url"] = "http://localhost:3000"
            inputs["capture"] = ["console", "network", "screenshot"]

        elif tool == "test_runner":
            inputs["test_command"] = "npm test"

        return inputs

    def _expected_outputs(self, tool: str) -> list[dict]:
        """Define expected outputs for a tool."""
        outputs = {
            "inspector": [
                {"artifact": "project_structure", "format": "json", "required": False},
                {"artifact": "config_files", "format": "json", "required": False},
                {"artifact": "error_patterns", "format": "json", "required": False},
                {"artifact": "SECRET_FINDINGS", "format": "json", "required": False},
            ],
            "secrets_scanner": [
                {"artifact": "SECRET_FINDINGS", "format": "json", "required": True},
                {"artifact": "SECRET_FINDINGS", "format": "md", "required": False},
                {"artifact": "SCAN_PROFILE", "format": "json", "required": False},
            ],
            "rules_auditor": [
                {"artifact": "RULES_ANALYSIS", "format": "json", "required": True},
            ],
            "browser": [
                {"artifact": "CONSOLE_LOG", "format": "json", "required": False},
                {"artifact": "NETWORK_LOG", "format": "json", "required": False},
            ],
            "test_runner": [
                {"artifact": "TEST_RESULTS", "format": "json", "required": True},
            ],
            "reporter": [
                # Ghost archivist handles final report
                {"artifact": "FINAL_REPORT", "format": "md", "required": False},
            ],
        }

        return outputs.get(tool, [])

    def build_dependencies(self, tasks: list[dict]) -> dict:
        """
        Build dependency graph for tasks.

        Currently simple: reporter depends on all others.
        """
        dependencies = {}

        # Find reporter task
        reporter_tasks = [t for t in tasks if t["tool"] == "reporter"]
        other_tasks = [t for t in tasks if t["tool"] != "reporter"]

        for reporter in reporter_tasks:
            dependencies[reporter["task_id"]] = [t["task_id"] for t in other_tasks]

        return dependencies

    def _can_parallelize(self, tasks: list[dict]) -> bool:
        """
        Determine if tasks can be safely parallelized.

        Returns True if:
        - No exclusive tools (test_runner, etc.)
        - At least 2 tasks can run in parallel
        """
        # Execution classes by tool
        TOOL_EXEC_CLASS = {
            "inspector": "read_only",
            "secrets_scanner": "read_only",
            "rules_auditor": "read_only",
            "test_runner": "exclusive",
            "browser": "browser",
            "reporter": "read_only",
        }

        # Check if any task is exclusive
        for task in tasks:
            tool = task.get("tool", "")
            exec_class = TOOL_EXEC_CLASS.get(tool, "read_only")
            if exec_class == "exclusive":
                return False  # Cannot parallelize with exclusive tasks

        # Count non-reporter tasks (potential parallel candidates)
        parallelizable = [t for t in tasks if t["tool"] != "reporter"]
        return len(parallelizable) >= 2

    def _has_propose_tasks(self, tasks: list[dict]) -> bool:
        """
        Check if plan contains PROPOSE tasks.

        When PROPOSE tasks exist, plan should pause for approval.
        """
        PROPOSE_TOOLS = {"propose", "proposer", "remediation_proposer", "config_proposer"}
        for task in tasks:
            tool = task.get("tool", "").lower()
            if tool in PROPOSE_TOOLS or tool.startswith("propose_"):
                return True
        return False

    def _has_apply_tasks(self, tasks: list[dict]) -> bool:
        """
        Check if plan contains APPLY tasks.

        APPLY tasks require prior approval.
        """
        APPLY_TOOLS = {"apply", "applier", "patch_apply"}
        for task in tasks:
            tool = task.get("tool", "").lower()
            if tool in APPLY_TOOLS or tool.startswith("apply_"):
                return True
        return False

    def generate_plan(self) -> dict:
        """
        Generate complete PLAN.json.

        Returns plan dict ready for BQ executor.
        """
        # Parse intent
        self.parse_intent()

        # Generate plan ID
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        plan_id = f"PLAN-{self.project.upper()}-{timestamp}"

        # Generate tasks
        tasks = self.generate_tasks()

        # Build dependencies
        dependencies = self.build_dependencies(tasks)

        # Build plan
        self.plan = {
            "plan_id": plan_id,
            "mission": self.mission,
            "project": self.project,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "planner_version": self.VERSION,
            "intent": {
                "category": self.intent.category,
                "subcategory": self.intent.subcategory,
                "keywords": self.intent.keywords,
                "urgency": self.intent.urgency,
            },
            "tasks": tasks,
            "dependencies": dependencies,
            "config": {
                "parallel_execution": self._can_parallelize(tasks),
                "max_parallel_workers": 4,
                "fail_fast": self.intent.urgency == "critical",
                "max_total_duration_ms": 300000,  # 5 min
                "evidence_retention": "all",
                # Proposal boundaries
                "has_propose_tasks": self._has_propose_tasks(tasks),
                "has_apply_tasks": self._has_apply_tasks(tasks),
                "pause_for_approval": self._has_propose_tasks(tasks),  # Pause after PROPOSE, before APPLY
            },
        }

        return self.plan

    def write_plan(self, output_path: Path) -> Path:
        """
        Write plan to PLAN.json file.

        Returns path to written file.
        """
        if not self.plan:
            self.generate_plan()

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(self.plan, f, indent=2)

        return output_path


def generate_plan(mission: str, project: str, run_id: str, output_path: Path = None) -> dict:
    """
    Convenience function to generate a plan.

    Args:
        mission: Mission statement
        project: Project identifier
        run_id: Run identifier
        output_path: Optional path to write PLAN.json

    Returns:
        Plan dict
    """
    planner = MQPlanner(mission, project, run_id)
    plan = planner.generate_plan()

    if output_path:
        planner.write_plan(output_path)

    return plan


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MQ Planner - Mission to Plan")
    parser.add_argument("--mission", required=True, help="Mission statement")
    parser.add_argument("--project", required=True, help="Project identifier")
    parser.add_argument("--output", help="Output path for PLAN.json")

    args = parser.parse_args()

    run_id = f"RUN-{args.project.upper()}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

    plan = generate_plan(
        args.mission,
        args.project,
        run_id,
        Path(args.output) if args.output else None
    )

    print(f"\nGenerated plan: {plan['plan_id']}")
    print(f"Intent: {plan['intent']['category']}/{plan['intent']['subcategory']}")
    print(f"Tasks: {len(plan['tasks'])}")
    for task in plan["tasks"]:
        print(f"  {task['task_id']}: {task['tool']} ({task['profile']})")
