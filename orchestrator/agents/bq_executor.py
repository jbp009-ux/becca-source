#!/usr/bin/env python3
"""
bq_executor.py - BQ (Bee Queue) Task Executor

The BQ Executor runs tasks from a PLAN.json, enforcing:
  - Pre-execution gates (validation, dependencies)
  - Stop conditions (timeout, max findings, critical found)
  - Output validation (expected artifacts)
  - RESULT.json generation per task
  - Parallel execution via DAG scheduling (Phase 2.2)

Protocol:
  1. Load PLAN.json
  2. Build DAG from tasks and dependencies
  3. Generate topological layers (Kahn's algorithm)
  4. For each layer, execute tasks (parallel if enabled):
     a. Gate check: dependencies complete? inputs valid?
     b. Execute tool with profile
     c. Validate outputs against outputs_expected
     d. Generate RESULT.json
     e. Check stop conditions
  5. Return aggregated results

Execution Classes:
  - read_only: Can run in parallel with other read_only tasks
  - browser: Only one browser task at a time (browser lock)
  - exclusive: No other tasks run during execution

Resume Behavior:
  - Tasks with prior SUCCESS status and valid outputs are skipped
  - Failed/incomplete tasks are re-executed

Usage:
    from orchestrator.agents.bq_executor import BQExecutor

    executor = BQExecutor(plan_path, run_dir, project_path)
    results = executor.execute()
"""

import hashlib
import json
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Optional

# Tool imports (will be expanded as tools are added)
TOOL_REGISTRY = {}

# Execution class definitions
EXECUTION_CLASS = {
    "read_only": {"parallel": True, "browser_lock": False, "exclusive": False},
    "browser": {"parallel": False, "browser_lock": True, "exclusive": False},
    "exclusive": {"parallel": False, "browser_lock": False, "exclusive": True},
}

# Default execution classes by tool
TOOL_EXECUTION_CLASS = {
    "inspector": "read_only",
    "secrets_scanner": "read_only",
    "rules_auditor": "read_only",
    "test_runner": "exclusive",  # Tests may modify state
    "browser": "browser",
    "reporter": "read_only",
}


class DAGScheduler:
    """
    DAG-based task scheduler using Kahn's algorithm.

    Builds dependency graph and generates topological layers
    for parallel execution.
    """

    def __init__(self, tasks: list[dict], dependencies: dict[str, list[str]]):
        self.tasks = {t["task_id"]: t for t in tasks}
        self.dependencies = dependencies
        self.layers: list[list[str]] = []

    def validate(self) -> tuple[bool, str]:
        """
        Validate DAG structure.

        Checks:
        - All dependency IDs reference existing tasks
        - No cycles exist

        Returns (valid, error_message)
        """
        task_ids = set(self.tasks.keys())

        # Check for unknown dependencies
        for task_id, deps in self.dependencies.items():
            if task_id not in task_ids:
                return False, f"Dependency defined for unknown task: {task_id}"
            for dep in deps:
                if dep not in task_ids:
                    return False, f"Task {task_id} depends on unknown task: {dep}"

        # Check for cycles using DFS
        visited = set()
        rec_stack = set()

        def has_cycle(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)

            # Get tasks that depend on this node (reverse edges for cycle detection)
            for task_id, deps in self.dependencies.items():
                if node in deps and task_id not in visited:
                    if has_cycle(task_id):
                        return True
                elif task_id in rec_stack and node in deps:
                    return True

            rec_stack.remove(node)
            return False

        for task_id in task_ids:
            if task_id not in visited:
                if has_cycle(task_id):
                    return False, f"Cycle detected involving task: {task_id}"

        return True, ""

    def build_layers(self) -> list[list[str]]:
        """
        Generate topological layers using Kahn's algorithm.

        Each layer contains tasks whose dependencies are all in previous layers.
        Tasks in the same layer can potentially run in parallel.

        Returns list of layers, each layer is a list of task IDs.
        """
        # Build in-degree map (how many tasks each task depends on)
        in_degree = {task_id: 0 for task_id in self.tasks}

        # Build reverse dependency map (who depends on me)
        dependents = defaultdict(list)

        for task_id, deps in self.dependencies.items():
            in_degree[task_id] = len(deps)
            for dep in deps:
                dependents[dep].append(task_id)

        # Start with tasks that have no dependencies
        queue = deque([t for t, deg in in_degree.items() if deg == 0])

        self.layers = []

        while queue:
            # Current layer: all tasks ready to execute
            layer = list(queue)
            self.layers.append(layer)
            queue.clear()

            # Process this layer, decrement in-degree of dependents
            for task_id in layer:
                for dependent in dependents[task_id]:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        queue.append(dependent)

        # Verify all tasks are scheduled
        scheduled = sum(len(layer) for layer in self.layers)
        if scheduled != len(self.tasks):
            # Some tasks couldn't be scheduled (likely due to cycle)
            unscheduled = set(self.tasks.keys()) - set(t for layer in self.layers for t in layer)
            raise ValueError(f"Could not schedule tasks (cycle?): {unscheduled}")

        return self.layers

    def get_execution_plan(self) -> list[dict]:
        """
        Get detailed execution plan with layers and execution classes.

        Returns list of layer info dicts.
        """
        if not self.layers:
            self.build_layers()

        plan = []
        for i, layer in enumerate(self.layers):
            layer_info = {
                "layer": i,
                "tasks": [],
                "parallel_groups": []
            }

            # Group tasks by execution class
            read_only_tasks = []
            browser_tasks = []
            exclusive_tasks = []

            for task_id in layer:
                task = self.tasks[task_id]
                exec_class = task.get("execution_class") or TOOL_EXECUTION_CLASS.get(task["tool"], "read_only")

                task_info = {
                    "task_id": task_id,
                    "tool": task["tool"],
                    "execution_class": exec_class
                }
                layer_info["tasks"].append(task_info)

                if exec_class == "read_only":
                    read_only_tasks.append(task_id)
                elif exec_class == "browser":
                    browser_tasks.append(task_id)
                else:
                    exclusive_tasks.append(task_id)

            # Build parallel groups
            # read_only tasks can all run together
            if read_only_tasks:
                layer_info["parallel_groups"].append({
                    "type": "parallel",
                    "tasks": read_only_tasks
                })

            # browser tasks run sequentially (browser lock)
            for task_id in browser_tasks:
                layer_info["parallel_groups"].append({
                    "type": "browser_sequential",
                    "tasks": [task_id]
                })

            # exclusive tasks run alone
            for task_id in exclusive_tasks:
                layer_info["parallel_groups"].append({
                    "type": "exclusive",
                    "tasks": [task_id]
                })

            plan.append(layer_info)

        return plan


@dataclass
class TaskFingerprint:
    """
    Input fingerprint for TOCTOU-safe resume.

    Captures the execution context so we don't skip tasks
    that were run against a different code state.
    """
    tool: str = ""
    tool_version: str = "1.0.0"
    profile: str = ""
    inputs_hash: str = ""  # SHA256 of sorted inputs JSON
    project_commit: str = ""  # Git HEAD commit if available
    suppression_hash: str = ""  # Hash of suppression file if used

    def matches(self, other: "TaskFingerprint", allow_stale: bool = False) -> tuple[bool, str]:
        """
        Check if fingerprints match for safe resume.

        Returns (matches, reason_if_not)
        """
        if self.tool != other.tool:
            return False, f"Tool changed: {self.tool} -> {other.tool}"
        if self.profile != other.profile:
            return False, f"Profile changed: {self.profile} -> {other.profile}"
        if self.inputs_hash != other.inputs_hash:
            return False, f"Inputs changed"
        if self.suppression_hash != other.suppression_hash:
            return False, f"Suppressions changed"

        # Commit check is optional with allow_stale
        if self.project_commit != other.project_commit:
            if allow_stale:
                return True, "Commit changed but --allow-stale"
            return False, f"Commit changed: {self.project_commit[:8]} -> {other.project_commit[:8]}"

        return True, "Fingerprint matches"


@dataclass
class TaskTiming:
    """Timing breakdown for a task."""
    total_ms: float = 0.0
    enumerate_ms: float = 0.0
    process_ms: float = 0.0
    write_ms: float = 0.0


@dataclass
class TaskStats:
    """Statistics from task execution."""
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_processed: int = 0
    findings_count: int = 0
    findings_by_severity: dict = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
    })


@dataclass
class TaskOutput:
    """Output artifact from a task."""
    artifact: str
    path: str
    format: str
    size_bytes: int = 0
    hash: str = ""


@dataclass
class TaskError:
    """Error from task execution."""
    code: str
    message: str
    details: str = ""
    recoverable: bool = True


@dataclass
class TaskResult:
    """Result of executing a single task."""
    result_id: str
    task_id: str
    plan_id: str
    status: str  # success, partial, failed, timeout, skipped, blocked
    started_at: str
    completed_at: str
    timing: TaskTiming = field(default_factory=TaskTiming)
    tool: str = ""
    tool_version: str = "1.0.0"
    profile: str = ""
    stats: TaskStats = field(default_factory=TaskStats)
    outputs: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    stop_reason: str = "completed"
    metrics: dict = field(default_factory=dict)
    fingerprint: TaskFingerprint = field(default_factory=TaskFingerprint)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        d = asdict(self)
        d["timing"] = asdict(self.timing)
        d["stats"] = asdict(self.stats)
        d["fingerprint"] = asdict(self.fingerprint)
        return d


class GateError(Exception):
    """Raised when a pre-execution gate fails."""
    pass


class StopConditionMet(Exception):
    """Raised when a stop condition is triggered."""
    def __init__(self, reason: str, details: str = ""):
        self.reason = reason
        self.details = details
        super().__init__(f"Stop condition met: {reason}")


class BQExecutor:
    """
    BQ (Bee Queue) Executor - Runs tasks from a plan with gates and validation.

    The Ants follow protocol. BQ enforces it.

    Supports:
    - Parallel execution via DAG scheduling
    - Execution classes (read_only, browser, exclusive)
    - Resume from prior run (skip verified SUCCESS tasks)
    """

    def __init__(self, plan_path: Path, run_dir: Path, project_path: Path, prior_results: list[dict] = None):
        self.plan_path = Path(plan_path)
        self.run_dir = Path(run_dir)
        self.project_path = Path(project_path)
        self.prior_results = prior_results or []

        self.plan: dict = {}
        self.results: list[TaskResult] = []
        self.completed_tasks: set[str] = set()
        self.skipped_tasks: set[str] = set()
        self.global_stop: bool = False
        self.stop_reason: str = ""
        self.stop_type: str = ""  # "intentional" (stop condition) or "failure" (task failed)

        # Threading locks for parallel execution
        self._results_lock = Lock()
        self._browser_lock = Lock()
        self._stop_lock = Lock()

        # DAG scheduler
        self.scheduler: Optional[DAGScheduler] = None

        # Create BQ evidence directory
        self.evidence_dir = self.run_dir / "bq_executor" / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Load tool registry
        self._load_tools()

        # Index prior results for resume
        self._prior_results_index = {r.get("task_id"): r for r in self.prior_results if r.get("task_id")}

        # Get project commit for fingerprinting
        self._project_commit = self._get_git_commit()

        # Allow stale resume (skip commit check)
        self.allow_stale_resume = False

    def _get_git_commit(self) -> str:
        """Get current git HEAD commit hash for fingerprinting."""
        import subprocess
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return ""

    def _generate_fingerprint(self, task: dict) -> TaskFingerprint:
        """
        Generate input fingerprint for a task.

        Captures execution context for TOCTOU-safe resume.
        """
        tool = task.get("tool", "")
        profile = task.get("profile", "")
        inputs = task.get("inputs", {})

        # Hash inputs deterministically
        inputs_json = json.dumps(inputs, sort_keys=True)
        inputs_hash = hashlib.sha256(inputs_json.encode()).hexdigest()[:16]

        # Check for suppression file
        suppression_hash = ""
        suppression_file = inputs.get("suppression_file") or inputs.get("suppressions")
        if suppression_file:
            supp_path = self.project_path / suppression_file
            if supp_path.exists():
                suppression_hash = self._hash_file(supp_path)

        return TaskFingerprint(
            tool=tool,
            tool_version="1.0.0",  # TODO: Get from tool registry
            profile=profile,
            inputs_hash=inputs_hash,
            project_commit=self._project_commit,
            suppression_hash=suppression_hash
        )

    def _load_tools(self):
        """Load available tools into registry."""
        global TOOL_REGISTRY

        # Import tools lazily to avoid circular imports
        try:
            from tools.tool_inspector import run_inspector
            TOOL_REGISTRY["inspector"] = run_inspector
        except ImportError:
            pass

        try:
            from tools.secrets_scanner import SecretsScanner
            TOOL_REGISTRY["secrets_scanner"] = SecretsScanner
        except ImportError:
            pass

        try:
            from tools.tool_scout import run_scout
            TOOL_REGISTRY["scout"] = run_scout
        except ImportError:
            pass

        try:
            from tools.evidence_contract import validate_scout_output
            self._evidence_validator = validate_scout_output
        except ImportError:
            self._evidence_validator = None

        # Add more tools as they become available
        # TOOL_REGISTRY["rules_auditor"] = run_rules_auditor
        # TOOL_REGISTRY["test_runner"] = run_test_runner

    def load_plan(self) -> dict:
        """Load and validate PLAN.json."""
        if not self.plan_path.exists():
            raise FileNotFoundError(f"Plan not found: {self.plan_path}")

        with open(self.plan_path) as f:
            self.plan = json.load(f)

        # Validate required fields
        required = ["plan_id", "mission", "tasks"]
        for field in required:
            if field not in self.plan:
                raise ValueError(f"Plan missing required field: {field}")

        if not self.plan["tasks"]:
            raise ValueError("Plan has no tasks")

        return self.plan

    def _check_dependencies(self, task: dict) -> tuple[bool, str]:
        """Check if task dependencies are satisfied."""
        task_id = task["task_id"]
        dependencies = self.plan.get("dependencies", {}).get(task_id, [])

        for dep_id in dependencies:
            if dep_id not in self.completed_tasks:
                return False, f"Dependency {dep_id} not complete"

        return True, ""

    def _validate_inputs(self, task: dict) -> tuple[bool, str]:
        """Validate task inputs before execution."""
        inputs = task.get("inputs", {})
        tool = task.get("tool", "")

        # Tool must be registered
        if tool not in TOOL_REGISTRY and tool not in ["inspector", "secrets_scanner", "rules_auditor", "test_runner", "reporter", "scout"]:
            return False, f"Unknown tool: {tool}"

        # Target path must exist if specified
        target_path = inputs.get("target_path")
        if target_path:
            full_path = self.project_path / target_path
            if not full_path.exists():
                return False, f"Target path does not exist: {target_path}"

        return True, ""

    def _gate_check(self, task: dict) -> tuple[bool, str]:
        """
        Pre-execution gate check.

        Gates enforce:
        1. Dependencies are complete
        2. Inputs are valid
        3. Global stop not triggered
        """
        task_id = task["task_id"]

        # Check global stop (thread-safe)
        with self._stop_lock:
            if self.global_stop:
                return False, f"Global stop active: {self.stop_reason}"

        # Check dependencies
        deps_ok, deps_msg = self._check_dependencies(task)
        if not deps_ok:
            return False, deps_msg

        # Validate inputs
        inputs_ok, inputs_msg = self._validate_inputs(task)
        if not inputs_ok:
            return False, inputs_msg

        return True, ""

    def _can_skip_task(self, task: dict) -> tuple[bool, Optional[TaskResult]]:
        """
        Check if task can be skipped due to prior successful execution.

        Resume rules (TOCTOU-safe):
        - Task must have prior SUCCESS status
        - Fingerprint must match (tool, profile, inputs, commit)
        - All expected outputs must exist with matching hashes
        - No dependency has been re-executed

        Returns (can_skip, prior_result)
        """
        task_id = task["task_id"]

        # Check if we have prior result
        prior = self._prior_results_index.get(task_id)
        if not prior:
            return False, None

        # Must be SUCCESS
        if prior.get("status") != "success":
            return False, None

        # Verify fingerprint matches (TOCTOU guard)
        prior_fp_data = prior.get("fingerprint", {})
        if prior_fp_data:
            prior_fp = TaskFingerprint(**prior_fp_data)
            current_fp = self._generate_fingerprint(task)

            matches, reason = prior_fp.matches(current_fp, allow_stale=self.allow_stale_resume)
            if not matches:
                print(f"          FINGERPRINT MISMATCH: {reason}")
                return False, None

        # Check if any dependency was re-executed (not skipped)
        deps = self.plan.get("dependencies", {}).get(task_id, [])
        for dep_id in deps:
            if dep_id not in self.skipped_tasks:
                # Dependency was re-executed, need to re-run this task
                return False, None

        # Verify outputs still exist with matching hashes
        for output in prior.get("outputs", []):
            output_path = self.run_dir / output.get("path", "")
            if not output_path.exists():
                return False, None

            # Verify hash
            expected_hash = output.get("hash", "")
            if expected_hash:
                actual_hash = self._hash_file(output_path)
                if actual_hash != expected_hash:
                    return False, None

        # Can skip - recreate TaskResult from prior
        timing_data = prior.get("timing", {})
        stats_data = prior.get("stats", {})
        fp_data = prior.get("fingerprint", {})

        result = TaskResult(
            result_id=prior.get("result_id", f"RESULT-{task_id}-RESUMED"),
            task_id=task_id,
            plan_id=prior.get("plan_id", ""),
            status="success",
            started_at=prior.get("started_at", ""),
            completed_at=prior.get("completed_at", ""),
            timing=TaskTiming(**timing_data) if timing_data else TaskTiming(),
            tool=prior.get("tool", ""),
            tool_version=prior.get("tool_version", "1.0.0"),
            profile=prior.get("profile", ""),
            stats=TaskStats(**stats_data) if stats_data else TaskStats(),
            outputs=[TaskOutput(**o) for o in prior.get("outputs", [])],
            errors=prior.get("errors", []),
            stop_reason="skipped_resume",
            fingerprint=TaskFingerprint(**fp_data) if fp_data else TaskFingerprint()
        )

        return True, result

    def _execute_tool(self, task: dict) -> dict:
        """
        Execute the tool for a task.

        Returns tool output dict with:
        - status: success/partial/failed
        - evidence: list of evidence paths
        - findings: list of findings (if applicable)
        - stats: execution statistics
        """
        tool = task["tool"]
        inputs = task.get("inputs", {})
        profile = task.get("profile", "")

        # Build tool-specific arguments
        if tool == "inspector":
            # Use existing inspector
            from tools.tool_inspector import run_inspector
            return run_inspector(
                run_id=self.plan.get("plan_id", ""),
                run_dir=self.run_dir,
                project_path=self.project_path,
                mission=self.plan.get("mission", ""),
                project_name=self.plan.get("project", "")
            )

        elif tool == "secrets_scanner":
            # Use secrets scanner directly
            from tools.secrets_scanner import SecretsScanner, generate_findings_json, generate_findings_md
            from tools.tool_inspector import scan_for_secrets
            from dataclasses import asdict

            scan_mode = inputs.get("scan_mode", "fast")
            scan_result = scan_for_secrets(
                self.project_path,
                audit={"project_path": str(self.project_path), "deny_patterns": []},
                evidence_dir=self.evidence_dir,
                scan_mode=scan_mode
            )

            # Convert ScanResult dataclass to dict
            evidence_paths = []
            if self.evidence_dir:
                findings_json = self.evidence_dir / "SECRET_FINDINGS.json"
                findings_md = self.evidence_dir / "SECRET_FINDINGS.md"
                profile_json = self.evidence_dir / "SCAN_PROFILE.json"

                # Write findings
                generate_findings_json(scan_result, findings_json)
                generate_findings_md(scan_result, findings_md)

                evidence_paths = [str(findings_json), str(findings_md)]
                if profile_json.exists():
                    evidence_paths.append(str(profile_json))

            return {
                "status": "success" if scan_result.severity_counts["CRITICAL"] == 0 else "partial",
                "evidence": evidence_paths,
                "findings": scan_result.findings,
                "stats": {
                    "files_scanned": scan_result.files_scanned,
                    "findings_count": len(scan_result.findings),
                    "findings_by_severity": scan_result.severity_counts,
                }
            }

        elif tool == "reporter":
            # Ghost archivist handles the final report now
            # Return success - the kernel's Ghost phase does the actual reporting
            return {
                "status": "success",
                "evidence": [],
                "message": "Report generation delegated to Ghost archivist"
            }

        elif tool == "scout":
            # Project scout / launch readiness assessment
            from tools.tool_scout import run_scout

            mission = inputs.get("mission", self.plan.get("mission", ""))
            focus_areas = inputs.get("focus_areas", ["security", "scalability", "testing"])

            result = run_scout(
                project_path=self.project_path,
                mission=mission,
                focus_areas=focus_areas,
                evidence_dir=self.evidence_dir
            )

            # Validate against evidence contract
            if self._evidence_validator:
                validation = self._evidence_validator(result, self.project_path, strict=True)
                if not validation.valid:
                    print(f"          ⚠️ EVIDENCE CONTRACT VIOLATION:")
                    for error in validation.errors[:5]:
                        print(f"             ❌ {error}")
                    # Don't fail the task, but mark as partial
                    result["status"] = "partial"
                    result["evidence_validation"] = {
                        "valid": False,
                        "score": validation.score,
                        "errors": validation.errors
                    }

            return result

        else:
            # Placeholder for unimplemented tools
            return {
                "status": "skipped",
                "error": f"Tool '{tool}' not implemented",
                "evidence": []
            }

    def _validate_outputs(self, task: dict, tool_output: dict) -> tuple[bool, list[str]]:
        """
        Validate tool outputs against expected artifacts.

        Returns (all_required_present, missing_artifacts)
        """
        expected = task.get("outputs_expected", [])
        missing = []

        evidence_items = tool_output.get("evidence", [])

        # Normalize evidence to path strings
        evidence_paths = []
        for item in evidence_items:
            if isinstance(item, dict):
                evidence_paths.append(item.get("path", ""))
            else:
                evidence_paths.append(str(item))

        for exp in expected:
            artifact_name = exp.get("artifact", "")
            required = exp.get("required", True)

            # Check if artifact was produced
            found = any(artifact_name in p for p in evidence_paths)

            if required and not found:
                missing.append(artifact_name)

        return len(missing) == 0, missing

    def _check_stop_conditions(self, task: dict, tool_output: dict) -> Optional[str]:
        """
        Check if stop conditions are met.

        Returns stop reason if triggered, None otherwise.
        """
        stop_conditions = task.get("stop_conditions", {})

        # Check severity threshold
        on_critical = stop_conditions.get("on_critical", "continue")
        if on_critical == "stop":
            findings = tool_output.get("findings", [])
            critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
            if critical_count > 0:
                return "critical_found"

        # Check max findings
        max_findings = stop_conditions.get("max_findings")
        if max_findings:
            findings_count = len(tool_output.get("findings", []))
            if findings_count >= max_findings:
                return "max_findings"

        return None

    def _generate_result(
        self,
        task: dict,
        status: str,
        started_at: datetime,
        completed_at: datetime,
        tool_output: dict,
        errors: list[TaskError] = None,
        stop_reason: str = "completed"
    ) -> TaskResult:
        """Generate RESULT.json for a task."""
        task_id = task["task_id"]
        timestamp = completed_at.strftime("%Y%m%d-%H%M%S")

        result = TaskResult(
            result_id=f"RESULT-{task_id}-{timestamp}",
            task_id=task_id,
            plan_id=self.plan.get("plan_id", ""),
            status=status,
            started_at=started_at.isoformat() + "Z",
            completed_at=completed_at.isoformat() + "Z",
            tool=task.get("tool", ""),
            profile=task.get("profile", ""),
            stop_reason=stop_reason
        )

        # Timing
        total_ms = (completed_at - started_at).total_seconds() * 1000
        result.timing = TaskTiming(total_ms=total_ms)

        # Stats from tool output
        if "stats" in tool_output:
            stats = tool_output["stats"]
            result.stats = TaskStats(
                files_scanned=stats.get("files_scanned", stats.get("files_read", 0)),
                files_skipped=stats.get("files_skipped", 0),
                bytes_processed=stats.get("bytes_processed", stats.get("bytes_read", 0)),
                findings_count=stats.get("findings_count", len(tool_output.get("findings", [])))
            )

        # Outputs - handle both dict format (inspector) and string format (secrets_scanner)
        for evidence_item in tool_output.get("evidence", []):
            # Extract path from dict if needed
            if isinstance(evidence_item, dict):
                evidence_path = evidence_item.get("path", "")
            else:
                evidence_path = evidence_item

            if not evidence_path:
                continue

            path = Path(evidence_path)
            if path.exists():
                result.outputs.append(TaskOutput(
                    artifact=path.stem,
                    path=str(path.relative_to(self.run_dir)) if self.run_dir in path.parents else str(path),
                    format=path.suffix.lstrip("."),
                    size_bytes=path.stat().st_size,
                    hash=self._hash_file(path)
                ))

        # Errors
        if errors:
            result.errors = [asdict(e) for e in errors]

        # Fingerprint for TOCTOU-safe resume
        result.fingerprint = self._generate_fingerprint(task)

        # Write RESULT.json
        result_path = self.evidence_dir / f"RESULT_{task_id}.json"
        with open(result_path, "w") as f:
            json.dump(result.to_dict(), f, indent=2)

        return result

    def _hash_file(self, path: Path) -> str:
        """Generate SHA256 hash of a file."""
        if not path.exists():
            return ""

        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        return f"sha256:{sha256.hexdigest()}"

    def execute_task(self, task: dict) -> TaskResult:
        """
        Execute a single task with full gate/validation protocol.

        Thread-safe for parallel execution.
        """
        task_id = task["task_id"]
        tool = task.get("tool", "unknown")
        exec_class = task.get("execution_class") or TOOL_EXECUTION_CLASS.get(tool, "read_only")

        print(f"      [{task_id}] {tool}...")

        # Check for resume skip
        can_skip, prior_result = self._can_skip_task(task)
        if can_skip and prior_result:
            print(f"          SKIPPED (resume: prior SUCCESS valid)")
            with self._results_lock:
                self.completed_tasks.add(task_id)
                self.skipped_tasks.add(task_id)
            return prior_result

        # Gate check
        gate_ok, gate_msg = self._gate_check(task)
        if not gate_ok:
            print(f"          BLOCKED: {gate_msg}")
            result = self._generate_result(
                task,
                status="blocked",
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                tool_output={},
                errors=[TaskError(code="E001", message=gate_msg, recoverable=False)],
                stop_reason="blocked"
            )
            return result

        # Acquire browser lock if needed
        browser_locked = False
        if exec_class == "browser":
            self._browser_lock.acquire()
            browser_locked = True

        # Execute with timing
        started_at = datetime.utcnow()

        try:
            # Apply timeout if specified
            stop_conditions = task.get("stop_conditions", {})
            max_duration_ms = stop_conditions.get("max_duration_ms", 300000)  # 5 min default

            # Execute tool
            tool_output = self._execute_tool(task)

            completed_at = datetime.utcnow()

            # Check execution time
            elapsed_ms = (completed_at - started_at).total_seconds() * 1000
            if elapsed_ms > max_duration_ms:
                status = "timeout"
                stop_reason = "timeout"
            else:
                status = tool_output.get("status", "success")
                stop_reason = "completed"

            # Check stop conditions
            triggered_stop = self._check_stop_conditions(task, tool_output)
            if triggered_stop:
                stop_reason = triggered_stop
                # Check if this should trigger global stop (thread-safe)
                on_critical = stop_conditions.get("on_critical", "continue")
                if triggered_stop == "critical_found" and on_critical == "stop":
                    with self._stop_lock:
                        self.global_stop = True
                        self.stop_reason = "Critical finding detected"
                        self.stop_type = "intentional"  # Stop condition, not failure

            # Validate outputs
            outputs_ok, missing = self._validate_outputs(task, tool_output)
            if not outputs_ok:
                status = "partial"
                print(f"          WARN: Missing artifacts: {missing}")

            # Generate result
            result = self._generate_result(
                task,
                status=status,
                started_at=started_at,
                completed_at=completed_at,
                tool_output=tool_output,
                stop_reason=stop_reason
            )

            print(f"          {status.upper()} ({result.timing.total_ms:.0f}ms)")

            # Mark complete (thread-safe)
            with self._results_lock:
                self.completed_tasks.add(task_id)

            return result

        except Exception as e:
            completed_at = datetime.utcnow()
            print(f"          FAILED: {e}")

            result = self._generate_result(
                task,
                status="failed",
                started_at=started_at,
                completed_at=completed_at,
                tool_output={},
                errors=[TaskError(code="E999", message=str(e), recoverable=False)],
                stop_reason="error"
            )

            return result

        finally:
            # Release browser lock if held
            if browser_locked:
                self._browser_lock.release()

    def execute(self) -> list[TaskResult]:
        """
        Execute all tasks in the plan using DAG scheduling.

        Uses parallel execution for tasks in the same layer when:
        - parallel_execution is enabled in plan config
        - Tasks have compatible execution classes

        Returns list of TaskResult objects.
        """
        # Load plan
        self.load_plan()

        plan_id = self.plan.get("plan_id", "UNKNOWN")
        print(f"\n      BQ Executor: {plan_id}")
        print(f"      Tasks: {len(self.plan['tasks'])}")

        # Check plan config
        config = self.plan.get("config", {})
        fail_fast = config.get("fail_fast", True)
        parallel_execution = config.get("parallel_execution", False)
        max_workers = config.get("max_parallel_workers", 4)
        pause_for_approval = config.get("pause_for_approval", False)

        # Build DAG and generate layers
        dependencies = self.plan.get("dependencies", {})
        self.scheduler = DAGScheduler(self.plan["tasks"], dependencies)

        # Validate DAG
        valid, error = self.scheduler.validate()
        if not valid:
            print(f"      ERROR: Invalid DAG - {error}")
            return self.results

        layers = self.scheduler.build_layers()
        print(f"      Layers: {len(layers)} (parallel={parallel_execution})")

        # Track if we've seen PROPOSE tasks
        propose_completed = False

        # Execute by layer
        for layer_idx, layer in enumerate(layers):
            # Check global stop before starting layer
            with self._stop_lock:
                if self.global_stop:
                    print(f"      HALT: {self.stop_reason}")
                    break

            layer_tasks = [self.plan["tasks"][self._get_task_index(tid)] for tid in layer]

            # Check if this layer has APPLY tasks that need approval
            if pause_for_approval and propose_completed:
                has_apply = any(
                    t.get("tool", "").lower().startswith(("apply", "patch_apply"))
                    for t in layer_tasks
                )
                if has_apply:
                    print(f"      PAUSED: Waiting for approval before APPLY tasks")
                    with self._stop_lock:
                        self.global_stop = True
                        self.stop_reason = "Paused for approval (PROPOSE complete, APPLY pending)"
                        self.stop_type = "intentional"
                    break

            if parallel_execution and len(layer_tasks) > 1:
                # Parallel execution within layer
                self._execute_layer_parallel(layer_tasks, max_workers, fail_fast)
            else:
                # Sequential execution
                self._execute_layer_sequential(layer_tasks, fail_fast)

            # Track if PROPOSE tasks completed in this layer
            for task in layer_tasks:
                tool = task.get("tool", "").lower()
                if tool.startswith(("propose", "proposer", "remediation")):
                    propose_completed = True

        # Write aggregated results
        self._write_execution_summary()

        return self.results

    def _get_task_index(self, task_id: str) -> int:
        """Get index of task in plan by task_id."""
        for i, task in enumerate(self.plan["tasks"]):
            if task["task_id"] == task_id:
                return i
        raise ValueError(f"Task not found: {task_id}")

    def _execute_layer_sequential(self, tasks: list[dict], fail_fast: bool):
        """Execute tasks in a layer sequentially."""
        for task in tasks:
            # Check global stop
            with self._stop_lock:
                if self.global_stop:
                    return

            result = self.execute_task(task)
            with self._results_lock:
                self.results.append(result)

            # Check fail fast
            if fail_fast and result.status == "failed":
                print(f"      HALT: fail_fast triggered by {task['task_id']}")
                with self._stop_lock:
                    self.global_stop = True
                    self.stop_reason = f"fail_fast: {task['task_id']} failed"
                    self.stop_type = "failure"
                return

    def _execute_layer_parallel(self, tasks: list[dict], max_workers: int, fail_fast: bool):
        """
        Execute tasks in a layer with parallel execution.

        Groups tasks by execution class:
        - read_only: Run in parallel
        - browser: Run sequentially (browser lock)
        - exclusive: Run alone

        Stops all tasks when stop condition triggered.
        """
        # Group tasks by execution class
        read_only_tasks = []
        browser_tasks = []
        exclusive_tasks = []

        for task in tasks:
            tool = task.get("tool", "")
            exec_class = task.get("execution_class") or TOOL_EXECUTION_CLASS.get(tool, "read_only")

            if exec_class == "exclusive":
                exclusive_tasks.append(task)
            elif exec_class == "browser":
                browser_tasks.append(task)
            else:
                read_only_tasks.append(task)

        # Execute exclusive tasks first (one at a time)
        for task in exclusive_tasks:
            with self._stop_lock:
                if self.global_stop:
                    return

            result = self.execute_task(task)
            with self._results_lock:
                self.results.append(result)

            if fail_fast and result.status == "failed":
                with self._stop_lock:
                    self.global_stop = True
                    self.stop_reason = f"fail_fast: {task['task_id']} failed"
                    self.stop_type = "failure"
                return

        # Execute read_only tasks in parallel
        if read_only_tasks:
            with self._stop_lock:
                if self.global_stop:
                    return

            with ThreadPoolExecutor(max_workers=min(max_workers, len(read_only_tasks))) as executor:
                futures = {executor.submit(self.execute_task, task): task for task in read_only_tasks}

                for future in as_completed(futures):
                    task = futures[future]
                    try:
                        result = future.result()
                        with self._results_lock:
                            self.results.append(result)

                        if fail_fast and result.status == "failed":
                            with self._stop_lock:
                                self.global_stop = True
                                self.stop_reason = f"fail_fast: {task['task_id']} failed"
                                self.stop_type = "failure"
                            # Cancel pending futures
                            for f in futures:
                                f.cancel()
                            return

                    except Exception as e:
                        print(f"      ERROR in parallel task {task['task_id']}: {e}")
                        # Create failed result
                        result = self._generate_result(
                            task,
                            status="failed",
                            started_at=datetime.utcnow(),
                            completed_at=datetime.utcnow(),
                            tool_output={},
                            errors=[TaskError(code="E999", message=str(e), recoverable=False)],
                            stop_reason="error"
                        )
                        with self._results_lock:
                            self.results.append(result)

        # Execute browser tasks sequentially (browser lock already handled in execute_task)
        for task in browser_tasks:
            with self._stop_lock:
                if self.global_stop:
                    return

            result = self.execute_task(task)
            with self._results_lock:
                self.results.append(result)

            if fail_fast and result.status == "failed":
                with self._stop_lock:
                    self.global_stop = True
                    self.stop_reason = f"fail_fast: {task['task_id']} failed"
                    self.stop_type = "failure"
                return

    def _write_execution_summary(self):
        """Write execution summary to evidence directory."""
        summary = {
            "plan_id": self.plan.get("plan_id", ""),
            "executed_at": datetime.utcnow().isoformat() + "Z",
            "total_tasks": len(self.plan.get("tasks", [])),
            "completed_tasks": len(self.completed_tasks),
            "skipped_tasks": len(self.skipped_tasks),
            "results": [r.to_dict() for r in self.results],
            "global_stop": self.global_stop,
            "stop_reason": self.stop_reason,
            "stop_type": self.stop_type  # "intentional" or "failure"
        }

        summary_path = self.evidence_dir / "EXECUTION_SUMMARY.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)


def run_bq_executor(
    plan_path: Path,
    run_dir: Path,
    project_path: Path,
    prior_results: list[dict] = None
) -> list[TaskResult]:
    """
    Convenience function to run BQ executor.

    Args:
        plan_path: Path to PLAN.json
        run_dir: Run directory for output
        project_path: Project root path
        prior_results: Optional list of prior task results for resume

    Returns:
        List of TaskResult objects
    """
    executor = BQExecutor(plan_path, run_dir, project_path, prior_results)
    return executor.execute()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="BQ Executor - Task Runner")
    parser.add_argument("--plan", required=True, help="Path to PLAN.json")
    parser.add_argument("--run-dir", required=True, help="Run directory")
    parser.add_argument("--project", required=True, help="Project root path")

    args = parser.parse_args()

    results = run_bq_executor(
        Path(args.plan),
        Path(args.run_dir),
        Path(args.project)
    )

    print(f"\nExecuted {len(results)} tasks")
    for r in results:
        print(f"  {r.task_id}: {r.status}")
