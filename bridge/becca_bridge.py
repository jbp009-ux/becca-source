#!/usr/bin/env python3
"""
becca_bridge.py - Local Bridge Agent

Runs on the development machine and connects OUTBOUND to BECCA Online.
Provides live truth data that GitHub API can't see:
  - git status (uncommitted changes)
  - Test run results
  - Log file contents
  - Local file searches

SECURITY:
  - Outbound connection only (no open ports)
  - Only runs allowlisted commands
  - Applies redaction before sending
  - Logs all operations
  - Auto-loads BRIDGE_SECRET from .env

Usage:
    python becca_bridge.py --server https://source.betaos.com
    python becca_bridge.py --server http://localhost:5001 --project sonny
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any


# Paths
BECCA_ROOT = Path(__file__).parent.parent
PROJECTS_FILE = BECCA_ROOT / "governance" / "specs" / "PROJECTS.json"
POLICIES_DIR = BECCA_ROOT / "governance" / "policies"
REDACTION_RULES = POLICIES_DIR / "redaction_rules.json"
DENY_GLOBS = POLICIES_DIR / "deny_globs.txt"
ENV_FILE = BECCA_ROOT / ".env"

# Machine ID (persistent across restarts)
MACHINE_ID_FILE = BECCA_ROOT / ".bridge_machine_id"


def load_env_file() -> dict:
    """Load environment variables from .env file."""
    env_vars = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                env_vars[key.strip()] = value.strip()
                os.environ[key.strip()] = value.strip()
    return env_vars


# Load .env on startup
_env_vars = load_env_file()
BRIDGE_SECRET = os.environ.get("BRIDGE_SECRET", "")


def get_machine_id() -> str:
    """Get or create a persistent machine ID."""
    if MACHINE_ID_FILE.exists():
        return MACHINE_ID_FILE.read_text().strip()

    machine_id = f"{platform.node()}-{uuid.uuid4().hex[:8]}"
    MACHINE_ID_FILE.write_text(machine_id)
    return machine_id


def load_projects() -> dict:
    """Load project configurations."""
    if PROJECTS_FILE.exists():
        with open(PROJECTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {"projects": {}}


def load_redaction_rules() -> List[Dict]:
    """Load redaction rules."""
    if REDACTION_RULES.exists():
        with open(REDACTION_RULES, encoding="utf-8") as f:
            data = json.load(f)
            return data.get("rules", [])
    return []


def load_deny_globs() -> List[str]:
    """Load deny glob patterns."""
    if DENY_GLOBS.exists():
        patterns = []
        for line in DENY_GLOBS.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
        return patterns
    return []


def is_command_allowed(command: str, allowed_commands: List[str]) -> bool:
    """Check if a command is in the allowlist."""
    # Exact match or prefix match
    for allowed in allowed_commands:
        if command == allowed:
            return True
        if command.startswith(allowed + " "):
            return True
    return False


def redact_content(content: str, rules: List[Dict]) -> str:
    """Apply redaction rules to content."""
    for rule in rules:
        for pattern in rule.get("patterns", []):
            try:
                redact_with = rule.get("redactWith", "[REDACTED]")
                content = re.sub(pattern, redact_with, content, flags=re.IGNORECASE)
            except re.error:
                pass
    return content


def run_command_safe(command: str, cwd: Path, timeout: int = 30) -> Dict:
    """
    Run a command safely with timeout and capture output.

    Returns dict with status, stdout, stderr, duration.
    """
    start = time.time()
    try:
        result = subprocess.run(
            command,
            shell=True,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace"
        )
        duration = time.time() - start
        return {
            "status": "success" if result.returncode == 0 else "failed",
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration": duration
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "returncode": -1,
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s",
            "duration": timeout
        }
    except Exception as e:
        return {
            "status": "error",
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "duration": time.time() - start
        }


class BeccaBridge:
    """
    Local bridge agent that connects to BECCA Online.

    Security:
    - Only outbound connections
    - Only allowlisted commands
    - Redaction before transmission
    """

    def __init__(self, server_url: str, projects: List[str] = None):
        self.server_url = server_url.rstrip("/")
        self.machine_id = get_machine_id()
        self.config = load_projects()
        self.redaction_rules = load_redaction_rules()
        self.deny_globs = load_deny_globs()

        # Filter to requested projects
        if projects:
            self.project_ids = [p for p in projects if p in self.config.get("projects", {})]
        else:
            # Only projects with local.enabled = true
            self.project_ids = [
                pid for pid, pdata in self.config.get("projects", {}).items()
                if pdata.get("local", {}).get("enabled", False)
            ]

        # Track connection state
        self.connected = False
        self.last_update = None

    def get_project_config(self, project_id: str) -> Optional[Dict]:
        """Get configuration for a project."""
        return self.config.get("projects", {}).get(project_id)

    def get_project_path(self, project_id: str) -> Optional[Path]:
        """Get local path for a project."""
        config = self.get_project_config(project_id)
        if config:
            local = config.get("local", {})
            if local.get("enabled"):
                return Path(local.get("rootPath", ""))
        return None

    def get_allowed_commands(self, project_id: str) -> List[str]:
        """Get allowlisted commands for a project."""
        config = self.get_project_config(project_id)
        if config:
            return config.get("security", {}).get("allowCommands", [])
        return []

    def connect(self) -> bool:
        """Register with BECCA Online server."""
        try:
            import requests
        except ImportError:
            print("[ERROR] requests package required. Install with: pip install requests")
            return False

        # Build headers with auth
        headers = {}
        if BRIDGE_SECRET:
            headers["X-Bridge-Secret"] = BRIDGE_SECRET
            print(f"[AUTH] Using bridge secret from .env")
        else:
            print(f"[WARN] No BRIDGE_SECRET set - auth may fail in production")

        try:
            response = requests.post(
                f"{self.server_url}/api/bridge/connect",
                json={
                    "machine_id": self.machine_id,
                    "projects": self.project_ids,
                    "capabilities": ["git", "npm", "file_search"]
                },
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self.connected = True
                print(f"[OK] Connected to {self.server_url}")
                print(f"     Machine ID: {self.machine_id}")
                print(f"     Projects: {data.get('projects_registered', [])}")
                return True
            elif response.status_code == 401:
                print(f"[ERROR] Authentication failed - check BRIDGE_SECRET in .env")
                return False
            else:
                print(f"[ERROR] Connection failed: {response.status_code}")
                return False

        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
            return False

    def disconnect(self):
        """Disconnect from BECCA Online server."""
        try:
            import requests
            requests.post(
                f"{self.server_url}/api/bridge/disconnect",
                json={"machine_id": self.machine_id},
                timeout=5
            )
        except Exception:
            pass
        self.connected = False

    def collect_truth(self, project_id: str) -> Dict:
        """
        Collect live truth for a project.

        Returns dict with git_status, test_run (if applicable), etc.
        """
        project_path = self.get_project_path(project_id)
        if not project_path or not project_path.exists():
            return {"error": f"Project path not found: {project_path}"}

        allowed_commands = self.get_allowed_commands(project_id)
        results = {}
        now = datetime.now(timezone.utc).isoformat()

        # Git status
        if is_command_allowed("git status", allowed_commands):
            git_result = run_command_safe("git status --porcelain", project_path)
            if git_result["status"] == "success":
                # Redact before storing
                output = redact_content(git_result["stdout"], self.redaction_rules)
                results["git_status"] = {
                    "dirty": len(output.strip()) > 0,
                    "changes": len(output.strip().split("\n")) if output.strip() else 0,
                    "timestamp": now
                }

        # Git log (recent commits)
        if is_command_allowed("git log", allowed_commands):
            git_log = run_command_safe("git log -n 5 --oneline", project_path)
            if git_log["status"] == "success":
                output = redact_content(git_log["stdout"], self.redaction_rules)
                results["git_log"] = {
                    "recent_commits": output.strip().split("\n")[:5],
                    "timestamp": now
                }

        # Git branch
        if is_command_allowed("git branch", allowed_commands):
            branch_result = run_command_safe("git branch --show-current", project_path)
            if branch_result["status"] == "success":
                results["git_branch"] = {
                    "current": branch_result["stdout"].strip(),
                    "timestamp": now
                }

        return results

    def run_tests(self, project_id: str, command: str = "npm test") -> Dict:
        """
        Run tests if the command is allowlisted.

        Returns test result summary (not full output).
        """
        project_path = self.get_project_path(project_id)
        if not project_path:
            return {"error": "Project path not found"}

        allowed_commands = self.get_allowed_commands(project_id)
        if not is_command_allowed(command, allowed_commands):
            return {"error": f"Command not allowed: {command}"}

        result = run_command_safe(command, project_path, timeout=120)
        now = datetime.now(timezone.utc).isoformat()

        # Determine pass/fail from output
        output = result["stdout"] + result["stderr"]
        output = redact_content(output, self.redaction_rules)

        # Look for common test result patterns
        if result["returncode"] == 0:
            status = "pass"
        elif "FAIL" in output or "failed" in output.lower():
            status = "fail"
        else:
            status = "unknown"

        return {
            "command": command,
            "status": status,
            "returncode": result["returncode"],
            "duration": result["duration"],
            "timestamp": now,
            # Only include a summary, not full output
            "summary": output[:500] if len(output) > 500 else output
        }

    def send_results(self, project_id: str, results: Dict) -> bool:
        """Send collected results to BECCA Online."""
        try:
            import requests

            # Build headers with auth
            headers = {}
            if BRIDGE_SECRET:
                headers["X-Bridge-Secret"] = BRIDGE_SECRET

            response = requests.post(
                f"{self.server_url}/api/bridge/result",
                json={
                    "project_id": project_id,
                    "results": results,
                    "machine_id": self.machine_id,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                },
                headers=headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"[ERROR] Failed to send results: {e}")
            return False

    def run_loop(self, interval: int = 60):
        """
        Main loop: periodically collect and send truth.

        Runs until interrupted.
        """
        print(f"\n[BRIDGE] Starting collection loop (interval: {interval}s)")
        print(f"         Projects: {self.project_ids}")
        print(f"         Press Ctrl+C to stop\n")

        while True:
            try:
                for project_id in self.project_ids:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Collecting truth for {project_id}...")

                    # Collect git status and other data
                    truth = self.collect_truth(project_id)

                    if "error" not in truth:
                        # Send to server
                        if self.send_results(project_id, truth):
                            dirty = truth.get("git_status", {}).get("dirty", "?")
                            print(f"         Git dirty: {dirty}")
                        else:
                            print(f"         [WARN] Failed to send results")
                    else:
                        print(f"         [ERROR] {truth.get('error')}")

                self.last_update = datetime.now(timezone.utc).isoformat()
                time.sleep(interval)

            except KeyboardInterrupt:
                print("\n[BRIDGE] Shutting down...")
                self.disconnect()
                break


def main():
    parser = argparse.ArgumentParser(description="BECCA Local Bridge Agent")
    parser.add_argument("--server", default="http://localhost:5001",
                        help="BECCA Online server URL")
    parser.add_argument("--project", action="append", dest="projects",
                        help="Project ID to connect (can specify multiple)")
    parser.add_argument("--interval", type=int, default=60,
                        help="Collection interval in seconds")
    parser.add_argument("--once", action="store_true",
                        help="Collect once and exit (no loop)")

    args = parser.parse_args()

    print("=" * 60)
    print("BECCA LOCAL BRIDGE")
    print("=" * 60)
    print(f"Server: {args.server}")
    print(f"Interval: {args.interval}s")
    print("=" * 60)

    bridge = BeccaBridge(args.server, args.projects)

    if not bridge.project_ids:
        print("[ERROR] No projects to connect")
        sys.exit(1)

    # Connect to server
    if not bridge.connect():
        print("[ERROR] Failed to connect to server")
        sys.exit(1)

    if args.once:
        # Collect once and exit
        for project_id in bridge.project_ids:
            truth = bridge.collect_truth(project_id)
            print(f"\n{project_id}:")
            print(json.dumps(truth, indent=2))
            bridge.send_results(project_id, truth)
    else:
        # Run continuous loop
        bridge.run_loop(args.interval)


if __name__ == "__main__":
    main()
