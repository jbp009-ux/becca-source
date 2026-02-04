#!/usr/bin/env python3
"""
activate_becca.py - Activate BECCA (PMX-01) for autonomous task execution

Usage:
    python activate_becca.py "Your task description here"
    python activate_becca.py --file task.md
    python activate_becca.py --interactive

Examples:
    python activate_becca.py "Add dark mode to Sonny dashboard"
    python activate_becca.py "Fix the checkout bug in CartDrawer.tsx"
    python activate_becca.py "Run security audit on firestore.rules"
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime, timezone

# Fix Windows Unicode output (cp1252 can't handle emojis)
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Check for API key
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    print("❌ ANTHROPIC_API_KEY not set!")
    print("   Run: export ANTHROPIC_API_KEY='sk-ant-...'")
    sys.exit(1)

try:
    from anthropic import Anthropic
except ImportError:
    print("❌ anthropic package not installed!")
    print("   Run: pip install anthropic")
    sys.exit(1)


# Paths
BECCA_KERNEL_ROOT = Path(__file__).parent
SONNY_ROOT = Path("d:/projects/sonny")
BECCA_PROMPT_PATH = SONNY_ROOT / "governance/prompts/pmx/roles/PMX-01_BECCA-exec.md"


def load_becca_prompt() -> str:
    """Load BECCA's system prompt from file."""
    if not BECCA_PROMPT_PATH.exists():
        print(f"❌ BECCA prompt not found at {BECCA_PROMPT_PATH}")
        sys.exit(1)
    return BECCA_PROMPT_PATH.read_text(encoding="utf-8")


def create_task_packet(task: str, project: str = "sonny") -> dict:
    """Create a structured task packet for BECCA."""
    return {
        "from": "GUARDIAN",
        "to": "PMX-01",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "project": project,
        "task": task,
        "context": {
            "working_dir": str(SONNY_ROOT),
            "becca_kernel": str(BECCA_KERNEL_ROOT),
        }
    }


def activate_becca(task: str, project: str = "sonny") -> str:
    """
    Activate BECCA with a task.

    Returns BECCA's response.
    """
    client = Anthropic(api_key=ANTHROPIC_API_KEY)

    # Load BECCA's prompt
    becca_prompt = load_becca_prompt()

    # Create task packet
    task_packet = create_task_packet(task, project)

    print("=" * 60)
    print("🐜👑 ACTIVATING BECCA (PMX-01)")
    print("=" * 60)
    print(f"Task: {task}")
    print(f"Project: {project}")
    print("-" * 60)

    # Call BECCA
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=8192,
        system=becca_prompt,
        messages=[
            {
                "role": "user",
                "content": f"""## GUARDIAN TASK REQUEST

{json.dumps(task_packet, indent=2)}

---

**Task:** {task}

Please proceed with autonomous execution. Report back when complete or if you need Guardian escalation.
"""
            }
        ]
    )

    # Extract response
    becca_response = response.content[0].text

    print("\n" + "=" * 60)
    print("📋 BECCA RESPONSE")
    print("=" * 60)
    print(becca_response)
    print("=" * 60)

    # Save response to artifacts
    artifacts_dir = BECCA_KERNEL_ROOT / "artifacts" / "becca_runs"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    response_file = artifacts_dir / f"becca_response_{timestamp}.md"
    response_file.write_text(f"""# BECCA Response
**Timestamp:** {datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
**Task:** {task}
**Project:** {project}

---

{becca_response}
""", encoding="utf-8")

    print(f"\n💾 Response saved to: {response_file}")

    return becca_response


def interactive_mode():
    """Run BECCA in interactive mode."""
    print("=" * 60)
    print("🐜👑 BECCA INTERACTIVE MODE")
    print("=" * 60)
    print("Type your tasks. BECCA will execute autonomously.")
    print("Type 'exit' or 'quit' to stop.")
    print("-" * 60)

    while True:
        try:
            task = input("\n🗣️ Guardian > ").strip()
            if task.lower() in ("exit", "quit", "q"):
                print("👋 BECCA signing off.")
                break
            if not task:
                continue
            activate_becca(task)
        except KeyboardInterrupt:
            print("\n👋 BECCA signing off.")
            break


def main():
    parser = argparse.ArgumentParser(
        description="Activate BECCA (PMX-01) for autonomous task execution"
    )
    parser.add_argument(
        "task",
        nargs="?",
        help="Task description for BECCA"
    )
    parser.add_argument(
        "--file", "-f",
        help="Read task from file"
    )
    parser.add_argument(
        "--project", "-p",
        default="sonny",
        help="Project name (default: sonny)"
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Run in interactive mode"
    )

    args = parser.parse_args()

    if args.interactive:
        interactive_mode()
    elif args.file:
        task = Path(args.file).read_text(encoding="utf-8")
        activate_becca(task, args.project)
    elif args.task:
        activate_becca(args.task, args.project)
    else:
        parser.print_help()
        print("\n❌ No task provided. Use --interactive for interactive mode.")
        sys.exit(1)


if __name__ == "__main__":
    main()
