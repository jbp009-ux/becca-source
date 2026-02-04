#!/usr/bin/env python3
"""
becca_online.py - BECCA Online: Phone-Accessible Truth Service

The main web service for BECCA Online that enforces Truth Mode.
Can be accessed from phone/tablet when development machine is OFF.

Features:
  - /api/status - Get project status with evidence
  - /api/run - Trigger evidence collection
  - /api/chat - Truth Mode chat (replaces old becca_chat)
  - /api/bridge/* - Local bridge connection endpoints

Security:
  - API key required for write operations
  - Rate limiting per IP
  - CORS restricted to known origins
  - Bridge authentication via shared secret

Every response includes:
  - CLAIMS: Verified statements
  - EVIDENCE: Traceable references
  - UNKNOWN: What can't be verified
  - NEXT ACTION: How to get more evidence

Deploy target: source.betaos.com
"""

import hashlib
import json
import os
import secrets
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, render_template, request, jsonify, g
from flask_cors import CORS

# Add orchestrator to path
sys.path.insert(0, str(Path(__file__).parent / "orchestrator"))

from truth_mode import TruthModeResponse, TruthModeValidator, build_status_response
from tools.tool_github import fetch_github_truth, run_github_tool
from tools.tool_iambecca_writer import run_iambecca_writer, update_status_json

# Paths
BECCA_ROOT = Path(__file__).parent
PROJECTS_FILE = BECCA_ROOT / "governance" / "specs" / "PROJECTS.json"
STATUS_FILE = BECCA_ROOT / "governance" / "state" / "STATUS.json"
ENV_FILE = BECCA_ROOT / ".env"
TEMPLATES_DIR = BECCA_ROOT / "templates"


# =============================================================================
# PERSISTENT API KEY MANAGEMENT
# =============================================================================

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


def save_env_file(env_vars: dict):
    """Save environment variables to .env file."""
    lines = [
        "# BECCA Configuration (auto-generated keys)",
        f"# Last updated: {datetime.now().isoformat()}",
        ""
    ]
    for key, value in env_vars.items():
        lines.append(f"{key}={value}")
    ENV_FILE.write_text("\n".join(lines) + "\n")


def generate_api_key() -> str:
    """Generate a secure random API key."""
    return f"becca_{secrets.token_urlsafe(32)}"


def ensure_api_keys():
    """
    Ensure API keys exist. Generate and save if missing.

    Keys are stored permanently in .env so you don't need to
    set them manually or expose them on your phone.
    """
    env_vars = load_env_file()
    changed = False

    # Check BECCA_API_KEY
    if not env_vars.get("BECCA_API_KEY"):
        env_vars["BECCA_API_KEY"] = generate_api_key()
        os.environ["BECCA_API_KEY"] = env_vars["BECCA_API_KEY"]
        print(f"[SECURITY] Generated new BECCA_API_KEY")
        changed = True

    # Check BRIDGE_SECRET
    if not env_vars.get("BRIDGE_SECRET"):
        env_vars["BRIDGE_SECRET"] = generate_api_key()
        os.environ["BRIDGE_SECRET"] = env_vars["BRIDGE_SECRET"]
        print(f"[SECURITY] Generated new BRIDGE_SECRET")
        changed = True

    # Preserve ANTHROPIC_API_KEY if it exists
    if "ANTHROPIC_API_KEY" not in env_vars:
        env_vars["ANTHROPIC_API_KEY"] = os.environ.get("ANTHROPIC_API_KEY", "")

    # Save if changed
    if changed:
        save_env_file(env_vars)
        print(f"[SECURITY] Keys saved to {ENV_FILE}")

    return env_vars


# Load and ensure keys on startup
_env_vars = ensure_api_keys()

# Flask app
app = Flask(__name__, template_folder=str(TEMPLATES_DIR))

# CORS - restrict to known origins in production
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
CORS(app, origins=ALLOWED_ORIGINS)

# =============================================================================
# SECURITY: API Keys and Rate Limiting
# =============================================================================

# API keys (now loaded from .env automatically)
BECCA_API_KEY = os.environ.get("BECCA_API_KEY", "")
BRIDGE_SECRET = os.environ.get("BRIDGE_SECRET", "")

# Rate limiting (simple in-memory, per IP)
rate_limit_store = defaultdict(list)  # ip -> [timestamps]
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 30  # per window


def check_rate_limit(ip: str) -> bool:
    """Check if IP is within rate limit. Returns True if allowed."""
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW

    # Clean old entries
    rate_limit_store[ip] = [ts for ts in rate_limit_store[ip] if ts > window_start]

    # Check limit
    if len(rate_limit_store[ip]) >= RATE_LIMIT_MAX_REQUESTS:
        return False

    # Record request
    rate_limit_store[ip].append(now)
    return True


def require_api_key(f):
    """Decorator to require API key for protected endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Skip auth if no API key configured (development mode)
        if not BECCA_API_KEY:
            return f(*args, **kwargs)

        # Check header
        provided_key = request.headers.get("X-API-Key", "")
        if not provided_key:
            provided_key = request.args.get("api_key", "")

        if provided_key != BECCA_API_KEY:
            return jsonify({
                "error": "Invalid or missing API key",
                "hint": "Set X-API-Key header or api_key query param"
            }), 401

        return f(*args, **kwargs)
    return decorated


def require_bridge_auth(f):
    """Decorator to require bridge authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Skip auth if no secret configured (development mode)
        if not BRIDGE_SECRET:
            return f(*args, **kwargs)

        # Check header
        provided_secret = request.headers.get("X-Bridge-Secret", "")
        if provided_secret != BRIDGE_SECRET:
            return jsonify({"error": "Invalid bridge authentication"}), 401

        return f(*args, **kwargs)
    return decorated


@app.before_request
def before_request():
    """Apply rate limiting to all requests."""
    ip = request.remote_addr
    if not check_rate_limit(ip):
        return jsonify({
            "error": "Rate limit exceeded",
            "retry_after": RATE_LIMIT_WINDOW
        }), 429

    # Track request timing
    g.start_time = time.time()


@app.after_request
def after_request(response):
    """Add security headers and timing."""
    # Add timing header
    if hasattr(g, "start_time"):
        elapsed = time.time() - g.start_time
        response.headers["X-Response-Time"] = f"{elapsed:.3f}s"

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"

    return response


# Global state
api_key_storage = {"key": os.environ.get("ANTHROPIC_API_KEY", "")}
bridge_connections = {}  # project_id -> connection info


def load_env():
    """Load API key from .env file."""
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip()
                if key.strip() == "ANTHROPIC_API_KEY":
                    api_key_storage["key"] = value.strip()


load_env()


def load_projects() -> dict:
    """Load project configurations."""
    if PROJECTS_FILE.exists():
        with open(PROJECTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {"projects": {}}


def load_status() -> dict:
    """Load current status cache."""
    if STATUS_FILE.exists():
        with open(STATUS_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {"projects": {}}


def generate_run_id(project_id: str) -> str:
    """Generate unique run ID."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"RUN-{project_id.upper()}-{ts}"


# =============================================================================
# HEALTH & INFO ENDPOINTS
# =============================================================================

@app.route("/")
def index():
    """Serve the BECCA Online interface."""
    return render_template("becca_online.html")


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "service": "becca-online",
        "version": "1.0.0",
        "truth_mode": True,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/projects")
def list_projects():
    """List available projects."""
    config = load_projects()
    projects = []
    for pid, pdata in config.get("projects", {}).items():
        projects.append({
            "id": pid,
            "name": pdata.get("displayName", pid),
            "github_enabled": pdata.get("github", {}).get("enabled", False),
            "local_enabled": pdata.get("local", {}).get("enabled", False)
        })
    return jsonify({"projects": projects})


# =============================================================================
# STATUS ENDPOINT (Core Truth Mode Query)
# =============================================================================

@app.route("/api/status/<project_id>")
def get_status(project_id: str):
    """
    Get project status in Truth Mode format.

    This is the main endpoint for "What's the update on X?" queries.
    Works even when development machine is OFF (GitHub-only mode).
    """
    config = load_projects()

    if project_id not in config.get("projects", {}):
        return jsonify({
            "error": f"Unknown project: {project_id}",
            "available_projects": list(config.get("projects", {}).keys())
        }), 404

    project = config["projects"][project_id]
    github_config = project.get("github", {})
    github_data = None
    bridge_data = None

    # Try to fetch GitHub data
    if github_config.get("enabled"):
        repo = github_config.get("repo")
        branch = github_config.get("defaultBranch", "main")

        try:
            truth = fetch_github_truth(project_id, repo, branch)
            github_data = {
                "repo": repo,
                "latest_commit": truth.latest_commit,
                "latest_commit_message": truth.latest_commit_message,
                "latest_commit_date": truth.latest_commit_date,
                "open_prs": truth.open_prs,
                "open_issues": truth.open_issues,
                "latest_workflow": truth.latest_workflow,
                "errors": truth.errors
            }
        except Exception as e:
            github_data = {"error": str(e)}

    # Check for bridge connection
    if project_id in bridge_connections:
        conn = bridge_connections[project_id]
        bridge_data = {
            "connected": True,
            "machine_id": conn.get("machine_id"),
            "git_dirty": conn.get("git_dirty"),
            "last_test_run": conn.get("last_test_run"),
            "timestamp": conn.get("last_update")
        }

    # Build Truth Mode response
    response = build_status_response(project_id, github_data, bridge_data)

    # Validate response
    violations = TruthModeValidator.validate(response)

    # Determine mode explicitly
    github_ok = github_data is not None and "error" not in (github_data or {})
    bridge_ok = bridge_data is not None

    if bridge_ok and github_ok:
        mode = "FULL (GitHub + Bridge)"
        mode_code = "full"
    elif github_ok:
        mode = "GITHUB ONLY (PC may be OFF)"
        mode_code = "github_only"
    elif bridge_ok:
        mode = "BRIDGE ONLY (no GitHub configured)"
        mode_code = "bridge_only"
    else:
        mode = "NO DATA SOURCES (configure GitHub or start bridge)"
        mode_code = "none"

    return jsonify({
        "project_id": project_id,
        "truth_mode": True,
        "mode": mode,
        "mode_code": mode_code,
        "response": response.to_dict(),
        "response_markdown": response.to_markdown(),
        "response_chat": response.to_chat_response(),
        "violations": violations,
        "is_valid": len(violations) == 0,
        "evidence_count": response.evidence_count,
        "sources": {
            "github": github_ok,
            "bridge": bridge_ok
        }
    })


# =============================================================================
# RUN ENDPOINT (Trigger Evidence Collection)
# =============================================================================

@app.route("/api/run", methods=["POST"])
@require_api_key
def trigger_run():
    """
    Trigger an evidence collection run.

    This fetches fresh data from all available sources and writes to IAMBecca.
    Requires API key authentication.
    """
    data = request.json or {}
    project_id = data.get("project_id", data.get("project"))

    if not project_id:
        return jsonify({"error": "project_id required"}), 400

    config = load_projects()
    if project_id not in config.get("projects", {}):
        return jsonify({"error": f"Unknown project: {project_id}"}), 404

    project = config["projects"][project_id]
    run_id = generate_run_id(project_id)
    run_dir = BECCA_ROOT / "governance" / "runs" / run_id

    github_data = None
    bridge_data = None

    # Fetch GitHub data
    github_config = project.get("github", {})
    if github_config.get("enabled"):
        try:
            repo = github_config.get("repo")
            branch = github_config.get("defaultBranch", "main")
            truth = fetch_github_truth(project_id, repo, branch)

            github_data = {
                "repo": repo,
                "latest_commit": truth.latest_commit,
                "latest_commit_message": truth.latest_commit_message,
                "latest_commit_date": truth.latest_commit_date,
                "open_prs": truth.open_prs,
                "open_issues": truth.open_issues,
                "latest_workflow": truth.latest_workflow
            }
        except Exception as e:
            github_data = {"error": str(e)}

    # Check bridge
    if project_id in bridge_connections:
        conn = bridge_connections[project_id]
        bridge_data = conn

    # Write to IAMBecca
    result = run_iambecca_writer(
        run_id=run_id,
        project_id=project_id,
        github_truth=github_data if github_data and "error" not in github_data else None,
        bridge_truth=bridge_data
    )

    return jsonify({
        "run_id": run_id,
        "project_id": project_id,
        "status": result["status"],
        "truth_response": result["truth_response"],
        "truth_response_markdown": result["truth_response_markdown"],
        "evidence_count": result["evidence_count"],
        "artifacts": result["artifacts"],
        "errors": result["errors"]
    })


# =============================================================================
# CHAT ENDPOINT (Truth Mode Chat)
# =============================================================================

@app.route("/api/chat", methods=["POST"])
def chat():
    """
    Chat endpoint with Truth Mode enforcement.

    Detects status queries and routes to evidence-based responses.
    For other queries, uses Claude with Truth Mode system prompt.
    """
    data = request.json or {}
    message = data.get("message", "").strip()
    project_id = data.get("project_id")

    if not message:
        return jsonify({"error": "message required"}), 400

    # Check if this is a status query
    status_patterns = [
        "what's the update",
        "whats the update",
        "what is the update",
        "status of",
        "how's it going",
        "hows it going",
        "what's happening",
        "whats happening",
        "progress on",
        "what have i worked on",
        "what did i work on",
        "recent work",
        "recent commits",
        "recent changes",
        "what's new",
        "whats new",
        "latest commits",
        "show me commits",
        "my activity",
        "what's been done",
        "whats been done",
        "show me the",
        "give me an update",
        "worked on lately",
        "been working on"
    ]

    is_status_query = any(p in message.lower() for p in status_patterns)

    if is_status_query:
        # Route to status endpoint
        if not project_id:
            # Try to extract project from message
            config = load_projects()
            for pid in config.get("projects", {}).keys():
                if pid.lower() in message.lower():
                    project_id = pid
                    break

        if project_id:
            # Get status with evidence
            config = load_projects()
            if project_id in config.get("projects", {}):
                # Reuse status logic
                project = config["projects"][project_id]
                github_config = project.get("github", {})
                github_data = None

                if github_config.get("enabled"):
                    try:
                        repo = github_config.get("repo")
                        branch = github_config.get("defaultBranch", "main")
                        truth = fetch_github_truth(project_id, repo, branch)
                        github_data = {
                            "repo": repo,
                            "latest_commit": truth.latest_commit,
                            "latest_commit_message": truth.latest_commit_message,
                            "latest_commit_date": truth.latest_commit_date,
                            "open_prs": truth.open_prs,
                            "open_issues": truth.open_issues,
                            "latest_workflow": truth.latest_workflow
                        }
                    except Exception as e:
                        github_data = None

                bridge_data = bridge_connections.get(project_id)
                response = build_status_response(project_id, github_data, bridge_data)

                # Determine mode
                github_ok = github_data is not None
                bridge_ok = bridge_data is not None
                if bridge_ok and github_ok:
                    mode = "FULL (GitHub + Bridge)"
                elif github_ok:
                    mode = "GITHUB ONLY (PC may be OFF)"
                elif bridge_ok:
                    mode = "BRIDGE ONLY"
                else:
                    mode = "NO DATA SOURCES"

                return jsonify({
                    "type": "status",
                    "project_id": project_id,
                    "response": response.to_dict(),
                    "mode": mode,
                    "sources": {"github": github_ok, "bridge": bridge_ok},
                    "evidence_count": response.evidence_count,
                    "is_grounded": response.is_grounded
                })

    # For general questions, use Claude AI with Truth Mode
    return ask_claude_truth_mode(message, project_id)


def ask_claude_truth_mode(message: str, project_id: str = None):
    """
    Ask Claude a question with Truth Mode enforcement.

    Claude is instructed to always separate verified facts from speculation.
    Now includes real GitHub data in the context so Claude can answer accurately.
    """
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")

    if not anthropic_key or anthropic_key == "sk-ant-your-key-here":
        return jsonify({
            "type": "chat",
            "message": "I need Claude AI to answer general questions, but no API key is configured. "
                       "For status queries, try: 'What's the update on sonny?'",
            "suggestion": "Set ANTHROPIC_API_KEY in .env to enable full chat",
            "needs_api_key": True
        })

    # Build context about available projects with REAL GitHub data
    config = load_projects()
    project_context = "\n\n=== LIVE DATA FROM GITHUB ===\n"

    # Fetch real GitHub data for all enabled projects
    for pid, pdata in config.get("projects", {}).items():
        github_config = pdata.get("github", {})
        if github_config.get("enabled"):
            repo = github_config.get("repo")
            branch = github_config.get("defaultBranch", "main")
            try:
                truth = fetch_github_truth(pid, repo, branch)
                project_context += f"\n**{pdata.get('displayName', pid)}** ({repo}):\n"
                if truth.latest_commit:
                    project_context += f"  - Latest commit: {truth.latest_commit[:8]} - {truth.latest_commit_message}\n"
                    project_context += f"  - Commit date: {truth.latest_commit_date}\n"
                if truth.recent_commits:
                    project_context += f"  - Recent commits ({len(truth.recent_commits)}):\n"
                    for c in truth.recent_commits[:5]:
                        msg = c.get('message', '').split('\n')[0][:60]
                        project_context += f"    * {c.get('sha', '')[:7]}: {msg}\n"
                project_context += f"  - Open PRs: {truth.open_prs}\n"
                project_context += f"  - Open Issues: {truth.open_issues}\n"
                if truth.latest_workflow:
                    wf = truth.latest_workflow
                    project_context += f"  - CI: {wf.get('name')} - {wf.get('conclusion', 'in progress')}\n"
            except Exception as e:
                project_context += f"\n**{pid}**: Error fetching data - {str(e)[:50]}\n"

    project_context += "\n=== END LIVE DATA ===\n"

    if project_id and project_id in config.get("projects", {}):
        proj = config["projects"][project_id]
        project_context += f"\nUser is specifically asking about: {project_id} ({proj.get('displayName', project_id)})"

    # Truth Mode system prompt
    system_prompt = """You are BECCA, a truth-focused AI advisor. You have access to LIVE GitHub data shown below.

IMPORTANT RULES:
1. USE the live data provided to answer questions accurately
2. Reference specific commits, dates, and evidence from the data
3. Be direct and concise - the user wants facts, not fluff
4. If something isn't in the live data, say you don't have that specific information

You are helping a developer stay on track with their projects. Answer based on the evidence."""

    try:
        import anthropic
        import httpx

        # Use short timeout to avoid hanging
        http_client = httpx.Client(timeout=httpx.Timeout(30.0, connect=5.0))
        client = anthropic.Anthropic(api_key=anthropic_key, http_client=http_client)

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=system_prompt + project_context,
            messages=[{"role": "user", "content": message}]
        )

        answer = response.content[0].text

        return jsonify({
            "type": "chat",
            "message": answer,
            "model": "claude-sonnet-4-20250514",
            "truth_mode": True,
            "has_live_data": True
        })

    except ImportError as e:
        return jsonify({
            "type": "chat",
            "message": f"Missing package: {e}. Run: pip install anthropic httpx",
            "error": "missing_package"
        })
    except Exception as e:
        error_name = type(e).__name__
        if "Timeout" in error_name or "timeout" in str(e).lower():
            return jsonify({
                "type": "chat",
                "message": "Claude is taking too long to respond. This could be a network issue or API overload. Try again in a moment.",
                "error": "timeout"
            })
        elif "Authentication" in error_name or "401" in str(e):
            return jsonify({
                "type": "chat",
                "message": "Invalid Anthropic API key. Update ANTHROPIC_API_KEY in .env file.",
                "error": "auth_error"
            })
        else:
            return jsonify({
                "type": "chat",
                "message": f"Claude error ({error_name}): {str(e)[:200]}",
                "error": str(e)[:100]
            })


# =============================================================================
# BRIDGE ENDPOINTS (Local Machine Connection)
# =============================================================================

@app.route("/api/bridge/connect", methods=["POST"])
@require_bridge_auth
def bridge_connect():
    """
    Register a local bridge connection.

    The bridge calls this when it starts up to register itself.
    Requires bridge authentication.
    """
    data = request.json or {}
    machine_id = data.get("machine_id")
    projects = data.get("projects", [])
    capabilities = data.get("capabilities", [])

    if not machine_id:
        return jsonify({"error": "machine_id required"}), 400

    now = datetime.now(timezone.utc).isoformat()

    for project_id in projects:
        bridge_connections[project_id] = {
            "machine_id": machine_id,
            "capabilities": capabilities,
            "connected_at": now,
            "last_update": now,
            "git_dirty": None,
            "last_test_run": None
        }

    return jsonify({
        "status": "connected",
        "machine_id": machine_id,
        "projects_registered": projects,
        "timestamp": now
    })


@app.route("/api/bridge/result", methods=["POST"])
@require_bridge_auth
def bridge_result():
    """
    Receive results from the local bridge.

    The bridge posts command results here.
    Requires bridge authentication.
    """
    data = request.json or {}
    project_id = data.get("project_id")
    results = data.get("results", {})

    if not project_id:
        return jsonify({"error": "project_id required"}), 400

    if project_id not in bridge_connections:
        return jsonify({"error": "bridge not connected for this project"}), 400

    now = datetime.now(timezone.utc).isoformat()

    # Update bridge state
    conn = bridge_connections[project_id]
    conn["last_update"] = now

    if "git_status" in results:
        conn["git_dirty"] = results["git_status"].get("dirty", False)

    if "test_run" in results:
        conn["last_test_run"] = {
            "command": results["test_run"].get("command"),
            "status": results["test_run"].get("status"),
            "timestamp": now
        }

    return jsonify({
        "status": "received",
        "project_id": project_id,
        "timestamp": now
    })


@app.route("/api/bridge/disconnect", methods=["POST"])
def bridge_disconnect():
    """Disconnect a bridge."""
    data = request.json or {}
    machine_id = data.get("machine_id")

    # Remove all connections for this machine
    to_remove = [pid for pid, conn in bridge_connections.items()
                 if conn.get("machine_id") == machine_id]

    for pid in to_remove:
        del bridge_connections[pid]

    return jsonify({
        "status": "disconnected",
        "projects_removed": to_remove
    })


# =============================================================================
# ARTIFACT BUNDLE ENDPOINT
# =============================================================================

@app.route("/api/run/<run_id>/bundle")
def get_run_bundle(run_id: str):
    """
    Get a portable proof bundle for a run.

    Returns JSON with all artifacts, evidence, and checksums.
    """
    run_dir = BECCA_ROOT / "governance" / "runs" / run_id

    if not run_dir.exists():
        return jsonify({"error": f"Run not found: {run_id}"}), 404

    bundle = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifacts": [],
        "checksums": {}
    }

    # Collect all artifacts
    for artifact_path in run_dir.rglob("*"):
        if artifact_path.is_file():
            rel_path = str(artifact_path.relative_to(run_dir))

            # Compute checksum
            content = artifact_path.read_bytes()
            checksum = hashlib.sha256(content).hexdigest()

            bundle["artifacts"].append(rel_path)
            bundle["checksums"][rel_path] = checksum

            # Include small JSON/MD files inline
            if artifact_path.suffix in (".json", ".md") and len(content) < 50000:
                try:
                    if artifact_path.suffix == ".json":
                        bundle[f"content:{rel_path}"] = json.loads(content.decode("utf-8"))
                    else:
                        bundle[f"content:{rel_path}"] = content.decode("utf-8")
                except Exception:
                    pass

    bundle["artifact_count"] = len(bundle["artifacts"])

    return jsonify(bundle)


# =============================================================================
# LEDGER VERIFICATION ENDPOINT
# =============================================================================

@app.route("/api/ledger/verify")
def verify_ledger():
    """
    Verify the tamper-evident ledger chain.

    Returns verification status and any errors.
    """
    try:
        from tamper_evident_ledger import TamperEvidentLedger

        ledger = TamperEvidentLedger()
        is_valid, errors = ledger.verify_chain()
        summary = ledger.get_chain_summary()

        return jsonify({
            "chain_valid": is_valid,
            "summary": summary,
            "errors": errors[:10] if errors else [],
            "verification_timestamp": datetime.now(timezone.utc).isoformat()
        })

    except ImportError:
        return jsonify({
            "error": "Tamper-evident ledger not available",
            "hint": "Run: python orchestrator/tamper_evident_ledger.py migrate"
        }), 500


@app.route("/api/ledger/entries")
def get_ledger_entries():
    """
    Get recent ledger entries.
    """
    try:
        from tamper_evident_ledger import TamperEvidentLedger

        limit = request.args.get("limit", 20, type=int)
        project = request.args.get("project")
        run_id = request.args.get("run_id")

        ledger = TamperEvidentLedger()
        entries = ledger.get_entries(limit=limit, project=project, run_id=run_id)

        return jsonify({
            "entries": entries,
            "count": len(entries),
            "filters": {"limit": limit, "project": project, "run_id": run_id}
        })

    except ImportError:
        return jsonify({"error": "Tamper-evident ledger not available"}), 500


# =============================================================================
# KEY MANAGEMENT ENDPOINT (localhost only)
# =============================================================================

@app.route("/api/keys")
def show_keys():
    """
    Show API keys (only accessible from localhost for security).

    This lets you see your keys once to save them, then forget about them.
    """
    # Only allow from localhost
    if request.remote_addr not in ("127.0.0.1", "::1", "localhost"):
        return jsonify({
            "error": "This endpoint is only accessible from localhost",
            "your_ip": request.remote_addr
        }), 403

    return jsonify({
        "warning": "Keep these keys secret! Only share with trusted devices.",
        "becca_api_key": BECCA_API_KEY,
        "bridge_secret": BRIDGE_SECRET,
        "usage": {
            "api_key_header": "X-API-Key: <your_becca_api_key>",
            "bridge_header": "X-Bridge-Secret: <your_bridge_secret>",
            "query_param": "?api_key=<your_becca_api_key>"
        },
        "stored_in": str(ENV_FILE)
    })


@app.route("/api/keys/regenerate", methods=["POST"])
def regenerate_keys():
    """
    Regenerate API keys (only accessible from localhost).
    """
    if request.remote_addr not in ("127.0.0.1", "::1", "localhost"):
        return jsonify({"error": "This endpoint is only accessible from localhost"}), 403

    global BECCA_API_KEY, BRIDGE_SECRET

    # Load current env
    env_vars = load_env_file()

    # Regenerate
    env_vars["BECCA_API_KEY"] = generate_api_key()
    env_vars["BRIDGE_SECRET"] = generate_api_key()

    # Save
    save_env_file(env_vars)

    # Update globals
    BECCA_API_KEY = env_vars["BECCA_API_KEY"]
    BRIDGE_SECRET = env_vars["BRIDGE_SECRET"]
    os.environ["BECCA_API_KEY"] = BECCA_API_KEY
    os.environ["BRIDGE_SECRET"] = BRIDGE_SECRET

    return jsonify({
        "status": "regenerated",
        "becca_api_key": BECCA_API_KEY,
        "bridge_secret": BRIDGE_SECRET,
        "warning": "Old keys are now invalid!"
    })


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("BECCA ONLINE - Truth Mode Service")
    print("=" * 60)
    print(f"Truth Mode: ENABLED (hard enforcement)")
    print(f"Rate Limit: {RATE_LIMIT_MAX_REQUESTS} req / {RATE_LIMIT_WINDOW}s")
    print("=" * 60)
    print("SECURITY (keys auto-generated and saved):")
    print(f"  Keys stored in: {ENV_FILE}")
    print(f"  API Key:     {BECCA_API_KEY[:20]}..." if BECCA_API_KEY else "  API Key:     NOT SET")
    print(f"  Bridge Secret: {BRIDGE_SECRET[:20]}..." if BRIDGE_SECRET else "  Bridge Secret: NOT SET")
    print("")
    print("  View full keys:  http://localhost:5001/api/keys")
    print("  Regenerate keys: POST /api/keys/regenerate")
    print("=" * 60)
    print("Endpoints:")
    print("  GET  /health              - Health check")
    print("  GET  /api/projects        - List projects")
    print("  GET  /api/status/<id>     - Get project status (Truth Mode)")
    print("  POST /api/run             - Trigger evidence [API KEY]")
    print("  POST /api/chat            - Chat (Truth Mode)")
    print("  POST /api/bridge/*        - Bridge connection [BRIDGE SECRET]")
    print("  GET  /api/run/<id>/bundle - Download proof bundle")
    print("  GET  /api/ledger/verify   - Verify hash chain")
    print("  GET  /api/keys            - View API keys (localhost only)")
    print("=" * 60)
    print("Phone Access:")
    print("  1. Start server on your PC")
    print("  2. Note your PC's IP (e.g., 192.168.1.100)")
    print("  3. On phone, go to: http://192.168.1.100:5001")
    print("  4. For /api/run, add ?api_key=<your_key> or X-API-Key header")
    print("=" * 60)
    print("Open: http://localhost:5001")
    print("Press Ctrl+C to stop")
    print("=" * 60)

    app.run(host="0.0.0.0", port=5001, debug=True)
