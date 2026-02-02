#!/usr/bin/env python3
"""
becca_chat.py - Web chat interface for BECCA (PMX-01)

Usage:
    python becca_chat.py

Then open: http://localhost:5000
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

try:
    from anthropic import Anthropic
except ImportError:
    print("[ERROR] Required packages not installed!")
    print("   Run: pip install anthropic flask flask-cors python-dotenv")
    sys.exit(1)

# Paths
BECCA_KERNEL_ROOT = Path(__file__).parent
ENV_FILE = BECCA_KERNEL_ROOT / ".env"

# Load .env file if it exists
def load_env():
    """Load API key from .env file."""
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip()

load_env()
SONNY_ROOT = Path("d:/projects/sonny")
# For deployment, use local prompt file
BECCA_PROMPT_PATH = BECCA_KERNEL_ROOT / "prompts/PMX-01_BECCA-exec.md"
# Fallback to sonny path for local development
if not BECCA_PROMPT_PATH.exists():
    BECCA_PROMPT_PATH = SONNY_ROOT / "governance/prompts/pmx/roles/PMX-01_BECCA-exec.md"

# Flask app
app = Flask(__name__, template_folder=str(BECCA_KERNEL_ROOT / "templates"))
CORS(app)

# Session storage (in-memory for simplicity)
sessions = {}

# Global API key (can be set via env or browser)
api_key_storage = {
    "key": os.environ.get("ANTHROPIC_API_KEY", "")
}


def get_client():
    """Get Anthropic client with current API key."""
    if not api_key_storage["key"]:
        return None
    return Anthropic(api_key=api_key_storage["key"])


def load_becca_prompt() -> str:
    """Load BECCA's system prompt from file."""
    if not BECCA_PROMPT_PATH.exists():
        return "ERROR: BECCA prompt not found"
    return BECCA_PROMPT_PATH.read_text(encoding="utf-8")


def get_session(session_id: str) -> dict:
    """Get or create a session."""
    if session_id not in sessions:
        sessions[session_id] = {
            "messages": [],
            "injected": False,
            "system_prompt": None
        }
    return sessions[session_id]


@app.route("/")
def index():
    """Serve the chat interface."""
    return render_template("chat.html")


def save_key_to_env(key: str):
    """Save API key to .env file for permanent storage."""
    ENV_FILE.write_text(f"ANTHROPIC_API_KEY={key}\n")
    print(f"[INFO] API key saved to {ENV_FILE}", flush=True)


@app.route("/api/set_key", methods=["POST"])
def set_api_key():
    """Set the API key from the browser."""
    data = request.json
    key = data.get("api_key", "").strip()
    save_permanently = data.get("save", True)  # Default to saving permanently

    if not key:
        return jsonify({"error": "No API key provided"}), 400

    if not key.startswith("sk-ant-"):
        return jsonify({"error": "Invalid API key format. Must start with 'sk-ant-'"}), 400

    api_key_storage["key"] = key

    # Save to .env file for permanent storage
    if save_permanently:
        save_key_to_env(key)

    return jsonify({
        "success": True,
        "message": "API key set and saved permanently!" if save_permanently else "API key set for this session",
        "has_key": True,
        "saved": save_permanently
    })


@app.route("/api/check_key", methods=["GET"])
def check_api_key():
    """Check if API key is set."""
    has_key = bool(api_key_storage["key"])
    return jsonify({
        "has_key": has_key,
        "key_preview": api_key_storage["key"][:20] + "..." if has_key else None
    })


@app.route("/api/inject", methods=["POST"])
def inject_becca():
    """Inject BECCA's prompt into the session."""
    data = request.json
    session_id = data.get("session_id", "default")

    if not api_key_storage["key"]:
        return jsonify({
            "error": "API key not set. Enter your Anthropic API key first.",
            "needs_key": True
        }), 400

    session = get_session(session_id)
    session["system_prompt"] = load_becca_prompt()
    session["injected"] = True
    session["messages"] = []  # Clear previous messages

    return jsonify({
        "success": True,
        "message": "BECCA (PMX-01) injected and ready!",
        "injected": True
    })


@app.route("/api/test_key", methods=["POST"])
def test_api_key():
    """Test the API key with a simple call."""
    import sys
    print("[TEST] Testing API key...", flush=True)
    sys.stderr.write("[TEST] Testing API key...\n")
    sys.stderr.flush()

    if not api_key_storage["key"]:
        return jsonify({"error": "No API key set"}), 400

    try:
        client = get_client()
        # Simple test call
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=50,
            messages=[{"role": "user", "content": "Say 'API OK' in 2 words"}]
        )
        result = response.content[0].text
        print(f"[TEST] SUCCESS: {result}", flush=True)
        return jsonify({"success": True, "response": result})
    except Exception as e:
        error_msg = str(e)
        print(f"[TEST] FAILED: {error_msg}", flush=True)
        sys.stderr.write(f"[TEST] FAILED: {error_msg}\n")
        sys.stderr.flush()
        return jsonify({"error": error_msg}), 500


@app.route("/api/chat", methods=["POST"])
def chat():
    """Send a message to BECCA."""
    import sys
    print("[CHAT] Request received!", flush=True)
    sys.stderr.write("[CHAT] Request received!\n")
    sys.stderr.flush()

    data = request.json
    session_id = data.get("session_id", "default")
    user_message = data.get("message", "")
    image_data = data.get("image")  # Base64 data URL

    print(f"[CHAT] Message: {user_message[:50] if user_message else '(no text)'}", flush=True)
    print(f"[CHAT] Has image: {bool(image_data)}", flush=True)
    print(f"[CHAT] API key set: {bool(api_key_storage['key'])}", flush=True)

    if not user_message and not image_data:
        return jsonify({"error": "No message provided"}), 400

    if not api_key_storage["key"]:
        return jsonify({
            "error": "API key not set. Enter your Anthropic API key first.",
            "needs_key": True
        }), 400

    session = get_session(session_id)

    if not session["injected"]:
        return jsonify({
            "error": "BECCA not injected. Click the injection button first.",
            "injected": False
        }), 400

    # Build message content (text only or multimodal with image)
    if image_data:
        # Extract base64 data and media type from data URL
        # Format: data:image/png;base64,<base64_data>
        try:
            header, base64_data = image_data.split(",", 1)
            media_type = header.split(":")[1].split(";")[0]  # e.g., "image/png"
        except (ValueError, IndexError):
            return jsonify({"error": "Invalid image format"}), 400

        # Multimodal content with image
        message_content = [
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": media_type,
                    "data": base64_data
                }
            }
        ]
        if user_message:
            message_content.append({
                "type": "text",
                "text": user_message
            })
    else:
        # Text-only message
        message_content = user_message

    # Add user message to history
    session["messages"].append({
        "role": "user",
        "content": message_content
    })

    try:
        # Get client and call BECCA
        client = get_client()
        if not client:
            return jsonify({"error": "API key not configured"}), 500

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=8192,
            system=session["system_prompt"],
            messages=session["messages"]
        )

        # Extract response
        assistant_message = response.content[0].text

        # Add to history
        session["messages"].append({
            "role": "assistant",
            "content": assistant_message
        })

        # Save to artifacts
        save_response(user_message or "(Screenshot)", assistant_message)

        return jsonify({
            "success": True,
            "response": assistant_message,
            "injected": True
        })

    except Exception as e:
        error_msg = str(e)
        print(f"[ERROR] API call failed: {error_msg}", flush=True)  # Log actual error
        import sys; sys.stderr.write(f"[ERROR] {error_msg}\n"); sys.stderr.flush()

        # Check for specific auth errors (not just any "invalid")
        is_auth_error = (
            "401" in error_msg or
            "authentication" in error_msg.lower() or
            "invalid api key" in error_msg.lower() or
            "invalid x-api-key" in error_msg.lower()
        )

        if is_auth_error:
            return jsonify({
                "error": "Invalid API key. Please check your key and try again.",
                "needs_key": True
            }), 401
        return jsonify({
            "error": error_msg,
            "injected": session["injected"]
        }), 500


@app.route("/api/clear", methods=["POST"])
def clear_session():
    """Clear the current session."""
    data = request.json
    session_id = data.get("session_id", "default")

    if session_id in sessions:
        sessions[session_id] = {
            "messages": [],
            "injected": False,
            "system_prompt": None
        }

    return jsonify({
        "success": True,
        "message": "Session cleared",
        "injected": False
    })


def save_response(user_message: str, assistant_message: str):
    """Save response to artifacts."""
    artifacts_dir = BECCA_KERNEL_ROOT / "artifacts" / "becca_chats"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    response_file = artifacts_dir / f"chat_{timestamp}.md"
    response_file.write_text(f"""# BECCA Chat
**Timestamp:** {datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}

## User
{user_message}

## BECCA
{assistant_message}
""", encoding="utf-8")


if __name__ == "__main__":
    print("=" * 60)
    print("BECCA WEB CHAT")
    print("=" * 60)
    if api_key_storage["key"]:
        print(f"API Key: {api_key_storage['key'][:20]}...")
    else:
        print("API Key: Not set (enter in browser)")
    print("Open: http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)
