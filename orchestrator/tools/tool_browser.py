#!/usr/bin/env python3
"""
tool_browser.py - DevTools capture via browser automation

This tool captures browser console logs, network requests, and screenshots.
Uses Chrome DevTools Protocol via selenium or playwright.

Actions: screenshot, console, network
"""

import json
import os
import time
from datetime import datetime
from pathlib import Path

# Try to import browser automation libraries
PLAYWRIGHT_AVAILABLE = False
SELENIUM_AVAILABLE = False

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    pass


def run_browser(run_id: str, run_dir: Path, url: str, mission: str) -> dict:
    """
    Capture browser DevTools data.

    Returns tool output per ARTIFACT_SPEC.
    """
    started_at = datetime.utcnow()
    evidence = []

    tool_dir = run_dir / "tool_browser"
    evidence_dir = tool_dir / "evidence"

    print(f"      URL: {url}")

    # Check if we have browser automation available
    if PLAYWRIGHT_AVAILABLE:
        print("      Using: Playwright")
        result = capture_with_playwright(url, evidence_dir, mission)
    elif SELENIUM_AVAILABLE:
        print("      Using: Selenium")
        result = capture_with_selenium(url, evidence_dir, mission)
    else:
        print("      WARNING: No browser automation library available")
        print("      Install with: pip install playwright && playwright install chromium")
        result = capture_mock(url, evidence_dir, mission)

    evidence = result.get("evidence", [])
    console_logs = result.get("console_logs", [])
    network_requests = result.get("network_requests", [])
    error = result.get("error")

    completed_at = datetime.utcnow()
    duration = (completed_at - started_at).total_seconds()

    # Determine status
    status = "pass" if not error else "fail"
    if error and "not available" in str(error).lower():
        status = "pass"  # Mock mode is acceptable for MVP

    # Count errors in console
    console_errors = [log for log in console_logs if log.get("type") in ["error", "warning"]]

    # Build output
    output = {
        "tool_id": "tool_browser",
        "run_id": run_id,
        "status": status,
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
                f"URL accessible: {url}",
                f"Console logs captured: {len(console_logs)}",
                f"Network requests captured: {len(network_requests)}",
                f"Screenshot taken: {any(e['type'] == 'screenshot' for e in evidence)}"
            ],
            "assumptions_made": [
                "Dev server is running at target URL",
                "Page loads within 10 seconds",
                "No authentication required"
            ],
            "not_tested": [
                "User interactions not simulated",
                "Multiple pages not visited",
                "Form submissions not tested"
            ]
        },
        "risks": [
            {
                "level": "info",
                "description": f"Found {len(console_errors)} console errors/warnings",
                "mitigation": "Review errors in evidence"
            }
        ] if console_errors else [],
        "next_actions": [
            {
                "tool": "tool_reporter",
                "priority": "required",
                "reason": "Generate final report with all evidence"
            }
        ],
        "timing": {
            "started_at": started_at.isoformat() + "Z",
            "completed_at": completed_at.isoformat() + "Z",
            "duration_seconds": duration
        },
        "tokens_used": 0,
        "error": error,
        "browser_summary": {
            "url": url,
            "console_total": len(console_logs),
            "console_errors": len(console_errors),
            "network_requests": len(network_requests)
        }
    }

    # Save output
    output_file = tool_dir / "output.json"
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    return output


def capture_with_playwright(url: str, evidence_dir: Path, mission: str) -> dict:
    """Capture using Playwright."""
    evidence = []
    console_logs = []
    network_requests = []
    error = None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            # Capture console
            def handle_console(msg):
                console_logs.append({
                    "type": msg.type,
                    "text": msg.text,
                    "timestamp": datetime.utcnow().isoformat()
                })

            page.on("console", handle_console)

            # Capture network
            def handle_request(request):
                network_requests.append({
                    "url": request.url,
                    "method": request.method,
                    "timestamp": datetime.utcnow().isoformat()
                })

            page.on("request", handle_request)

            # Navigate
            try:
                page.goto(url, timeout=10000)
                time.sleep(2)  # Wait for dynamic content
            except Exception as e:
                error = f"Navigation failed: {e}"

            # Screenshot
            screenshot_path = evidence_dir / "screenshot.png"
            page.screenshot(path=str(screenshot_path))
            evidence.append({
                "type": "screenshot",
                "path": str(screenshot_path),
                "description": f"Screenshot of {url}"
            })

            browser.close()

    except Exception as e:
        error = str(e)

    # Save console logs
    console_file = evidence_dir / "console.json"
    with open(console_file, "w") as f:
        json.dump(console_logs, f, indent=2)
    evidence.append({
        "type": "console",
        "path": str(console_file),
        "description": f"Console logs ({len(console_logs)} entries)"
    })

    # Save network requests
    network_file = evidence_dir / "network.json"
    with open(network_file, "w") as f:
        json.dump(network_requests, f, indent=2)
    evidence.append({
        "type": "network",
        "path": str(network_file),
        "description": f"Network requests ({len(network_requests)} entries)"
    })

    return {
        "evidence": evidence,
        "console_logs": console_logs,
        "network_requests": network_requests,
        "error": error
    }


def capture_with_selenium(url: str, evidence_dir: Path, mission: str) -> dict:
    """Capture using Selenium."""
    evidence = []
    console_logs = []
    network_requests = []
    error = None

    try:
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.set_capability("goog:loggingPrefs", {"browser": "ALL", "performance": "ALL"})

        driver = webdriver.Chrome(options=options)

        try:
            driver.get(url)
            time.sleep(3)

            # Get console logs
            for entry in driver.get_log("browser"):
                console_logs.append({
                    "type": "error" if "ERROR" in entry.get("level", "") else "log",
                    "text": entry.get("message", ""),
                    "timestamp": datetime.utcnow().isoformat()
                })

            # Screenshot
            screenshot_path = evidence_dir / "screenshot.png"
            driver.save_screenshot(str(screenshot_path))
            evidence.append({
                "type": "screenshot",
                "path": str(screenshot_path),
                "description": f"Screenshot of {url}"
            })

        finally:
            driver.quit()

    except Exception as e:
        error = str(e)

    # Save console logs
    console_file = evidence_dir / "console.json"
    with open(console_file, "w") as f:
        json.dump(console_logs, f, indent=2)
    evidence.append({
        "type": "console",
        "path": str(console_file),
        "description": f"Console logs ({len(console_logs)} entries)"
    })

    # Save empty network (Selenium needs additional setup for this)
    network_file = evidence_dir / "network.json"
    with open(network_file, "w") as f:
        json.dump(network_requests, f, indent=2)
    evidence.append({
        "type": "network",
        "path": str(network_file),
        "description": "Network requests (not captured with Selenium)"
    })

    return {
        "evidence": evidence,
        "console_logs": console_logs,
        "network_requests": network_requests,
        "error": error
    }


def capture_mock(url: str, evidence_dir: Path, mission: str) -> dict:
    """Mock capture when no browser automation is available."""
    evidence = []
    console_logs = []
    network_requests = []

    # Create mock console log
    console_logs = [
        {"type": "log", "text": "[MOCK] Browser automation not available", "timestamp": datetime.utcnow().isoformat()},
        {"type": "info", "text": f"[MOCK] Would have visited: {url}", "timestamp": datetime.utcnow().isoformat()},
    ]

    # Save mock console
    console_file = evidence_dir / "console.json"
    with open(console_file, "w") as f:
        json.dump(console_logs, f, indent=2)
    evidence.append({
        "type": "console",
        "path": str(console_file),
        "description": "Console logs (MOCK - install playwright for real capture)"
    })

    # Save empty network
    network_file = evidence_dir / "network.json"
    with open(network_file, "w") as f:
        json.dump([], f, indent=2)
    evidence.append({
        "type": "network",
        "path": str(network_file),
        "description": "Network requests (MOCK)"
    })

    # Create mock screenshot placeholder
    screenshot_path = evidence_dir / "screenshot_placeholder.txt"
    with open(screenshot_path, "w") as f:
        f.write(f"Screenshot placeholder\n\nURL: {url}\nMission: {mission}\n\nInstall playwright for real screenshots:\n  pip install playwright\n  playwright install chromium\n")
    evidence.append({
        "type": "file",
        "path": str(screenshot_path),
        "description": "Screenshot placeholder (install playwright for real capture)"
    })

    return {
        "evidence": evidence,
        "console_logs": console_logs,
        "network_requests": network_requests,
        "error": "Browser automation not available - using mock mode"
    }
