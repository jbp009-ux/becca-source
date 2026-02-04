# ARTIFACT_SPEC v1.0.0
**Purpose:** Standard I/O contract for all BECCA tools

---

## Tool Input Schema

Every tool BECCA calls receives this structure:

```json
{
  "run_id": "RUN-{PROJECT}-{YYYYMMDD}-{HHMMSS}",
  "tool_id": "tool_{name}",
  "role": "PMX-##",
  "mission": "Clear description of what to accomplish",
  "constraints": ["constraint1", "constraint2"],
  "allowed_actions": ["read", "grep", "bash:specific_command"],
  "environment": "dev|staging|prod",
  "auto_approve_gates": ["D0", "D1"],
  "require_approval": ["D3", "D4"],
  "context": {
    "previous_tool_output": {},
    "target_files": [],
    "pheromone_warnings": []
  },
  "budget": {
    "max_tokens": 10000,
    "max_files": 10,
    "max_time_seconds": 300
  }
}
```

---

## Tool Output Schema

Every tool MUST return this structure:

```json
{
  "tool_id": "tool_{name}",
  "run_id": "RUN-xxx",
  "status": "pass|fail|needs-approval|halted",
  "state": "COMPLETE|AWAITING_APPROVAL|HALTED_UNSAFE",

  "evidence": [
    {
      "type": "file|log|screenshot|diff",
      "path": "governance/runs/RUN-xxx/evidence/file.ext",
      "description": "What this evidence shows"
    }
  ],

  "changes": {
    "files_modified": 0,
    "files_created": 0,
    "lines_added": 0,
    "lines_removed": 0
  },

  "success_reasoning": {
    "invariants_checked": ["list of checks performed"],
    "assumptions_made": ["list of assumptions"],
    "not_tested": ["what was NOT verified"]
  },

  "risks": [
    {
      "level": "critical|high|medium|low|info",
      "description": "What the risk is",
      "mitigation": "How to address it"
    }
  ],

  "next_actions": [
    {
      "tool": "tool_name",
      "priority": "required|recommended|optional",
      "reason": "Why this should run next"
    }
  ],

  "timing": {
    "started_at": "ISO8601",
    "completed_at": "ISO8601",
    "duration_seconds": 0
  },

  "tokens_used": 0,
  "error": null
}
```

---

## Evidence Types

| Type | Extension | Purpose |
|------|-----------|---------|
| `file` | any | Source code, configs read |
| `log` | .log, .txt | Console output, command results |
| `screenshot` | .png | Visual browser state |
| `diff` | .patch, .diff | Code changes made |
| `network` | .har, .json | Network requests captured |
| `console` | .json | Browser console messages |

---

## Status Definitions

| Status | Meaning | Next Action |
|--------|---------|-------------|
| `pass` | Tool completed successfully | Continue to next tool |
| `fail` | Tool encountered error | Log error, may retry or halt |
| `needs-approval` | Waiting for human | Pause until approval granted |
| `halted` | Unsafe condition detected | Stop run, require investigation |

---

## Evidence Storage Convention

```
governance/runs/{RUN_ID}/
├── RUN_STATE.json          # Current state machine state
├── RUN_LOG.jsonl           # Append-only event log
├── FINAL_REPORT.md         # Generated at completion
├── tool_inspector/
│   ├── output.json         # Tool output per spec
│   └── evidence/
│       ├── files_read.json
│       └── grep_results.txt
├── tool_browser/
│   ├── output.json
│   └── evidence/
│       ├── screenshot_001.png
│       ├── console.json
│       └── network.har
└── tool_reporter/
    ├── output.json
    └── evidence/
        └── report.md
```

---

## Validation Rules

1. **run_id** must match pattern `RUN-[A-Z0-9-]+-\d{8}-\d{6}`
2. **evidence** array must not be empty for `pass` status
3. **success_reasoning** required for `pass` status
4. **error** required for `fail` status
5. **risks** with level `critical` or `high` trigger `needs-approval`
