# RUN_STATES v1.0.0
**Purpose:** State machine definition for BECCA orchestration

---

## State Diagram

```
                    ┌─────────────────────────────────────────────────────┐
                    │                                                     │
                    ▼                                                     │
┌──────┐    ┌──────────┐    ┌───────────┐    ┌───────────────────┐       │
│ INIT │───▶│ PLANNING │───▶│ EXECUTING │───▶│ AWAITING_APPROVAL │       │
└──────┘    └──────────┘    └───────────┘    └───────────────────┘       │
                                  │                    │                  │
                                  │                    │ (approved)       │
                                  │                    ▼                  │
                                  │           ┌───────────┐               │
                                  │           │ VERIFYING │───────────────┤
                                  │           └───────────┘               │
                                  │                    │                  │
                                  │                    ▼                  │
                                  │           ┌──────────┐    ┌──────────┐
                                  │           │ AUDITING │───▶│ COMPLETE │
                                  │           └──────────┘    └──────────┘
                                  │                    │
                                  ▼                    ▼
                         ┌───────────────┐    ┌─────────────┐
                         │ HALTED_UNSAFE │    │ ROLLED_BACK │
                         └───────────────┘    └─────────────┘
```

---

## State Definitions

| State | Description | Entry Condition | Exit Condition |
|-------|-------------|-----------------|----------------|
| `INIT` | Run created, not started | `run_id` generated | Planning begins |
| `PLANNING` | Analyzing project, selecting tools | INIT complete | Plan approved or auto-approved |
| `EXECUTING` | Tools running in sequence | Plan ready | All tools complete OR needs approval |
| `AWAITING_APPROVAL` | Paused for human decision | High-risk action detected | Human approves/rejects |
| `VERIFYING` | Checking results, running tests | Execution complete | Verification pass/fail |
| `AUDITING` | Horsemen review | Verification passed | Audit complete |
| `COMPLETE` | Run finished successfully | Audit passed | — (terminal) |
| `ROLLED_BACK` | Changes reverted | Failure or rejection | — (terminal) |
| `HALTED_UNSAFE` | Stopped due to safety concern | Critical risk detected | — (terminal, requires investigation) |

---

## State Transitions

### Valid Transitions

```
INIT → PLANNING
PLANNING → EXECUTING
PLANNING → HALTED_UNSAFE (if critical risk in plan)

EXECUTING → AWAITING_APPROVAL (high-risk action)
EXECUTING → VERIFYING (all tools pass)
EXECUTING → HALTED_UNSAFE (critical failure)
EXECUTING → ROLLED_BACK (tool failure + rollback)

AWAITING_APPROVAL → EXECUTING (approved, continue)
AWAITING_APPROVAL → ROLLED_BACK (rejected)
AWAITING_APPROVAL → HALTED_UNSAFE (timeout or escalation)

VERIFYING → AUDITING (tests pass)
VERIFYING → ROLLED_BACK (tests fail)

AUDITING → COMPLETE (audit pass)
AUDITING → ROLLED_BACK (audit fail)
```

### Invalid Transitions (NEVER allow)

```
COMPLETE → anything (terminal)
ROLLED_BACK → anything (terminal)
HALTED_UNSAFE → anything (terminal, requires new run)
EXECUTING → COMPLETE (must verify first)
INIT → EXECUTING (must plan first)
```

---

## RUN_STATE.json Schema

```json
{
  "run_id": "RUN-PROJECT-20260131-120000",
  "project_id": "PROJECT",
  "current_state": "EXECUTING",
  "previous_state": "PLANNING",
  "state_history": [
    {"state": "INIT", "entered_at": "2026-01-31T12:00:00Z", "exited_at": "2026-01-31T12:00:01Z"},
    {"state": "PLANNING", "entered_at": "2026-01-31T12:00:01Z", "exited_at": "2026-01-31T12:00:05Z"},
    {"state": "EXECUTING", "entered_at": "2026-01-31T12:00:05Z", "exited_at": null}
  ],
  "tools_planned": ["tool_inspector", "tool_browser", "tool_reporter"],
  "tools_completed": ["tool_inspector"],
  "tools_remaining": ["tool_browser", "tool_reporter"],
  "current_tool": "tool_browser",
  "approvals_pending": [],
  "approvals_granted": [],
  "created_at": "2026-01-31T12:00:00Z",
  "updated_at": "2026-01-31T12:00:30Z"
}
```

---

## Approval State Transitions

Approvals are NOT booleans. They are state machines:

```
┌─────────────────────┐
│ REQUEST_APPROVAL    │ (tool requests approval)
└─────────────────────┘
           │
           ▼
┌─────────────────────┐
│ AWAITING_HUMAN      │ (saved to PENDING/)
└─────────────────────┘
           │
     ┌─────┴─────┐
     ▼           ▼
┌─────────┐ ┌──────────┐
│ APPROVED│ │ REJECTED │
└─────────┘ └──────────┘
     │           │
     ▼           ▼
┌─────────┐ ┌──────────┐
│ EXECUTED│ │ ABORTED  │
└─────────┘ └──────────┘
```

---

## Timeout Rules

| State | Max Duration | On Timeout |
|-------|--------------|------------|
| INIT | 60 seconds | HALTED_UNSAFE |
| PLANNING | 5 minutes | HALTED_UNSAFE |
| EXECUTING | 30 minutes | HALTED_UNSAFE |
| AWAITING_APPROVAL | 24 hours | HALTED_UNSAFE |
| VERIFYING | 10 minutes | ROLLED_BACK |
| AUDITING | 15 minutes | ROLLED_BACK |

---

## State Persistence

State MUST be persisted after every transition:
1. Update `RUN_STATE.json` in run folder
2. Append event to `RUN_LOG.jsonl`
3. Update `RUN_LEDGER.jsonl` in command-center

This ensures recovery after crash.
