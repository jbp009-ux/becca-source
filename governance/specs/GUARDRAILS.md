# GUARDRAILS v1.0.0
**Purpose:** Safety rules that BECCA and all tools must obey

---

## Cardinal Rules (NEVER violate)

### 1. No Silent Irreversible Actions
Every action that modifies state must:
- Be logged before execution
- Create a backup/snapshot
- Be reversible via rollback

### 2. No Self-Approval of High-Risk Actions
BECCA cannot approve her own requests for:
- Production deployments
- Security rule changes
- Data deletions
- Secret access

### 3. No Execution Without Evidence
Every successful tool run must produce:
- Evidence array (not empty)
- Success reasoning (what was checked)
- Assumptions list (what was assumed)
- Not-tested list (what was skipped)

### 4. No State Skip
Runs must progress through states in order:
- INIT → PLANNING → EXECUTING → VERIFYING → AUDITING → COMPLETE
- Cannot skip from EXECUTING to COMPLETE

### 5. No Recovery From Terminal States
Once a run reaches a terminal state, it cannot be modified:
- COMPLETE (done)
- ROLLED_BACK (reverted)
- HALTED_UNSAFE (frozen)

To continue work, start a NEW run.

---

## HIGH RISK Actions (Always Require Human Approval)

| Action | Risk Level | Why |
|--------|------------|-----|
| Deploy to production | CRITICAL | Affects real users |
| Modify firestore.rules | CRITICAL | Security boundary |
| Modify storage.rules | CRITICAL | Security boundary |
| Delete any file | HIGH | Data loss |
| Access secrets/API keys | HIGH | Credential exposure |
| Create Firebase custom claims | HIGH | Auth escalation |
| Run database migrations | HIGH | Data integrity |
| Merge to main branch | HIGH | Code promotion |
| Modify auth flow | HIGH | Security impact |
| Cross-tenant queries | CRITICAL | Isolation breach |

---

## Auto-Approve Actions (Safe for automation)

| Action | Condition |
|--------|-----------|
| Read files | Always |
| Grep/search | Always |
| List directories | Always |
| Take screenshots | Always |
| Capture console logs | Always |
| Capture network requests | Always |
| Run tests (read-only) | In dev environment |
| Generate reports | Always |

---

## Environment Boundaries

### Development (dev)
- Auto-approve: read, write, test
- Require approval: deploy, secrets

### Staging
- Auto-approve: read, test
- Require approval: write, deploy, secrets

### Production
- Auto-approve: read only
- Require approval: EVERYTHING else

---

## Rate Limits

| Resource | Limit | Per |
|----------|-------|-----|
| API calls (Claude) | 100 | run |
| Tokens | 50,000 | run |
| Files modified | 20 | run |
| Time elapsed | 30 minutes | run |
| Retries per tool | 3 | tool |
| Concurrent tools | 1 | run |

Exceeding limits triggers HALTED_UNSAFE.

---

## Backup Requirements

### Before Every Write
```
governance/runs/{RUN_ID}/backups/
├── {timestamp}_before_tool_xxx/
│   └── {original_file_path_structure}
```

### Before Every Delete
```
governance/runs/{RUN_ID}/deleted/
├── {timestamp}_{filename}
```

### Before Security Rule Changes
```
governance/runs/{RUN_ID}/security_snapshots/
├── firestore.rules.{timestamp}
├── storage.rules.{timestamp}
```

---

## Rollback Protocol

### Automatic Rollback Triggers
1. Tool returns `fail` status
2. Verification fails
3. Audit fails
4. Human rejects approval
5. Timeout exceeded

### Rollback Steps
1. Stop all running tools
2. Restore files from backups
3. Log rollback to RUN_LOG.jsonl
4. Set state to ROLLED_BACK
5. Generate rollback report

### Manual Rollback
```bash
python scripts/rollback_run.py --run-id RUN-xxx
```

---

## Audit Trail Requirements

Every action must log:
```json
{
  "timestamp": "ISO8601",
  "run_id": "RUN-xxx",
  "tool_id": "tool_xxx",
  "action": "what was done",
  "target": "what was affected",
  "before": "state before (hash or snapshot)",
  "after": "state after (hash or snapshot)",
  "actor": "becca|tool|human",
  "approved_by": "human email or auto",
  "evidence_path": "path to evidence file"
}
```

---

## Emergency Stop

If any of these are detected, immediately HALT:
1. Attempt to access production without approval
2. Attempt to modify security rules without approval
3. Cross-tenant data access attempt
4. Token budget exceeded by 2x
5. Infinite loop detected (same tool called 5+ times)
6. Error rate > 50% in a run

Emergency stop:
1. Kill all processes
2. Set state to HALTED_UNSAFE
3. Send alert (if configured)
4. Do NOT auto-rollback (preserve evidence)
5. Require human investigation
