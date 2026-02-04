# BECCA KERNEL

**Purpose:** Automation orchestrator for Colony OS ecosystem
**Version:** 0.1.0 (MVP in development)

---

## What This Is

BECCA Kernel is the **single orchestration layer** that controls:
- Sonny (d:\projects\sonny) - Test SaaS app
- Colony-OS (d:\projects\colony-os) - Governance system

Instead of 4+ chat windows, BECCA runs as **one interface** that calls tools in the background.

---

## Structure

```
becca-kernel/
├── governance/
│   ├── specs/           ← ARTIFACT_SPEC, RUN_STATES, GUARDRAILS
│   ├── runs/            ← Each run gets a folder
│   ├── runtime/
│   │   └── approvals/   ← PENDING/APPROVED/REJECTED
│   └── command-center/
│       └── ledger/      ← RUN_LEDGER.jsonl
├── orchestrator/
│   ├── becca_mvp.py     ← MVP entry point
│   ├── becca_kernel.py  ← Full kernel (Phase 1)
│   ├── schemas/         ← JSON validation
│   └── tools/           ← tool_inspector, tool_browser, tool_reporter
└── scripts/
    └── rollback_run.py  ← Emergency rollback
```

---

## MVP Tools (Phase 0)

| Tool | Purpose | Actions |
|------|---------|---------|
| tool_inspector | Read/grep codebase | read, grep |
| tool_browser | DevTools capture | screenshot, console, network |
| tool_reporter | Generate report | write report.md |

**Flow:** Inspector → Browser → Reporter (observation only)

---

## Run a Test

```bash
cd d:\projects\becca-kernel
python orchestrator/becca_mvp.py --project sonny --mission "Find console errors"
```

---

## Key Files

- [BECCA_AUTOMATION_DEEP_DIVE.md](BECCA_AUTOMATION_DEEP_DIVE.md) - Full architecture
- [governance/specs/ARTIFACT_SPEC.md](governance/specs/ARTIFACT_SPEC.md) - Tool I/O contract
- [governance/specs/RUN_STATES.md](governance/specs/RUN_STATES.md) - State machine
- [governance/specs/GUARDRAILS.md](governance/specs/GUARDRAILS.md) - Safety rules
