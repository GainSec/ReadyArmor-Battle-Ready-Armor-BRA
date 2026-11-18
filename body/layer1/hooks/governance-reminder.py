#!/usr/bin/env python3
"""governance-reminder.py - periodic governance reminder hook.

Python port of governance-reminder.sh.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


HOOKS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = HOOKS_DIR.parent.parent
BRA_STATE = PROJECT_ROOT / ".bra"
LOG_DIR = BRA_STATE / "logs"
LOG_FILE = LOG_DIR / "governance-reminder.log"
REMINDER_FILE = BRA_STATE / "last_reminder"


def _utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(msg: str) -> None:
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"[{_utc_ts()}] [REMINDER] {msg}\n")
    except Exception:
        pass


def _should_remind(interval_seconds: int) -> bool:
    if not REMINDER_FILE.exists():
        return True
    try:
        last = int(REMINDER_FILE.read_text(encoding="utf-8").strip() or "0")
    except Exception:
        last = 0
    now = int(time.time())
    return now - last >= interval_seconds


def _write_reminder_ts() -> None:
    BRA_STATE.mkdir(parents=True, exist_ok=True)
    REMINDER_FILE.write_text(str(int(time.time())), encoding="utf-8")


def _scope_summary() -> list[str]:
    scope = PROJECT_ROOT / "layer3-engagement" / "SCOPE.md"
    if not scope.exists():
        return ["  (No scope defined - layer3-engagement/SCOPE.md not found)"]

    try:
        lines = scope.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return ["  (Unable to read SCOPE.md)"]

    engagement = "Not set"
    active_testing = "Unknown"

    for line in lines:
        if line.startswith("#") and engagement == "Not set":
            engagement = line.lstrip("#").strip()
        if "Active Testing:" in line:
            active_testing = line.split("Active Testing:", 1)[1].strip()
            break

    return [
        f"  Engagement: {engagement}",
        f"  Active Testing: {active_testing}",
    ]


def _token_summary() -> str:
    approvals = BRA_STATE / "approvals"
    if not approvals.exists():
        return "  Active: (none)"
    tokens = sorted(p.name for p in approvals.iterdir() if p.is_file())
    if not tokens:
        return "  Active: (none)"
    return f"  Active: {', '.join(tokens)}"


def _kill_switch_status() -> str:
    if os.environ.get("BRA_STOP") == "1":
        return "  Status: STOP (environment variable)"

    if (BRA_STATE / "STOP").exists():
        return "  Status: STOP (stop file)"

    claude = PROJECT_ROOT / "CLAUDE.md"
    if claude.exists():
        try:
            text = claude.read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                if line.strip() == "STOP":
                    return "  Status: STOP (CLAUDE.md)"
        except Exception:
            pass

    return "  Status: CLEAR"


def main() -> int:
    if os.environ.get("GOVERNANCE_REMINDER_DISABLE") == "1":
        return 0

    try:
        interval = int((os.environ.get("GOVERNANCE_REMINDER_INTERVAL") or "900").strip())
    except ValueError:
        interval = 900

    if not _should_remind(interval):
        return 0

    _log(f"Showing governance reminder (interval: {interval}s)")
    _write_reminder_ts()

    out = []
    out.append("\n================================================================================")
    out.append("                        B.R.A. GOVERNANCE REMINDER")
    out.append("================================================================================\n")
    out.append("Kill Switch:")
    out.append(_kill_switch_status())
    out.append("\nCurrent Scope:")
    out.extend(_scope_summary())
    out.append("\nApproval Tokens:")
    out.append(_token_summary())
    out.append("")
    out.append("--------------------------------------------------------------------------------")
    out.append("REQUIRED ACTIONS:")
    out.append("  1. Re-read CLAUDE.md if uncertain about scope")
    out.append("  2. Check .bra/approvals/ for current permissions")
    out.append("  3. Use /agentic command for engagement operations")
    out.append("  4. Stay within targets defined in layer3-engagement/SCOPE.md")
    out.append("--------------------------------------------------------------------------------")

    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
