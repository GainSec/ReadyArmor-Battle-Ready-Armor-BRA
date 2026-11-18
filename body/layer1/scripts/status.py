#!/usr/bin/env python3
"""status.py - Python port of layer1/scripts/status.sh.

Read-only project health dashboard.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from types import SimpleNamespace


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent  # body/
BRA_STATE = PROJECT_ROOT / ".bra"
LOG_DIR = BRA_STATE / "logs"
ARTIFACTS_DIR = BRA_STATE / "artifacts"
NOTES_DIR = PROJECT_ROOT / "layer3-engagement" / "NOTES"
STATE_FILE = BRA_STATE / "pipeline_state.json"


@dataclass
class HealthState:
    score: int = 100
    warnings: int = 0
    criticals: int = 0

    def deduct(self, points: int, severity: str = "warning") -> None:
        self.score = max(0, self.score - points)
        if severity == "critical":
            self.criticals += 1
        else:
            self.warnings += 1


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _count_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for p in path.rglob("*") if p.is_file())


def _count_regex(path: Path, pattern: str) -> int:
    if not path.exists():
        return 0
    rx = re.compile(pattern, re.MULTILINE)
    try:
        return len(rx.findall(path.read_text(errors="ignore")))
    except Exception:
        return 0


def get_pipeline_status() -> dict[str, Any]:
    artifacts = {
        "intel": (ARTIFACTS_DIR / ".intel_complete").exists(),
        "static": (ARTIFACTS_DIR / ".static_complete").exists(),
        "dynamic": (ARTIFACTS_DIR / ".dynamic_complete").exists(),
        "report": (ARTIFACTS_DIR / ".report_complete").exists(),
    }
    state = _read_json(STATE_FILE)
    return {
        "status": state.get("status", "initialized"),
        "last_phase": state.get("last_phase", ""),
        **artifacts,
    }


def get_active_tokens() -> str:
    out: list[str] = []
    approvals = BRA_STATE / "approvals"
    if approvals.exists():
        for p in sorted(approvals.iterdir()):
            if p.is_file():
                out.append(p.name)
    return ",".join(out) if out else "none"


def get_artifact_counts() -> dict[str, int]:
    counts = {
        "intel": _count_files(ARTIFACTS_DIR / "intel_work"),
        "static": _count_files(ARTIFACTS_DIR / "static_work"),
        "dynamic": _count_files(ARTIFACTS_DIR / "dynamic_work"),
        "report": _count_files(ARTIFACTS_DIR / "report_work"),
    }
    counts["total"] = sum(counts.values())
    return counts


def get_log_summary() -> dict[str, int]:
    out = {"errors": 0, "warnings": 0, "blocked": 0}
    if not LOG_DIR.exists():
        return out
    for log in LOG_DIR.glob("*.log"):
        try:
            text = log.read_text(errors="ignore")
        except Exception:
            continue
        out["errors"] += len(re.findall(r"\[ERROR\]", text, flags=re.IGNORECASE))
        out["warnings"] += len(re.findall(r"\[WARN\]", text, flags=re.IGNORECASE))
        out["blocked"] += len(re.findall(r"\[BLOCKED\]", text, flags=re.IGNORECASE))
    return out


def get_findings_counts() -> dict[str, int]:
    return {
        "count": _count_regex(NOTES_DIR / "FINDINGS.md", r"^##+\s"),
        "leads": _count_regex(NOTES_DIR / "LEADS.md", r"^(?:-|\*)\s"),
    }


def kill_switch_active() -> bool:
    claude_md = PROJECT_ROOT / "CLAUDE.md"
    if claude_md.exists():
        try:
            content = claude_md.read_text(errors="ignore")
            section_match = re.search(r"(?ms)^##\s*Kill\s*Switch\b(.*?)(?=^##\s|\Z)", content)
            if not section_match:
                return False
            kill_section = section_match.group(1)
            stop_match = re.search(r"(?m)^STOP$", kill_section)
            if not stop_match:
                return False
            return "```" not in kill_section[: stop_match.start()]
        except Exception:
            return False

    return False


def detect_session_state() -> str:
    if not BRA_STATE.exists():
        return "FRESH"

    state = _read_json(STATE_FILE)
    if state.get("active_session_id") and state.get("status") == "in_progress":
        return "IN_PROGRESS"

    intel_done = (ARTIFACTS_DIR / ".intel_complete").exists()
    static_done = (ARTIFACTS_DIR / ".static_complete").exists()
    dynamic_done = (ARTIFACTS_DIR / ".dynamic_complete").exists()
    report_done = (ARTIFACTS_DIR / ".report_complete").exists()

    if intel_done and static_done and dynamic_done and report_done:
        if (ARTIFACTS_DIR / ".growth_complete").exists():
            return "COMPLETE"
        return "ENDED"

    if intel_done or static_done or dynamic_done:
        return "IN_PROGRESS"

    scope_file = PROJECT_ROOT / "layer3-engagement" / "SCOPE.md"
    if scope_file.exists():
        content = scope_file.read_text(errors="ignore")
        if "_TBD_" not in content and "Populate from scope-intake" not in content and len(content.splitlines()) > 10:
            return "READY"

    return "NEEDS_SCOPE"


def compute_health() -> HealthState:
    health = HealthState()
    logs = get_log_summary()

    if kill_switch_active():
        health.deduct(50, severity="critical")

    if logs["errors"] > 0:
        health.deduct(logs["errors"] * 5, severity="critical")
    if logs["blocked"] > 5:
        health.deduct(10, severity="warning")

    pipeline = get_pipeline_status()
    if pipeline["status"] == "blocked":
        health.deduct(15, severity="warning")

    artifacts = get_artifact_counts()
    if artifacts["total"] == 0:
        health.deduct(10, severity="warning")

    state = detect_session_state()
    if state in {"FRESH", "NEEDS_SCOPE"}:
        health.deduct(15, severity="warning")

    return health


def get_backup_info() -> dict[str, Any]:
    backup_dir = PROJECT_ROOT / "BACKUPS"
    if not backup_dir.exists():
        return {"count": 0, "latest": "none"}
    archives = sorted(backup_dir.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    return {
        "count": len(archives),
        "latest": archives[0].name if archives else "none",
    }


def build_status_payload() -> dict[str, Any]:
    pipeline = get_pipeline_status()
    health = compute_health().__dict__
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "project": PROJECT_ROOT.name,
        "pipeline": pipeline,
        "tokens": get_active_tokens(),
        "artifacts": get_artifact_counts(),
        "logs": get_log_summary(),
        "findings": get_findings_counts(),
        "backups": get_backup_info(),
        "health": {**health, "kill_switch": kill_switch_active()},
    }


def compact_line(payload: dict[str, Any]) -> str:
    score = payload["health"]["score"]
    if score >= 80:
        icon = "[✓]"
    elif score >= 50:
        icon = "[!]"
    else:
        icon = "[✗]"

    phases = ""
    phases += "R" if payload["pipeline"].get("intel") else "."
    phases += "S" if payload["pipeline"].get("static") else "."
    phases += "D" if payload["pipeline"].get("dynamic") else "."
    phases += "R" if payload["pipeline"].get("report") else "."

    return (
        f"{icon} Pipeline:[{phases}] "
        f"Status:{payload['pipeline']['status']} "
        f"Findings:{payload['findings']['count']} "
        f"Errors:{payload['logs']['errors']} "
        f"Health:{score}%"
    )


def _render_phase(complete: bool) -> str:
    return "●" if complete else "○"


def _render_health_bar(score: int, width: int = 20) -> str:
    filled = score * width // 100
    empty = width - filled
    return "█" * filled + "░" * empty


def full_text(payload: dict[str, Any]) -> str:
    from datetime import datetime, timezone

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    project_name = PROJECT_ROOT.name

    status = payload["pipeline"]["status"]
    last_phase = payload["pipeline"]["last_phase"]
    tokens_str = payload["tokens"]
    art = payload["artifacts"]
    logs = payload["logs"]
    findings = payload["findings"]
    backups = payload["backups"]
    health = payload["health"]
    score = health["score"]

    lines: list[str] = []
    lines.append("")
    lines.append("╔══════════════════════════════════════════════════════════════════════╗")
    lines.append("║                      PROJECT STATUS DASHBOARD                        ║")
    lines.append("╚══════════════════════════════════════════════════════════════════════╝")
    lines.append("")
    lines.append(f"{timestamp}  Project: {project_name}")
    lines.append("")

    # Kill switch warning
    if health["kill_switch"]:
        lines.append("  ⚠  STOP KILL SWITCH IS ACTIVE - ALL OPERATIONS HALTED  ⚠")
        lines.append("")

    # Pipeline
    lines.append("  PIPELINE")
    lines.append("  ────────────────────────────────────────────────────────")
    intel_i = _render_phase(payload["pipeline"].get("intel", False))
    static_i = _render_phase(payload["pipeline"].get("static", False))
    dynamic_i = _render_phase(payload["pipeline"].get("dynamic", False))
    report_i = _render_phase(payload["pipeline"].get("report", False))
    lines.append(f"  {intel_i} INTEL  {static_i} STATIC  {dynamic_i} DYNAMIC  {report_i} REPORT")
    lines.append("")
    last_str = f"  Last: {last_phase}" if last_phase else ""
    lines.append(f"  Status: {status}{last_str}")
    lines.append("")

    # Two-column: TOKENS + ARTIFACTS
    lines.append("  TOKENS                                ARTIFACTS")
    lines.append("  ──────────────────────────────────    ──────────────────────────────")
    # Pad tokens to align with artifacts column
    tok_display = f"  {tokens_str}"
    pad = max(1, 40 - len(tok_display))
    lines.append(f"{tok_display}{' ' * pad}Intel: {art['intel']}  Static: {art['static']}")
    lines.append(f"{' ' * 40}Dynamic: {art['dynamic']}  Report: {art['report']}")
    lines.append(f"{' ' * 40}Total: {art['total']}")
    lines.append("")

    # Two-column: LOGS + FINDINGS
    lines.append("  LOGS                                 FINDINGS")
    lines.append("  ──────────────────────────────────    ──────────────────────────────")
    errors = logs["errors"]
    warnings_count = logs["warnings"]
    blocked = logs["blocked"]
    if errors > 0:
        log_status = f"{errors} errors"
    elif warnings_count > 0:
        log_status = f"{warnings_count} warnings"
    else:
        log_status = "Clean"
    log_display = f"  {log_status}, {blocked} blocked"
    pad2 = max(1, 40 - len(log_display))
    lines.append(f"{log_display}{' ' * pad2}Findings: {findings['count']}  Leads: {findings['leads']}")
    lines.append("")

    # Backups
    lines.append("  BACKUPS")
    lines.append("  ────────────────────────────────────────────────────────")
    if backups["count"] > 0:
        lines.append(f"  {backups['count']} archive(s)  Latest: {backups['latest']}")
    else:
        lines.append("  No backups")
    lines.append("")

    # Health
    lines.append("  HEALTH")
    lines.append("  ────────────────────────────────────────────────────────")
    bar = _render_health_bar(score)
    lines.append(f"  {bar}")
    if score >= 80:
        label = "Healthy"
    elif score >= 50:
        label = "Warning"
    else:
        label = "Critical"
    lines.append(f"  {score}% - {label}")
    if health["warnings"] > 0:
        lines.append(f"  {health['warnings']} warning(s)")
    if health["criticals"] > 0:
        lines.append(f"  {health['criticals']} critical issue(s)")
    lines.append("")

    # Quick actions
    lines.append("  Quick actions: audit.py | packup.py | precheck.py")
    lines.append("")

    return "\n".join(lines)


def show_help() -> None:
    print(
        "\n".join(
            [
                "status.py — Project Health Dashboard",
                "",
                "USAGE:",
                "    status.py                       Full dashboard",
                "    status.py --compact             Compact one-line summary",
                "    status.py --json                JSON output for automation",
                "    status.py --watch               Continuous monitoring (refresh every 5s)",
                "    status.py --help                Show this help",
                "",
                "DESCRIPTION:",
                "    Displays a comprehensive dashboard of project health including",
                "    pipeline state, active tokens, artifacts, logs, and findings.",
                "",
                "DASHBOARD SECTIONS:",
                "    Pipeline     - Phase completion status",
                "    Tokens       - Active approval tokens",
                "    Artifacts    - File counts per phase",
                "    Logs         - Error/warning counts",
                "    Findings     - Documented findings and leads",
                "    Health       - Overall health score",
                "",
                "EXIT CODES:",
                "    0 - Healthy (score >= 80)",
                "    1 - Warning (score 50-79)",
                "    2 - Critical (score < 50)",
                "",
                "EXAMPLES:",
                "    # Full dashboard",
                "    ./layer1/scripts/status.py",
                "",
                "    # Quick status check",
                "    ./layer1/scripts/status.py --compact",
                "",
                "    # Continuous monitoring",
                "    ./layer1/scripts/status.py --watch",
                "",
                "    # For scripts/automation",
                "    ./layer1/scripts/status.py --json",
            ]
        )
    )


def parse_args(argv: list[str]) -> SimpleNamespace:
    args = SimpleNamespace(compact=False, json_output=False, watch=False, show_help=False, invalid="")
    for raw in argv:
        if raw in {"--help", "-h"}:
            args.show_help = True
        elif raw in {"--compact", "-c"}:
            args.compact = True
        elif raw in {"--json", "-j"}:
            args.json_output = True
        elif raw in {"--watch", "-w"}:
            args.watch = True
        else:
            args.invalid = raw
            return args
    return args


def status_exit_code(score: int) -> int:
    if score >= 80:
        return 0
    if score >= 50:
        return 1
    return 2


def run_once(args: argparse.Namespace) -> int:
    payload = build_status_payload()
    if args.json_output:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif args.compact:
        print(compact_line(payload))
    else:
        print(full_text(payload))
    return status_exit_code(payload["health"]["score"])


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    if args.invalid:
        print(f"Unknown option: {args.invalid}")
        show_help()
        return 1

    if args.show_help:
        show_help()
        return 0

    if args.watch:
        rc = 0
        try:
            while True:
                rc = run_once(args)
                time.sleep(5)
        except KeyboardInterrupt:
            pass
        return rc

    return run_once(args)


if __name__ == "__main__":
    raise SystemExit(main())
