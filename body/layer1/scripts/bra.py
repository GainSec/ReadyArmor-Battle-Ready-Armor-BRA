#!/usr/bin/env python3
"""bra.py -- Unified Entry Point for B.R.A. Security Testing Framework

Purpose: Single entry point with session lifecycle management.
         Every menu option from the original bra.sh is available as an
         argparse subcommand, delegating to the corresponding Python port.

Usage:
    bra.py                      Show status (default)
    bra.py new                  Force new engagement setup (precheck)
    bra.py resume               Auto-resume from last phase
    bra.py status               Show status and exit
    bra.py quick                Auto-detect and suggest next action
    bra.py pipeline             Run full pipeline (all phases)
    bra.py phase <name>         Run a specific phase (intel|static|dynamic|report)
    bra.py pipeline-status      Show pipeline progress
    bra.py backup [ACTION]      Manage backups (create|list|restore|verify|prune)
    bra.py reset [--dry-run]    Archive and reset to fresh state
    bra.py mark-phase <name>    Mark a phase complete (utility)
    bra.py --help               Show this help

Session States:
    FRESH         - No .bra/ directory
    NEEDS_SCOPE   - .bra exists but SCOPE.md is skeleton
    READY         - Scope defined, pipeline not started
    IN_PROGRESS   - Some phases complete
    COMPLETE      - All phases done

Exit Codes:
    0 - Success
    1 - Error
    2 - User cancelled

Referenced By:
    - CLAUDE.md
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VERSION = "1.0"
PHASES = ("intel", "static", "dynamic", "report")


# ------------------------------------------------------------------ banner

def show_banner() -> None:
    """Display the B.R.A. ASCII art banner with box-drawing frame."""
    print()
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                                                                              ║")
    print("║    ██████╗    ██████╗      █████╗                                            ║")
    print("║    ██╔══██╗   ██╔══██╗    ██╔══██╗                                           ║")
    print("║    ██████╔╝   ██████╔╝    ███████║                                           ║")
    print("║    ██╔══██╗   ██╔══██╗    ██╔══██║                                           ║")
    print("║    ██████╔╝██╗██║  ██║██╗██║  ██║██╗                                         ║")
    print("║    ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝                                         ║")
    print("║                                                                              ║")
    print(f"║              Battle Ready Armor - Security Testing Framework v{VERSION}            ║")
    print("║                                                                              ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print()


# ------------------------------------------------------------------ help text

def show_help() -> None:
    """Display detailed help text matching the original bra.sh."""
    print("""\
bra.py -- Unified Entry Point for B.R.A.

USAGE:
    bra.py                      Show status (default)
    bra.py new                  Force new engagement setup
    bra.py resume               Auto-resume from last phase
    bra.py status               Show status and exit
    bra.py quick                Auto-detect and suggest next action
    bra.py pipeline             Run full pipeline (all phases)
    bra.py phase <name>         Run specific phase (intel|static|dynamic|report)
    bra.py pipeline-status      Show pipeline progress
    bra.py backup [ACTION]      Manage backups (create|list|restore|verify|prune)
    bra.py reset [--dry-run]    Archive and reset to fresh state
    bra.py mark-phase <name>    Mark a phase complete (utility)
    bra.py --help               Show this help

DESCRIPTION:
    Unified entry point for the B.R.A. security testing framework.
    Detects project state and guides you through the appropriate workflow.

SESSION STATES:
    FRESH         No .bra/ directory - new project
    NEEDS_SCOPE   .bra exists but scope not defined
    READY         Scope defined, ready to start pipeline
    IN_PROGRESS   Pipeline started, some phases complete
    COMPLETE      All phases finished

MENU MAPPING:
    [1] new             Start New Engagement (precheck)
    [2] resume          Resume Pipeline
    [3] status          View Status
    [4] pipeline        Run Full Pipeline
    [5] phase <name>    Run Single Phase
    [6] pipeline-status Pipeline Status
    [7] backup [ACTION] Manage Backups
    [8] reset           Reset Project

EXAMPLES:
    # Start new engagement
    python3 layer1/scripts/bra.py new

    # Quick mode - auto-detect best action
    python3 layer1/scripts/bra.py quick

    # Run static analysis phase directly
    python3 layer1/scripts/bra.py phase static

    # Check project status
    python3 layer1/scripts/bra.py status""")


# ------------------------------------------------------------------ helpers

def _body_root() -> Path:
    """Return the body/ directory (two parents above this script)."""
    return Path(__file__).resolve().parents[2]


def _scripts_dir() -> Path:
    """Return the directory containing this script."""
    return Path(__file__).resolve().parent


def _state_file(body_root: Path) -> Path:
    return body_root / ".bra" / "pipeline_state.json"


def _load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}


def _save_state(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------- session state

def _scope_configured(body_root: Path) -> bool:
    scope_file = body_root / "layer3-engagement" / "SCOPE.md"
    if not scope_file.is_file():
        return False
    text = scope_file.read_text(encoding="utf-8", errors="ignore")
    if "_TBD_" in text or "Populate from scope-intake" in text:
        return False
    line_count = text.count("\n")
    return line_count > 10


def _phase_markers(body_root: Path) -> dict[str, bool]:
    artifacts = body_root / ".bra" / "artifacts"
    return {phase: (artifacts / f".{phase}_complete").is_file() for phase in PHASES}


def _session_state(body_root: Path) -> str:
    bra_dir = body_root / ".bra"
    if not bra_dir.exists():
        return "FRESH"

    markers = _phase_markers(body_root)
    if all(markers.values()):
        return "COMPLETE"
    if any(markers.values()):
        return "IN_PROGRESS"
    if _scope_configured(body_root):
        return "READY"
    return "NEEDS_SCOPE"


def _next_phase(body_root: Path) -> str:
    markers = _phase_markers(body_root)
    for phase in PHASES:
        if not markers[phase]:
            return phase
    return "complete"


def _completed_count(body_root: Path) -> int:
    return sum(1 for v in _phase_markers(body_root).values() if v)


def _state_description(state: str) -> str:
    return {
        "FRESH": "New Project",
        "NEEDS_SCOPE": "Scope Required",
        "READY": "Ready to Start",
        "IN_PROGRESS": "In Progress",
        "COMPLETE": "Complete",
    }.get(state, "Unknown")


def _recommendation(state: str) -> str:
    mapping = {
        "FRESH": "python3 layer1/scripts/deploy.py",
        "NEEDS_SCOPE": "python3 layer1/scripts/scope-intake.py",
        "READY": "python3 layer1/scripts/agentic-handler.py",
        "IN_PROGRESS": "python3 layer1/scripts/agentic-handler.py --resume",
        "COMPLETE": "python3 layer1/scripts/report-ready.py",
    }
    return mapping.get(state, "python3 layer1/scripts/status.py")


# ---------------------------------------------------------- delegation

def _run_script(name: str, args: list[str] | None = None) -> int:
    """Run a sibling Python script by name, forwarding extra args.

    The script is resolved relative to the same directory as this file.
    cwd is set to body_root (body/) since bridge.py sets that.
    """
    script = _scripts_dir() / name
    if not script.is_file():
        print(f"[ERROR] {name} not found at {script}", file=sys.stderr)
        return 1
    cmd = [sys.executable, str(script)] + (args or [])
    result = subprocess.run(cmd, cwd=str(_body_root()))
    return result.returncode


def _confirm(prompt: str) -> bool:
    if not sys.stdin.isatty():
        return False
    answer = input(prompt).strip()
    return not answer.lower().startswith("n")


def show_main_menu(state: str) -> int:
    completed = _completed_count(_body_root())
    print()
    print("  B.R.A. MAIN MENU")
    print("  ══════════════════════════════════════════════════════════════")
    print()
    if state == "FRESH":
        print("  Session: NEW PROJECT")
    elif state == "NEEDS_SCOPE":
        print("  Session: SCOPE REQUIRED")
    elif state == "READY":
        print("  Session: READY TO START")
    elif state == "IN_PROGRESS":
        print(f"  Session: IN PROGRESS ({completed}/4 phases complete)")
        print(f"  Next:    {_next_phase(_body_root()).upper()}")
    elif state == "COMPLETE":
        print("  Session: COMPLETE (all phases finished)")
    print()
    print("  Quick Actions:")
    print("  [1] Start New Engagement    [2] Resume Pipeline    [3] View Status")
    print()
    print("  Pipeline Control:")
    print("  [4] Run Full Pipeline       [5] Run Single Phase   [6] Pipeline Status")
    print()
    print("  Management:")
    print("  [7] Manage Backups          [8] Reset Project")
    print()
    print("  [h] Help    [q] Quit")
    print()

    if not sys.stdin.isatty():
        return 0

    choice = input("  Select option: ").strip().lower()
    if choice == "1":
        return cmd_new(argparse.Namespace())
    if choice == "2":
        return cmd_resume(argparse.Namespace())
    if choice == "3":
        return cmd_status(argparse.Namespace())
    if choice == "4":
        return cmd_pipeline(argparse.Namespace())
    if choice == "5":
        phase = input("  Phase (intel/static/dynamic/report): ").strip().lower()
        if phase not in PHASES:
            print(f"[ERROR] Invalid phase: {phase}", file=sys.stderr)
            return 1
        return cmd_phase(argparse.Namespace(name=phase))
    if choice == "6":
        return cmd_pipeline_status(argparse.Namespace())
    if choice == "7":
        return cmd_backup(argparse.Namespace(action="create", target=None))
    if choice == "8":
        return cmd_reset(argparse.Namespace(dry_run=False))
    if choice == "h":
        show_help()
        return 0
    if choice == "q":
        print()
        print("Goodbye!")
        return 0

    print("Invalid selection. Try again.")
    return 1


def _run_legacy_mode(argv: list[str]) -> int | None:
    if not argv:
        return None

    args = list(argv)
    mode = "menu"
    phase = ""
    while args:
        token = args.pop(0)
        if token in {"--help", "-h"}:
            show_help()
            return 0
        if token in {"--quick", "-q"}:
            mode = "quick"
            continue
        if token in {"--new", "-n"}:
            mode = "new"
            continue
        if token in {"--resume", "-r"}:
            mode = "resume"
            continue
        if token in {"--status", "-s"}:
            mode = "status"
            continue
        if token in {"--phase", "-p"}:
            if not args:
                print("[ERROR] --phase requires an argument", file=sys.stderr)
                return 1
            mode = "phase"
            phase = args.pop(0)
            continue
        return None

    if mode == "menu":
        return None
    if mode == "quick":
        return cmd_quick(argparse.Namespace())
    if mode == "new":
        return cmd_new(argparse.Namespace())
    if mode == "resume":
        return cmd_resume(argparse.Namespace())
    if mode == "status":
        return cmd_status(argparse.Namespace())
    if mode == "phase":
        if phase not in PHASES:
            print(f"[ERROR] Invalid phase: {phase}", file=sys.stderr)
            print("Valid phases: intel, static, dynamic, report")
            return 1
        return cmd_phase(argparse.Namespace(name=phase))
    return None


def _legacy_mode_name(argv: list[str]) -> str | None:
    if not argv:
        return None
    mode = "menu"
    args = list(argv)
    while args:
        token = args.pop(0)
        if token in {"--help", "-h"}:
            return "help"
        if token in {"--quick", "-q"}:
            mode = "quick"
            continue
        if token in {"--new", "-n"}:
            mode = "new"
            continue
        if token in {"--resume", "-r"}:
            mode = "resume"
            continue
        if token in {"--status", "-s"}:
            mode = "status"
            continue
        if token in {"--phase", "-p"}:
            return "phase"
        return None
    return mode


# ====================================================================
#  Subcommand handlers — one per menu item / CLI mode from bra.sh
# ====================================================================

def cmd_new(_args: argparse.Namespace) -> int:
    """Menu [1]: Start New Engagement — delegates to precheck.py."""
    print()
    print("═══ NEW ENGAGEMENT SETUP ═══")
    print()
    print("[1/2] Running environment precheck...")
    print()
    rc = _run_script("precheck.py")
    if rc != 0:
        return rc
    print()
    print("[2/2] Project structure initialized")
    print()
    print("Next steps:")
    print("  1. Define scope in layer3-engagement/SCOPE.md")
    print("  2. Configure ROE in layer3-engagement/ROE.md")
    print("  3. Run 'python3 layer1/scripts/bra.py' to start pipeline")
    print()
    return 0


def cmd_resume(_args: argparse.Namespace) -> int:
    """Menu [2]: Resume Pipeline — delegates to agentic-handler.py."""
    body = _body_root()
    nxt = _next_phase(body)

    if nxt == "complete":
        print("Pipeline already complete!")
        print("Use 'bra.py status' to view status or 'bra.py reset' to start over.")
        return 0

    print()
    print("═══ RESUMING PIPELINE ═══")
    print()
    print(f"Next phase: {nxt.upper()}")
    print()

    return _run_script("agentic-handler.py", [f"--{nxt}"])


def cmd_status(_args: argparse.Namespace) -> int:
    """Menu [3]: View Status — delegates to status.py."""
    return _run_script("status.py")


def cmd_pipeline(_args: argparse.Namespace) -> int:
    """Menu [4]: Run Full Pipeline — delegates to agentic-handler.py --all."""
    print()
    print("═══ RUNNING FULL PIPELINE ═══")
    print()
    print("This will run all phases: INTEL → STATIC → DYNAMIC → REPORT")
    print()
    return _run_script("agentic-handler.py", ["--all"])


def cmd_phase(args: argparse.Namespace) -> int:
    """Menu [5]: Run Single Phase — delegates to agentic-handler.py --<phase>."""
    phase = args.name
    print()
    print(f"═══ RUNNING PHASE: {phase.upper()} ═══")
    print()
    return _run_script("agentic-handler.py", [f"--{phase}"])


def cmd_pipeline_status(_args: argparse.Namespace) -> int:
    """Menu [6]: Pipeline Status — delegates to agentic-handler.py --status."""
    return _run_script("agentic-handler.py", ["--status"])


def cmd_backup(args: argparse.Namespace) -> int:
    """Menu [7]: Manage Backups — delegates to backup.py.

    Sub-actions: create (default), list, restore, verify, prune.
    """
    action = getattr(args, "action", "create") or "create"

    if action == "create":
        return _run_script("backup.py")
    elif action == "list":
        return _run_script("backup.py", ["--list"])
    elif action == "restore":
        target = getattr(args, "target", None)
        if not target:
            print("[ERROR] --target required for restore", file=sys.stderr)
            return 1
        return _run_script("backup.py", ["--restore", target])
    elif action == "verify":
        target = getattr(args, "target", None)
        if not target:
            print("[ERROR] --target required for verify", file=sys.stderr)
            return 1
        return _run_script("backup.py", ["--verify", target])
    elif action == "prune":
        return _run_script("backup.py", ["--prune"])
    else:
        print(f"[ERROR] Unknown backup action: {action}", file=sys.stderr)
        return 1


def cmd_reset(args: argparse.Namespace) -> int:
    """Menu [8]: Reset Project — delegates to reset.py."""
    print()
    print("═══ PROJECT RESET ═══")
    print()
    print("This will:")
    print("  - Archive all engagement data")
    print("  - Remove .bra/ (state, artifacts, logs)")
    print("  - Clear layer3-engagement/NOTES/ content")
    print("  - Reset layer3-engagement/*.md to skeletons")
    print()
    print("⚠ This is a destructive operation!")
    print()
    extra: list[str] = []
    if getattr(args, "dry_run", False):
        extra.append("--dry-run")
    return _run_script("reset.py", extra)


def cmd_quick(_args: argparse.Namespace) -> int:
    """CLI --quick: Auto-detect state and suggest next action."""
    body = _body_root()
    session = _session_state(body)
    nxt = _next_phase(body)
    completed = _completed_count(body)

    print(f"Session state: {session}")
    print()

    if session == "FRESH":
        print("Detected: New project without initialization")
        print()
        print("Suggested action: Initialize project")
        print()
        if _confirm("Run precheck to initialize? [Y/n]: "):
            return cmd_new(argparse.Namespace())
        print("To initialize, run:")
        print("  python3 layer1/scripts/bra.py new")

    elif session == "NEEDS_SCOPE":
        print("Detected: Project initialized but scope not defined")
        print()
        print("Required action: Define engagement scope")
        print()
        print("To define scope interactively, run:")
        print("  python3 layer1/scripts/scope-intake.py")
        print()
        print("Or manually edit: layer3-engagement/SCOPE.md")
        print("Template:         layer2-templates/scope-intake.md")

    elif session == "READY":
        print("Detected: Project ready to start")
        print()
        print("Suggested action: Start pipeline with INTEL")
        print()
        if _confirm("Start intelligence phase? [Y/n]: "):
            return cmd_phase(argparse.Namespace(name="intel"))
        print("To start, run:")
        print("  python3 layer1/scripts/bra.py phase intel")

    elif session == "IN_PROGRESS":
        print(f"Detected: Pipeline in progress ({completed}/4 phases complete)")
        print()
        print(f"Suggested action: Continue with {nxt.upper()}")
        print()
        if _confirm(f"Run {nxt} phase? [Y/n]: "):
            return cmd_phase(argparse.Namespace(name=nxt))
        print("To continue, run:")
        print(f"  python3 layer1/scripts/bra.py phase {nxt}")

    elif session == "COMPLETE":
        print("Detected: All phases complete")
        print()
        print("Options:")
        print("  - View final report: layer3-engagement/REPORT.md")
        print("  - Create backup:     python3 layer1/scripts/backup.py")
        print("  - Reset for new engagement: python3 layer1/scripts/bra.py reset")
        print()
        _run_script("status.py", ["--compact"])

    return 0


def cmd_mark_phase(args: argparse.Namespace) -> int:
    """Utility: mark a phase complete (writes marker file + updates state)."""
    body = _body_root()
    phase = args.name
    artifacts = body / ".bra" / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    marker = artifacts / f".{phase}_complete"
    marker.write_text(_utc_now() + "\n", encoding="utf-8")

    payload = _load_state(_state_file(body))
    payload.update({"status": "in_progress", "last_phase": phase, "timestamp": _utc_now()})
    _save_state(_state_file(body), payload)

    print(f"Marked phase complete: {phase}")
    print(f"Next phase: {_next_phase(body)}")
    return 0


# ====================================================================
#  Argparse
# ====================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bra.py",
        description="Unified BRA CLI entry point (v{}).".format(VERSION),
        epilog=(
            "Menu mapping from bra.sh:\n"
            "  [1] new             Start New Engagement (precheck)\n"
            "  [2] resume          Resume Pipeline\n"
            "  [3] status          View Status\n"
            "  [4] pipeline        Run Full Pipeline\n"
            "  [5] phase <name>    Run Single Phase\n"
            "  [6] pipeline-status Pipeline Status\n"
            "  [7] backup [ACTION] Manage Backups\n"
            "  [8] reset           Reset Project\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subs = parser.add_subparsers(dest="command", help="Available commands")

    # [1] new
    p_new = subs.add_parser("new", help="Start a new engagement (run precheck)")
    p_new.set_defaults(func=cmd_new)

    # [2] resume
    p_resume = subs.add_parser("resume", help="Resume pipeline from last phase")
    p_resume.set_defaults(func=cmd_resume)

    # [3] status
    p_status = subs.add_parser("status", help="Show project status")
    p_status.set_defaults(func=cmd_status)

    # [4] pipeline
    p_pipeline = subs.add_parser("pipeline", help="Run full pipeline (all phases)")
    p_pipeline.set_defaults(func=cmd_pipeline)

    # [5] phase
    p_phase = subs.add_parser("phase", help="Run a single phase")
    p_phase.add_argument("name", choices=PHASES, help="Phase to run")
    p_phase.set_defaults(func=cmd_phase)

    # [6] pipeline-status
    p_pstatus = subs.add_parser("pipeline-status", help="Show pipeline progress")
    p_pstatus.set_defaults(func=cmd_pipeline_status)

    # [7] backup
    p_backup = subs.add_parser(
        "backup",
        help="Manage backups (create, list, restore, verify, prune)",
    )
    p_backup.add_argument(
        "action",
        nargs="?",
        default="create",
        choices=["create", "list", "restore", "verify", "prune"],
        help="Backup action (default: create)",
    )
    p_backup.add_argument(
        "--target",
        default=None,
        help="Backup name/path for restore or verify",
    )
    p_backup.set_defaults(func=cmd_backup)

    # [8] reset
    p_reset = subs.add_parser("reset", help="Archive and reset project to fresh state")
    p_reset.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be removed without making changes",
    )
    p_reset.set_defaults(func=cmd_reset)

    # quick (--quick mode from bra.sh)
    p_quick = subs.add_parser("quick", help="Auto-detect state and suggest next action")
    p_quick.set_defaults(func=cmd_quick)

    # mark-phase (utility, was --phase in the old Python version)
    p_mark = subs.add_parser("mark-phase", help="Mark a specific phase complete")
    p_mark.add_argument("name", choices=PHASES, help="Phase to mark complete")
    p_mark.set_defaults(func=cmd_mark_phase)

    return parser


# ====================================================================
#  Entry point
# ====================================================================

def main(argv: list[str] | None = None) -> int:
    raw_args = sys.argv[1:] if argv is None else argv

    legacy_mode = _legacy_mode_name(raw_args)
    if legacy_mode is not None and legacy_mode not in {"status", "help"}:
        show_banner()
    legacy_result = _run_legacy_mode(raw_args)
    if legacy_result is not None:
        return legacy_result

    parser = _build_parser()
    args = parser.parse_args(raw_args)

    # No subcommand given -> main menu
    if not hasattr(args, "func"):
        show_banner()
        return show_main_menu(_session_state(_body_root()))

    # Show banner for interactive modes (not status or pipeline-status)
    command = getattr(args, "command", None)
    if command not in ("status", "pipeline-status"):
        show_banner()

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
