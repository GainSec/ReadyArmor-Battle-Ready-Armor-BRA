#!/usr/bin/env python3
"""Native engagement launcher/preflight helper for BRA.

Simplified flow for Claude-first orchestration:
  1. Banner (ASCII art)
  2. Preflight checks (kill switch, governance, tools, three-layer architecture)
  3. Precheck (full environment validation)
  4. Dry-run check (informational)
  5. Scope intake (if not already configured)
  6. Launch instructions for Claude + /agentic
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


def _body_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _kill_switch_active(body_root: Path) -> bool:
    if os.environ.get("BRA_STOP") == "1":
        return True
    if (body_root / ".bra" / "STOP").exists():
        return True

    claude_md = body_root / "CLAUDE.md"
    if not claude_md.is_file():
        return False
    text = claude_md.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r"##\s*Kill\s*Switch\s*\n+```\s*\n\s*(STOP|CLEAR)\s*\n```", text, flags=re.IGNORECASE)
    return bool(match and match.group(1).upper() == "STOP")


def _scope_file(body_root: Path) -> Path:
    return body_root / "layer3-engagement" / "SCOPE.md"


def _scope_configured(body_root: Path) -> bool:
    scope = _scope_file(body_root)
    if not scope.is_file():
        return False
    text = scope.read_text(encoding="utf-8", errors="ignore")
    return "Authorization" in text and "_TBD_" not in text


def _artifact_count(body_root: Path) -> int:
    artifacts_dir = body_root / ".bra" / "artifacts"
    if not artifacts_dir.is_dir():
        return 0
    return sum(1 for path in artifacts_dir.rglob("*") if path.is_file())


def _ensure_structure(body_root: Path) -> None:
    required = [
        body_root / ".bra" / "artifacts",
        body_root / ".bra" / "logs",
        body_root / ".bra" / "approvals",
        body_root / "layer3-engagement" / "NOTES",
        body_root / "layer3-engagement" / "pitches",
        body_root / "layer3-engagement" / "ingest",
    ]
    for directory in required:
        directory.mkdir(parents=True, exist_ok=True)


SCOPE_TEMPLATE = """# Scope

- Authorization: Yes
- Target: _TBD_
- Objective: _TBD_
- Constraints: _TBD_
"""


def _prepare_scope(body_root: Path) -> None:
    scope = _scope_file(body_root)
    if scope.exists():
        return
    scope.parent.mkdir(parents=True, exist_ok=True)
    scope.write_text(SCOPE_TEMPLATE, encoding="utf-8")


def _reset_overrides(body_root: Path) -> None:
    overrides = body_root / ".bra" / "overrides.json"
    if overrides.is_file():
        print("Resetting overrides from previous engagement")
    overrides.parent.mkdir(parents=True, exist_ok=True)
    overrides.write_text(json.dumps({"rules": []}, indent=2) + "\n", encoding="utf-8")


# ============== BANNER ==============

def _print_banner() -> None:
    print()
    print(r"    ____        __  __  __          __        __  _")
    print(r"   / __ )____ _/ /_/ /_/ /__  _____/ /_____ _/ /_(_)___  ____  _____")
    print(r"  / __  / __ `/ __/ __/ / _ \/ ___/ __/ __ `/ __/ / __ \/ __ \/ ___/")
    print(r" / /_/ / /_/ / /_/ /_/ /  __(__  ) /_/ /_/ / /_/ / /_/ / / / (__  )")
    print(r"/_____/\__,_/\__/\__/_/\___/____/\__/\__,_/\__/_/\____/_/ /_/____/")
    print()
    print(r" ____    ____    _                ____        _   _   _        ____                _")
    print(r"| __ )  |  _ \  / \      _____   | __ )  __ _| |_| |_| | ___  |  _ \ ___  __ _  __| |_   _")
    print(r"|  _ \  | |_) |/ _ \    |_____| |  _ \ / _` | __| __| |/ _ \ | |_) / _ \/ _` |/ _` | | | |")
    print(r"| |_) | |  _ </ ___ \    _____  | |_) | (_| | |_| |_| |  __/ |  _ <  __/ (_| | (_| | |_| |")
    print(r"|____/  |_| \_\_/  \_\  |_____| |____/ \__,_|\__|\__|_|\___| |_| \_\___|\__,_|\__,_|\__, |")
    print(r"     / \   _ __ _ __ ___   ___  _ __                                                |___/")
    print(r"    / _ \ | '__| '_ ` _ \ / _ \| '__|")
    print(r"   / ___ \| |  | | | | | | (_) | |")
    print(r"  /_/   \_\_|  |_| |_| |_|\___/|_|")
    print()
    print("                              Created by GainSec")
    print()


# ============== PREFLIGHT ==============

def _preflight_check(body_root: Path) -> bool:
    print()
    print("▶ PREFLIGHT CHECK")

    errors = 0

    print("  Kill switch... ", end="")
    if _kill_switch_active(body_root):
        print("ACTIVE - HALTED")
        return False
    print("CLEAR")

    print("  Governance files... ", end="")
    if (body_root / "CLAUDE.md").is_file():
        print("OK")
    else:
        print("MISSING")
        errors += 1

    print("  Directory structure... ", end="")
    if (body_root / ".bra").is_dir() and (body_root / "layer3-engagement" / "NOTES").is_dir():
        print("OK")
    else:
        print("INCOMPLETE")
        errors += 1

    print("  Three-layer architecture... ", end="")
    has_layers = (
        (body_root / "layer1" / "rules").is_dir()
        and (body_root / "layer2-templates").is_dir()
        and (body_root / "layer3-engagement").is_dir()
    )
    if has_layers:
        print("OK")
    else:
        print("INCOMPLETE")
        errors += 1

    if errors > 0:
        print()
        print("Preflight failed. Run deploy.py first.", file=sys.stderr)
        return False

    print()
    print("  All systems go.")
    return True


# ============== LAUNCH INSTRUCTIONS ==============

def _show_launch_instructions() -> None:
    print()
    print("═══════════════════════════════════════════════════════════════")
    print("  PREPARATION COMPLETE")
    print("═══════════════════════════════════════════════════════════════")
    print()
    print("  To start the engagement:")
    print()
    print("    1. Start Claude Code in this directory:")
    print()
    print("       claude")
    print()
    print("    2. Run the agentic command:")
    print()
    print("       /agentic")
    print()
    print("  Claude will orchestrate the engagement using:")
    print("    - Layer 1 (layer1/rules/): Governance, tokens (rarely changes)")
    print("    - Layer 2 (layer2-templates/): Skillset, toolset, methodologies (grows)")
    print("    - Layer 3 (layer3-engagement/): Scope, ROE, config")
    print()
    print("═══════════════════════════════════════════════════════════════")
    print()


# ============== SCOPE INTAKE ==============

def _run_scope_intake(body_root: Path) -> int:
    print()
    print("▶ SCOPE INTAKE")
    script = body_root / "layer1" / "scripts" / "scope-intake.py"
    if script.is_file():
        return subprocess.run([sys.executable, str(script)]).returncode
    print("  scope-intake.py not found, skipping.", file=sys.stderr)
    return 0


# ============== PRECHECK + DRY-RUN ==============

def _run_precheck(body_root: Path) -> int:
    script = body_root / "layer1" / "scripts" / "precheck.py"
    if script.is_file():
        return subprocess.run([sys.executable, str(script)]).returncode
    print("  precheck.py not found, skipping.")
    return 0


def _run_dry_run(body_root: Path) -> int:
    print()
    print("▶ DRY-RUN CHECK")
    script = body_root / "layer1" / "scripts" / "dry-run.py"
    if script.is_file():
        rc = subprocess.run([sys.executable, str(script)]).returncode
        if rc != 0:
            print("  Note: Some dry-run checks failed (see above). Continuing...")
        return 0  # Non-fatal
    print("  dry-run.py not found, skipping.")
    return 0


# ============== MAIN FLOW ==============

def _run_setup(body_root: Path) -> int:
    _print_banner()

    # Run full precheck
    _run_precheck(body_root)

    # Preflight
    if not _preflight_check(body_root):
        return 1

    _ensure_structure(body_root)
    _reset_overrides(body_root)

    # Dry-run check (non-fatal)
    _run_dry_run(body_root)

    # Scope intake
    rc = _run_scope_intake(body_root)
    if rc != 0:
        print("Scope intake failed or was cancelled.", file=sys.stderr)
        return rc

    _show_launch_instructions()
    return 0


def _show_status(body_root: Path) -> None:
    _print_banner()
    print("▶ ENGAGEMENT STATUS")
    print()

    # Scope
    print("  Scope:")
    if _scope_configured(body_root):
        print("    Configured")
        scope = _scope_file(body_root)
        if scope.is_file():
            text = scope.read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                m = re.match(r"\*\*(?:Name|Target Name):\*\*\s*(.+)", line.strip())
                if m:
                    print(f"    Target: {m.group(1).strip()}")
                    break
    else:
        print("    Not configured")

    print()

    # Tokens
    print("  Token Status:")
    approvals_dir = body_root / ".bra" / "approvals"
    token_name = "ACTIVE-TESTING-APPROVAL"
    granted = approvals_dir.is_dir() and (approvals_dir / token_name).is_file()
    status = "GRANTED" if granted else "Not set"
    print(f"    {token_name}: {status}")

    print()

    # Artifacts
    total = _artifact_count(body_root)
    print(f"  Artifacts: {total} files")

    artifacts_dir = body_root / ".bra" / "artifacts"
    if artifacts_dir.is_dir():
        print()
        print("  Artifact directories:")
        for phase in ("intel", "static", "dynamic"):
            phase_dir = artifacts_dir / phase
            if phase_dir.is_dir():
                count = sum(1 for p in phase_dir.rglob("*") if p.is_file())
                print(f"    - {phase}: {count} files")

    print()
    _show_launch_instructions()


def _show_help() -> None:
    print("Usage: battlestations.py [--status|--help]")
    print("")
    print("  (no args)  Prepare for new engagement (banner → preflight → scope)")
    print("  --status   Show current engagement status")
    print("  --help     Show this help")
    print("")
    print("After running battlestations.py, start the engagement with:")
    print("  claude")
    print("  /agentic")


def _parse_args(argv: list[str]) -> SimpleNamespace:
    args = SimpleNamespace(status=False, help=False)
    for raw in argv:
        if raw == "--status":
            args.status = True
        elif raw in {"--help", "-h"}:
            args.help = True
        else:
            args.unknown = raw
            return args
    args.unknown = ""
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    body_root = _body_root()
    os.chdir(body_root)

    if args.status:
        _show_status(body_root)
        return 0

    if args.help:
        _show_help()
        return 0

    return _run_setup(body_root)


if __name__ == "__main__":
    raise SystemExit(main())
