#!/usr/bin/env python3
"""Native deployment/preflight checks for BRA body runtime."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Totals:
    passed: int = 0
    failed: int = 0
    warned: int = 0
    fixed: int = 0


def _body_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit(kind: str, message: str, totals: Totals) -> None:
    print(f"[{kind}] {message}")
    if kind == "PASS":
        totals.passed += 1
    elif kind == "FAIL":
        totals.failed += 1
    elif kind == "WARN":
        totals.warned += 1
    elif kind == "FIXED":
        totals.fixed += 1


def _ensure_dir(path: Path, *, fix: bool, totals: Totals, root: Path) -> None:
    label = str(path.relative_to(root))
    if path.is_dir():
        _emit("PASS", f"{label}", totals)
        return
    if path.exists() and not path.is_dir():
        _emit("FAIL", f"{label} exists but is not a directory", totals)
        return
    if fix:
        path.mkdir(parents=True, exist_ok=True)
        _emit("FIXED", f"{label} created", totals)
        return
    _emit("FAIL", f"{label} missing", totals)


def _check_file(path: Path, *, totals: Totals, root: Path) -> None:
    label = str(path.relative_to(root))
    if path.is_file():
        _emit("PASS", label, totals)
    else:
        _emit("FAIL", f"{label} missing", totals)


def _check_tools(totals: Totals) -> None:
    required = ("git", "curl")
    optional = ("jq", "nmap", "adb", "radare2", "binwalk")

    for tool in required:
        if shutil.which(tool):
            _emit("PASS", f"tool {tool}", totals)
        else:
            _emit("FAIL", f"tool {tool} missing", totals)

    for tool in optional:
        if shutil.which(tool):
            _emit("PASS", f"optional tool {tool}", totals)
        else:
            _emit("WARN", f"optional tool {tool} missing", totals)


def _check_templates(body_root: Path, totals: Totals) -> None:
    template_dir = body_root / "layer2-templates"
    if not template_dir.is_dir():
        _emit("FAIL", "layer2-templates missing", totals)
        return

    md_count = sum(1 for path in template_dir.rglob("*.md") if path.is_file())
    if md_count >= 10:
        _emit("PASS", f"templates markdown count={md_count}", totals)
    else:
        _emit("WARN", f"templates markdown count={md_count}", totals)

    for rel in ("scope-intake.md", "plan.md", "report.md"):
        _check_file(template_dir / rel, totals=totals, root=body_root)


def _write_pipeline_state(body_root: Path) -> None:
    state_path = body_root / ".bra" / "pipeline_state.json"
    if state_path.exists():
        return
    payload = {
        "status": "initialized",
        "last_phase": "deploy",
        "timestamp": _utc_now(),
    }
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _check_killswitch(body_root: Path) -> bool:
    """Check kill switch. Returns True if active."""
    claude_md = body_root / "CLAUDE.md"
    if not claude_md.is_file():
        return False
    text = claude_md.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r"##\s*Kill\s*Switch\s*\n+```\s*\n\s*(STOP|CLEAR)\s*\n```", text, flags=re.IGNORECASE)
    return bool(match and match.group(1).upper() == "STOP")


def _validate_python_libs(body_root: Path, totals: Totals) -> None:
    """Validate Python library files have no syntax errors."""
    lib_dir = body_root / "layer1" / "lib"
    if not lib_dir.is_dir():
        _emit("WARN", "layer1/lib missing", totals)
        return

    py_files = sorted(lib_dir.glob("*.py"))
    errors = 0
    for py_file in py_files:
        result = subprocess.run(
            [sys.executable, "-c", f"import py_compile; py_compile.compile('{py_file}', doraise=True)"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            _emit("FAIL", f"syntax error in {py_file.name}: {result.stderr.strip()}", totals)
            errors += 1

    if errors == 0:
        _emit("PASS", f"library syntax: {len(py_files)} files OK", totals)


def _check_scripts_executable(body_root: Path, totals: Totals) -> None:
    """Check that script files have proper shebangs."""
    scripts_dir = body_root / "layer1" / "scripts"
    if not scripts_dir.is_dir():
        return
    for script in sorted(scripts_dir.glob("*.py")):
        try:
            first_line = script.read_text(encoding="utf-8", errors="ignore").split("\n", 1)[0]
            if not first_line.startswith("#!"):
                _emit("WARN", f"no shebang in {script.name}", totals)
        except OSError:
            pass


def _run_checks(body_root: Path, *, fix: bool, quick: bool) -> int:
    totals = Totals()

    # Kill switch check
    if _check_killswitch(body_root):
        print("Kill switch is ACTIVE. Deploy halted.", file=sys.stderr)
        print("")
        print("  To clear the kill switch:")
        print("    1. Edit CLAUDE.md")
        print("    2. Change STOP to CLEAR in Kill Switch section")
        return 99

    print("")
    print("    ____    ____       _")
    print("   / __ )  / __ \\     / \\")
    print("  / __  | / /_/ /    / _ \\")
    print(" / /_/ / / _, _/    / ___ \\")
    print("/_____(_)_/ |_(_)  /_/   \\_\\")
    print("")
    print("              B.R.A. DEPLOY")
    print("")
    print(f"Root: {body_root}")

    print("")
    print("━━━ KILL SWITCH ━━━")
    print("")
    _emit("PASS", "Kill switch is CLEAR", totals)

    print("")
    print("━━━ DIRECTORY STRUCTURE ━━━")
    print("")

    required_dirs = [
        ".bra",
        ".bra/artifacts",
        ".bra/artifacts/raw",
        ".bra/artifacts/intel_work",
        ".bra/artifacts/static_work",
        ".bra/artifacts/dynamic_work",
        ".bra/artifacts/report_work",
        ".bra/logs",
        ".bra/approvals",
        ".bra/one-time-approvals",
        ".bra/phase_state",
        ".bra/specs",
        ".bra/snapshots",
        ".bra/tmp",
        ".bra/config",
        ".bra/improvements",
        ".bra/locks",
        ".bra/dry-run",
        ".bra/ui",
        "layer3-engagement",
        "layer3-engagement/NOTES",
        "layer3-engagement/NOTES/reqs",
        "layer3-engagement/NOTES/reqs/reqfiles",
        "layer3-engagement/disclosure",
        "layer3-engagement/pitches",
        "layer3-engagement/ingest",
    ]

    for rel in required_dirs:
        _ensure_dir(body_root / rel, fix=fix, totals=totals, root=body_root)

    print("")
    print("━━━ GOVERNANCE FILES ━━━")
    print("")

    governance_files = [
        "CLAUDE.md",
        "layer1/rules/scope.md",
        "layer1/rules/roe.md",
        "layer1/rules/tokens.md",
        "layer2-templates/toolset.md",
        "layer2-templates/skillset.md",
    ]
    for rel in governance_files:
        _check_file(body_root / rel, totals=totals, root=body_root)

    if not quick:
        print("")
        print("━━━ TEMPLATES ━━━")
        print("")
        _check_templates(body_root, totals)

        print("")
        print("━━━ CORE TOOLS ━━━")
        print("")
        _check_tools(totals)

        print("")
        print("━━━ LIBRARIES ━━━")
        print("")
        _validate_python_libs(body_root, totals)

        print("")
        print("━━━ SCRIPTS ━━━")
        print("")
        _check_scripts_executable(body_root, totals)

    if fix:
        _write_pipeline_state(body_root)

    print("")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("                       DEPLOYMENT SUMMARY")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("")
    print(f"  Passed:   {totals.passed}")
    print(f"  Failed:   {totals.failed}")
    print(f"  Warnings: {totals.warned}")
    if totals.fixed > 0:
        print(f"  Fixed:    {totals.fixed}")
    print("")

    if totals.failed == 0:
        print("  ============================================")
        print("    DEPLOYMENT COMPLETE - READY FOR ACTION")
        print("  ============================================")
        print("")
        print("  Next step:")
        print("")
        print("    python3 layer1/scripts/battlestations.py")
        print("")
        print("  This will start the engagement pipeline.")
        print("")
        return 0
    print("  ============================================")
    print("    DEPLOYMENT INCOMPLETE - FIX ISSUES ABOVE")
    print("  ============================================")
    print("")
    print("  Run python3 layer1/scripts/deploy.py --fix to auto-fix issues")
    print("")
    return 1


def _parse_args(argv: list[str]) -> argparse.Namespace:
    epilog = """\
USAGE:
    python3 layer1/scripts/deploy.py              Full deployment with auto-fix
    python3 layer1/scripts/deploy.py --quick      Quick check, no fixes
    python3 layer1/scripts/deploy.py --fix        Auto-fix issues silently
    python3 layer1/scripts/deploy.py --help       Show this help

DESCRIPTION:
    Prepares the B.R.A. environment for an engagement by:

    1. Checking kill switch status
    2. Verifying directory structure
    3. Validating governance files
    4. Checking templates and methodologies
    5. Verifying scripts have shebangs
    6. Checking tool availability
    7. Validating library syntax
    8. Running full precheck

NEXT STEPS:
    After deployment completes successfully:

        python3 layer1/scripts/battlestations.py

    This launches the engagement pipeline starting with scope intake.
"""
    parser = argparse.ArgumentParser(
        description="Deploy/check BRA environment prerequisites.",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--quick", action="store_true", help="Skip template/tool checks.")
    parser.add_argument("--fix", action="store_true", help="Create missing directories/files where safe.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    body_root = _body_root()

    # Shell behavior: full deployment uses auto-fix by default.
    fix = True if not args.quick and not args.fix else args.fix
    return _run_checks(body_root, fix=fix, quick=args.quick)


if __name__ == "__main__":
    raise SystemExit(main())
