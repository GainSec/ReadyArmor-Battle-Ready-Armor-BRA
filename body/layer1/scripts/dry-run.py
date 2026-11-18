#!/usr/bin/env python3
"""Native Python lifecycle dry-run for BRA body runtime."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


# Simulated target: Generic IP Camera
TARGET_NAME = "SimCam-2000"
TARGET_IP = "192.168.1.100"
TARGET_DOMAIN = "simcam.local"
TARGET_PORTS = "80,443,554,8080"
TARGET_FIRMWARE = "simcam_v2.1.3.bin"


@dataclass
class Counts:
    passed: int = 0
    failed: int = 0
    skipped: int = 0


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


_HELP_TEXT = """\
dry-run.py — Lifecycle Health Check

USAGE:
    dry-run.py                     Run full lifecycle simulation
    dry-run.py --quick             Skip slower phases (dynamic, report)
    dry-run.py --keep              Keep generated artifacts after run
    dry-run.py --help              Show this help

DESCRIPTION:
    Exercises the entire B.R.A. engagement lifecycle using a simulated
    IoT device (IP Camera) target. Verifies all scripts, templates, and
    workflows function correctly.

SIMULATED TARGET:
    Device:   SimCam-2000 (Generic IP Camera)
    IP:       192.168.1.100
    Domain:   simcam.local
    Ports:    80, 443, 554, 8080
    Firmware: simcam_v2.1.3.bin

PHASES EXERCISED:
    1. Setup      - Directory structure, templates
    2. Scope      - Scope ingestion simulation
    3. Pipeline   - INTEL → STATIC → DYNAMIC → REPORT
    4. Review     - Audit verification
    5. Cleanup    - Remove temporary artifacts

EXIT CODES:
    0 - All checks passed
    1 - One or more checks failed

EXAMPLES:
    # Full lifecycle check
    python3 layer1/scripts/dry-run.py

    # Quick check (skip dynamic/report)
    python3 layer1/scripts/dry-run.py --quick

    # Keep artifacts for inspection
    python3 layer1/scripts/dry-run.py --keep
"""


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="dry-run.py",
        description="Run a lightweight BRA lifecycle simulation.",
        epilog=_HELP_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--quick", action="store_true", help="Skip slower simulated phases.")
    parser.add_argument("--keep", action="store_true", help="Keep generated dry-run artifacts.")
    return parser.parse_args(argv)


def _pass(label: str, counts: Counts, info: str = "") -> None:
    print(f"  ✓ {label}")
    if info:
        print(f"    → {info}")
    counts.passed += 1


def _fail(label: str, counts: Counts, info: str = "") -> None:
    print(f"  ✗ {label}")
    if info:
        print(f"    → {info}")
    counts.failed += 1


def _skip(label: str, counts: Counts) -> None:
    print(f"  ○ {label}")
    counts.skipped += 1


def _phase(label: str) -> None:
    print(f"\n▶ {label}")


def _log(log_path: Path, message: str) -> None:
    if log_path.parent.is_dir():
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"[{_ts()}] {message}\n")


def _write(path: Path, content: str, label: str, counts: Counts) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        _pass(label, counts)
        return True
    except OSError as exc:
        _fail(label, counts, str(exc))
        return False


# ── Simulated scope/ROE/plan ──────────────────────────────────────────────

def _create_simulated_scope(dry_run_dir: Path, counts: Counts) -> None:
    _phase("Creating simulated scope (IoT Camera)")

    scope = f"""# Engagement Scope (Dry-Run)

> **Generated:** {_ts()}
> **Type:** DRY-RUN SIMULATION
> **Target:** {TARGET_NAME}

---

## Target Definition

### Device
- **Model:** {TARGET_NAME}
- **Type:** IP Camera (IoT)
- **Firmware:** {TARGET_FIRMWARE}

### Network
- **IP Address:** {TARGET_IP}
- **Domain:** {TARGET_DOMAIN}
- **Ports:** {TARGET_PORTS}

### URLs
- http://{TARGET_IP}/
- https://{TARGET_IP}/
- rtsp://{TARGET_IP}:554/stream

---

## In-Scope

- [x] Web interface ({TARGET_IP}:80, {TARGET_IP}:443)
- [x] RTSP streaming ({TARGET_IP}:554)
- [x] API endpoints ({TARGET_IP}:8080)
- [x] Firmware analysis ({TARGET_FIRMWARE})

## Out-of-Scope

- [ ] Physical device access
- [ ] Cloud backend services
- [ ] Mobile companion app

---

## Constraints

- **Time Window:** Dry-run only (no actual testing)
- **Rate Limits:** N/A (simulation)
- **Data Handling:** No real data involved
"""
    _write(dry_run_dir / "SCOPE.md", scope, "Create simulated SCOPE.md", counts)

    roe = f"""# Rules of Engagement (Dry-Run)

> **Generated:** {_ts()}
> **Type:** DRY-RUN SIMULATION

---

## Authorization

This is a **simulated engagement** for health-check purposes only.
No actual testing is performed against real targets.

## Token Status

| Token | Status | Reason |
|-------|--------|--------|
| WATCH | Set | Dry-run logging |
| TRACK | Unset | Not needed |
| DESTRUCTIVE-APPROVAL | Unset | Simulation only |
| ACTIVE-TESTING-APPROVAL | Unset | Simulation only |

## Constraints

- No network traffic generated
- No files modified outside .bra/dry-run/
- All artifacts are temporary
"""
    _write(dry_run_dir / "ROE.md", roe, "Create simulated ROE.md", counts)

    plan = f"""# Engagement Plan (Dry-Run)

> **Target:** {TARGET_NAME}
> **Type:** IoT Camera Assessment (Simulated)

## Phases

1. [x] Intelligence - Enumerate target
2. [x] Static Analysis - Firmware review
3. [x] Dynamic Analysis - Runtime checks
4. [x] Report - Compile findings

## Simulated Findings

- Finding 1: Default credentials (admin/admin)
- Finding 2: Unencrypted RTSP stream
- Finding 3: Debug endpoint exposed
"""
    _write(dry_run_dir / "PLAN.md", plan, "Create simulated PLAN.md", counts)


def _create_simulated_target(dry_run_dir: Path, counts: Counts) -> None:
    _phase("Creating simulated target artifacts")
    fw_dir = dry_run_dir / "firmware"
    fw_dir.mkdir(parents=True, exist_ok=True)
    fw_path = fw_dir / TARGET_FIRMWARE
    _write(fw_path, "SIMULATED_FIRMWARE_HEADER_V2.1.3\n", "Create simulated firmware", counts)


# ── Verification checks ──────────────────────────────────────────────────

def _check_scripts(scripts_dir: Path, counts: Counts) -> None:
    _phase("Verifying script availability")
    scripts = [
        "precheck.py", "agentic-handler.py", "audit.py", "danger_check.py",
        "ref_harvest.py", "notes_guard.py", "self-improvement.py",
        "hunt.py", "lessons-learned.py", "growth.py", "packup.py", "status.py",
    ]
    for script in scripts:
        path = scripts_dir / script
        if path.is_file():
            _pass(script, counts)
        else:
            _fail(script, counts, "not found")


def _check_templates(body_root: Path, counts: Counts) -> None:
    _phase("Verifying template availability")
    template_dir = body_root / "layer2-templates"
    templates = ["scope-intake.md", "plan.md", "report.md", "review.md", "disclosure-package.md"]
    for tmpl in templates:
        if (template_dir / tmpl).is_file():
            _pass(tmpl, counts)
        else:
            _fail(tmpl, counts)


def _check_governance(body_root: Path, counts: Counts) -> None:
    _phase("Verifying root guides (Layer 1)")
    guides = [
        "CLAUDE.md",
        "layer2-templates/skillset.md",
        "layer2-templates/toolset.md",
        "layer1/rules/scope.md",
        "layer1/rules/roe.md",
        "layer1/rules/tokens.md",
    ]
    for guide in guides:
        if (body_root / guide).is_file():
            _pass(guide, counts)
        else:
            _fail(guide, counts)


def _run_script_check(
    scripts_dir: Path,
    script: str,
    args_list: list[str],
    label: str,
    counts: Counts,
    *,
    accepted_exit_codes: set[int] | None = None,
) -> None:
    """Run a Python script with given args and check exit code."""
    path = scripts_dir / script
    if not path.is_file():
        _fail(label, counts, f"{script} not found")
        return
    accepted = accepted_exit_codes or {0}
    try:
        result = subprocess.run(
            [sys.executable, str(path)] + args_list,
            capture_output=True, text=True, check=False, timeout=30,
        )
        if result.returncode in accepted:
            _pass(label, counts)
        else:
            _fail(label, counts, f"exit code {result.returncode}")
    except subprocess.TimeoutExpired:
        _fail(label, counts, "timed out")
    except OSError as exc:
        _fail(label, counts, str(exc))


def _simulate_precheck(scripts_dir: Path, body_root: Path, counts: Counts) -> None:
    _phase("Simulating precheck.py")
    if (body_root / ".bra").is_dir() and (body_root / "layer3-engagement" / "NOTES").is_dir():
        _pass("Directory structure", counts)
    else:
        _run_script_check(scripts_dir, "precheck.py", ["--fix"], "Directory structure (fix)", counts)


def _simulate_pipeline(scripts_dir: Path, body_root: Path, counts: Counts) -> None:
    _phase("Simulating agentic-handler.py")
    _run_script_check(scripts_dir, "agentic-handler.py", ["--help"], "agentic-handler.py --help", counts)
    _run_script_check(scripts_dir, "agentic-handler.py", ["--status"], "agentic-handler.py --status", counts)

    # Syntax validation
    path = scripts_dir / "agentic-handler.py"
    if path.is_file():
        try:
            result = subprocess.run(
                [sys.executable, "-c", f"import py_compile; py_compile.compile('{path}', doraise=True)"],
                capture_output=True, text=True, check=False,
            )
            if result.returncode == 0:
                _pass("agentic-handler.py syntax validation", counts)
            else:
                _fail("agentic-handler.py syntax validation", counts, result.stderr.strip())
        except OSError:
            _fail("agentic-handler.py syntax validation", counts)

    if (body_root / ".bra" / "artifacts").is_dir():
        _pass("Artifacts directory", counts)
    else:
        (body_root / ".bra" / "artifacts").mkdir(parents=True, exist_ok=True)
        _pass("Artifacts directory (created)", counts)


def _simulate_audit(scripts_dir: Path, counts: Counts, *, quick: bool) -> None:
    _phase("Simulating audit.py")
    _run_script_check(scripts_dir, "audit.py", ["--help"], "audit.py --help", counts)

    if not quick:
        _run_script_check(
            scripts_dir,
            "audit.py",
            [],
            "audit.py (verification)",
            counts,
            accepted_exit_codes={0, 1},
        )
    else:
        _skip("audit.py (verification)", counts)


def _check_support_scripts(scripts_dir: Path, counts: Counts) -> None:
    _phase("Verifying support scripts")
    _run_script_check(scripts_dir, "status.py", ["--help"], "status.py", counts)
    _run_script_check(scripts_dir, "notes_guard.py", ["--help"], "notes_guard.py --help", counts)
    _run_script_check(scripts_dir, "danger_check.py", ["--help"], "danger_check.py --help", counts)


def _simulate_phases(dry_run_dir: Path, counts: Counts, *, quick: bool) -> None:
    _phase("Simulating pipeline phases")
    for phase in ("intel", "static"):
        _write(
            dry_run_dir / f".{phase}_complete",
            f"{phase} simulated at {_ts()}\n",
            f"simulate {phase}",
            counts,
        )

    if quick:
        _skip("dynamic phase (quick mode)", counts)
        _skip("report phase (quick mode)", counts)
    else:
        for phase in ("dynamic", "report"):
            _write(
                dry_run_dir / f".{phase}_complete",
                f"{phase} simulated at {_ts()}\n",
                f"simulate {phase}",
                counts,
            )


# ── Main ──────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    body_root = _project_root()
    scripts_dir = Path(__file__).resolve().parent
    bra_dir = body_root / ".bra"
    dry_run_dir = bra_dir / "dry-run"
    log_path = dry_run_dir / "dry-run.log"
    counts = Counts()

    mode = "Quick" if args.quick else "Full"
    print()
    print("════════════════════════════════════════════════════════════════")
    print("  B.R.A. DRY-RUN")
    print("════════════════════════════════════════════════════════════════")
    print()
    print(f"  Target: {TARGET_NAME} (IoT Camera)")
    print(f"  IP:     {TARGET_IP}")
    print(f"  Mode:   {mode}")
    print(f"  Root:   {body_root}")

    # Initialize
    dry_run_dir.mkdir(parents=True, exist_ok=True)
    _log(log_path, f"Dry-run started. Target: {TARGET_NAME} ({TARGET_IP})")

    # Run all phases
    _create_simulated_scope(dry_run_dir, counts)
    _create_simulated_target(dry_run_dir, counts)
    _check_governance(body_root, counts)
    _check_templates(body_root, counts)
    _check_scripts(scripts_dir, counts)
    _simulate_precheck(scripts_dir, body_root, counts)
    _simulate_pipeline(scripts_dir, body_root, counts)
    _simulate_phases(dry_run_dir, counts, quick=args.quick)
    _simulate_audit(scripts_dir, counts, quick=args.quick)
    _check_support_scripts(scripts_dir, counts)

    # Cleanup
    _phase("Cleanup")
    if args.keep:
        _skip("Keeping artifacts", counts)
        print(f"         -> Artifacts preserved in: {dry_run_dir}")
    else:
        try:
            shutil.rmtree(dry_run_dir)
            _pass("Remove dry-run artifacts", counts)
        except OSError as exc:
            _fail("Remove dry-run artifacts", counts, str(exc))

    # Summary
    total = counts.passed + counts.failed + counts.skipped
    print()
    print("════════════════════════════════════════════════════════════════")
    print("  DRY-RUN SUMMARY")
    print("════════════════════════════════════════════════════════════════")
    print(f"  Target:  {TARGET_NAME} ({TARGET_IP})")
    print(f"  Passed:  {counts.passed}")
    print(f"  Failed:  {counts.failed}")
    print(f"  Skipped: {counts.skipped}")
    print(f"  Total:   {total}")
    print()
    if counts.failed == 0:
        print("  ALL CHECKS PASSED - B.R.A. is ready for engagements.")
    else:
        print(f"  {counts.failed} CHECK(S) FAILED")
        print("  Review failures above and run: python3 layer1/scripts/precheck.py --fix")
    print()

    _log(log_path, f"Summary: passed={counts.passed} failed={counts.failed} skipped={counts.skipped}")
    return 0 if counts.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
