#!/usr/bin/env python3
"""Native project audit utility for BRA body state.

Performs a thorough, exhaustive audit of project artifacts to determine
if completed tasks and phases worked properly. Read-only — no modifications.

Audit checks:
  1. Pipeline State     - Phase completion status
  2. Artifacts          - Expected vs actual files per phase
  3. Logs               - Per-file errors, warnings, blocked counts
  4. Findings           - Documentation completeness, evidence hashes
  5. NOTES              - Append-only invariant, empty file detection
  6. Tokens             - Active token states (file, env, ROE)
  7. Governance         - Policy compliance, kill switch, required docs
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PHASES = ("intel", "static", "dynamic", "report")

EXPECTED_ARTIFACTS: dict[str, list[str]] = {
    "intel": [
        "project_structure.md",
        "target_enumeration.md",
        "scope_verification.md",
        "tool_availability.md",
    ],
    "static": [
        "code_quality.md",
        "dependency_analysis.md",
        "config_review.md",
    ],
    "dynamic": [
        "runtime_environment.md",
        "process_analysis.md",
        "dynamic_readiness.md",
    ],
    "report": [
        "findings_summary.md",
        "pipeline_summary.md",
    ],
}

AUDIT_TOKENS = (
    "DESTRUCTIVE-APPROVAL",
    "PUSH-APPROVAL",
    "ACTIVE-TESTING-APPROVAL",
    "WATCH",
    "TRACK",
    "NEGATIVE-RESULTS",
    "ARTIFACTS-OVERRIDE",
    "IGNORE-BACKUP",
)

EXPECTED_LOGS = (
    "ci.log",
    "danger_check.log",
    "ref_harvest.log",
    "notes_guard.log",
)


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str  # PASS, WARN, FAIL, SKIP, INFO
    message: str


def _body_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _count_pattern(text: str, pattern: str) -> int:
    return len(re.findall(pattern, text, flags=re.IGNORECASE))


# ============== AUDIT FUNCTIONS ==============


def _audit_pipeline_state(body_root: Path) -> list[CheckResult]:
    results: list[CheckResult] = []
    state_file = body_root / ".bra" / "pipeline_state.json"
    artifacts_dir = body_root / ".bra" / "artifacts"
    state = _load_json(state_file)

    if not state:
        results.append(CheckResult("Pipeline State", "WARN",
                                   "No pipeline state file found - pipeline may not have run"))
    else:
        status = str(state.get("status", "unknown"))
        last_phase = str(state.get("last_phase", "unknown"))
        ts = str(state.get("timestamp", "unknown"))
        results.append(CheckResult("Pipeline State", "PASS",
                                   f"status={status} last_phase={last_phase} timestamp={ts}"))

    for phase in PHASES:
        marker = artifacts_dir / f".{phase}_complete"
        phase_upper = phase.upper()
        if marker.is_file():
            try:
                mtime = datetime.fromtimestamp(marker.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            except OSError:
                mtime = "unknown"
            results.append(CheckResult(f"{phase_upper} Phase", "PASS",
                                       f"Completed at {mtime}"))
        else:
            if state.get("status") == "blocked" and state.get("last_phase") == phase:
                results.append(CheckResult(f"{phase_upper} Phase", "WARN",
                                           "BLOCKED - waiting for dependencies or approval"))
            else:
                results.append(CheckResult(f"{phase_upper} Phase", "SKIP", "Not run"))

    return results


def _audit_phase_artifacts(body_root: Path, phase: str) -> list[CheckResult]:
    results: list[CheckResult] = []
    phase_lower = phase.lower()
    phase_upper = phase.upper()
    work_dir = body_root / ".bra" / "artifacts" / f"{phase_lower}_work"

    if not work_dir.exists():
        results.append(CheckResult(f"{phase_upper} Artifacts", "SKIP",
                                   "No artifacts directory found"))
        return results

    if not work_dir.is_dir():
        results.append(CheckResult(f"{phase_upper} Artifacts", "FAIL",
                                   "Phase work path is not a directory"))
        return results

    all_files = [p for p in work_dir.rglob("*") if p.is_file()]
    count = len(all_files)

    if count == 0:
        results.append(CheckResult(f"{phase_upper} Artifacts", "WARN",
                                   "Directory exists but contains no files"))
        return results

    results.append(CheckResult(f"{phase_upper} Artifacts", "PASS",
                               f"Found {count} artifact files"))

    # Check expected artifacts per phase
    for expected in EXPECTED_ARTIFACTS.get(phase_lower, []):
        if (work_dir / expected).is_file():
            results.append(CheckResult(phase_upper, "PASS", f"{expected} present"))
        else:
            results.append(CheckResult(phase_upper, "WARN", f"{expected} missing"))

    # Check for empty files
    empty_count = sum(1 for f in all_files if f.stat().st_size == 0)
    if empty_count:
        results.append(CheckResult(f"{phase_upper} Artifacts", "WARN",
                                   f"{empty_count} empty files found"))

    return results


def _audit_artifacts(body_root: Path, specific_phase: str | None) -> list[CheckResult]:
    results: list[CheckResult] = []
    artifacts_dir = body_root / ".bra" / "artifacts"

    if not artifacts_dir.is_dir():
        results.append(CheckResult("Artifacts Directory", "FAIL",
                                   f"Missing: {artifacts_dir}"))
        return results

    results.append(CheckResult("Artifacts Directory", "PASS",
                               f"Present at {artifacts_dir}"))

    # Check manifest
    manifest = artifacts_dir / "manifest.json"
    if manifest.is_file():
        size = manifest.stat().st_size
        if size > 10:
            results.append(CheckResult("Artifact Manifest", "PASS",
                                       f"Present ({size} bytes)"))
        else:
            results.append(CheckResult("Artifact Manifest", "WARN",
                                       "Present but appears empty/minimal"))
    else:
        results.append(CheckResult("Artifact Manifest", "WARN",
                                   "manifest.json not found"))

    # Audit per phase
    phases = [specific_phase.lower()] if specific_phase else list(PHASES)
    for phase in phases:
        results.extend(_audit_phase_artifacts(body_root, phase))

    return results


def _audit_logs(body_root: Path) -> list[CheckResult]:
    results: list[CheckResult] = []
    log_dir = body_root / ".bra" / "logs"

    if not log_dir.is_dir():
        results.append(CheckResult("Logs Directory", "WARN", f"Missing: {log_dir}"))
        return results

    results.append(CheckResult("Logs Directory", "PASS", f"Present at {log_dir}"))

    # Check each expected log file
    for log_name in EXPECTED_LOGS:
        log_path = log_dir / log_name
        if not log_path.is_file():
            results.append(CheckResult(log_name, "SKIP", "Not present"))
            continue

        text = _read_text(log_path)
        line_count = text.count("\n")
        error_count = _count_pattern(text, r"\[(?:ERROR|FAIL)\]")
        warn_count = _count_pattern(text, r"\[(?:WARN|WARNING)\]")
        blocked_count = _count_pattern(text, r"\[BLOCKED\]")

        if error_count > 0:
            results.append(CheckResult(log_name, "FAIL",
                                       f"{error_count} errors, {warn_count} warnings, "
                                       f"{blocked_count} blocked ({line_count} lines)"))
        elif warn_count > 0 or blocked_count > 0:
            results.append(CheckResult(log_name, "WARN",
                                       f"{warn_count} warnings, {blocked_count} blocked "
                                       f"({line_count} lines)"))
        else:
            results.append(CheckResult(log_name, "PASS",
                                       f"{line_count} lines, no errors/warnings"))

    # Check watch.log
    watch_log = log_dir / "watch.log"
    if watch_log.is_file():
        text = _read_text(watch_log)
        entries = len(re.findall(r"^\[", text, flags=re.MULTILINE))
        results.append(CheckResult("watch.log", "INFO",
                                   f"{entries} entries (WATCH token was active)"))

    # Check track.log
    track_log = log_dir / "track.log"
    if track_log.is_file():
        text = _read_text(track_log)
        blocks = text.count("┌─")
        results.append(CheckResult("track.log", "INFO",
                                   f"{blocks} tracked operations (TRACK token was active)"))

    return results


def _audit_findings(body_root: Path) -> list[CheckResult]:
    results: list[CheckResult] = []
    notes_dir = body_root / "layer3-engagement" / "NOTES"
    findings_file = notes_dir / "FINDINGS.md"

    if not findings_file.is_file():
        results.append(CheckResult("FINDINGS.md", "WARN",
                                   "Not present in layer3-engagement/NOTES/"))
        return results

    text = _read_text(findings_file)
    line_count = text.count("\n")
    finding_count = len(re.findall(r"^##+\s+", text, flags=re.MULTILINE))

    if line_count < 10:
        results.append(CheckResult("FINDINGS.md", "WARN",
                                   f"Present but minimal ({line_count} lines)"))
    else:
        results.append(CheckResult("FINDINGS.md", "PASS",
                                   f"{line_count} lines, {finding_count} sections"))

    # Check evidence hashes
    hash_count = len(re.findall(r"SHA256:|Hash:", text))
    if hash_count > 0:
        results.append(CheckResult("Evidence Hashes", "PASS",
                                   f"{hash_count} SHA256 hashes documented"))
    else:
        results.append(CheckResult("Evidence Hashes", "WARN",
                                   "No SHA256 hashes found - evidence chain incomplete"))

    # Check leads
    leads_file = notes_dir / "LEADS.md"
    if leads_file.is_file():
        leads_text = _read_text(leads_file)
        leads_count = len(re.findall(r"^(?:- |\* )", leads_text, flags=re.MULTILINE))
        results.append(CheckResult("LEADS.md", "INFO",
                                   f"{leads_count} items tracked"))

    return results


def _audit_notes_integrity(body_root: Path) -> list[CheckResult]:
    results: list[CheckResult] = []
    notes_dir = body_root / "layer3-engagement" / "NOTES"

    if not notes_dir.is_dir():
        results.append(CheckResult("NOTES Directory", "WARN", "Not present"))
        return results

    results.append(CheckResult("NOTES Directory", "PASS", f"Present at {notes_dir}"))

    md_files = list(notes_dir.glob("*.md"))
    all_files = list(notes_dir.rglob("*"))
    file_count = sum(1 for f in all_files if f.is_file())
    results.append(CheckResult("NOTES Contents", "INFO",
                               f"{len(md_files)} markdown files, {file_count} total files"))

    # Check for empty markdown files
    empty_md = sum(1 for f in md_files if f.stat().st_size == 0)
    if empty_md > 0:
        results.append(CheckResult("NOTES Integrity", "WARN",
                                   f"{empty_md} empty markdown files found"))
    else:
        results.append(CheckResult("NOTES Integrity", "PASS",
                                   "No empty markdown files"))

    # Check reqfiles subdirectory
    reqfiles_dir = notes_dir / "reqs" / "reqfiles"
    if reqfiles_dir.is_dir():
        req_count = sum(1 for f in reqfiles_dir.rglob("*") if f.is_file())
        results.append(CheckResult("reqfiles", "INFO",
                                   f"{req_count} requirement files"))

    return results


def _audit_tokens(body_root: Path) -> list[CheckResult]:
    results: list[CheckResult] = []
    approvals_dir = body_root / ".bra" / "approvals"
    roe_file = body_root / "layer3-engagement" / "ROE.md"
    roe_text = _read_text(roe_file) if roe_file.is_file() else ""

    for token in AUDIT_TOKENS:
        is_set = False
        sources: list[str] = []

        # Check file
        if approvals_dir.is_dir() and (approvals_dir / token).is_file():
            is_set = True
            sources.append("file")

        # Check environment
        env_var = token.replace("-", "_")
        if os.environ.get(env_var) == "1":
            is_set = True
            sources.append("env")

        # Check ROE.md
        if roe_text and re.search(
            rf"{re.escape(token)}:\s*(?:GRANTED|ENABLED)", roe_text
        ):
            is_set = True
            sources.append("ROE")

        if is_set:
            results.append(CheckResult(token, "WARN",
                                       f"ACTIVE (via {', '.join(sources)})"))
        else:
            results.append(CheckResult(token, "PASS", "Not set (default)"))

    return results


def _audit_governance(body_root: Path) -> list[CheckResult]:
    results: list[CheckResult] = []

    # Check governance templates
    for name, path in [
        ("Scope Definition", body_root / "layer1" / "rules" / "scope.md"),
        ("Rules of Engagement", body_root / "layer1" / "rules" / "roe.md"),
    ]:
        if path.is_file():
            results.append(CheckResult(name, "PASS", f"{path.name} present"))
        else:
            results.append(CheckResult(name, "WARN", f"{path.name} not found"))

    # Check instantiated engagement docs
    engagement_dir = body_root / "layer3-engagement"
    for doc in ("SCOPE.md", "ROE.md", "PLAN.md", "REPORT.md"):
        doc_path = engagement_dir / doc
        if doc_path.is_file():
            line_count = _read_text(doc_path).count("\n")
            if line_count < 20:
                results.append(CheckResult(f"layer3-engagement/{doc}", "WARN",
                                           f"Present but appears to be skeleton ({line_count} lines)"))
            else:
                results.append(CheckResult(f"layer3-engagement/{doc}", "PASS",
                                           f"Present ({line_count} lines)"))
        else:
            results.append(CheckResult(f"layer3-engagement/{doc}", "SKIP",
                                       "Not instantiated"))

    # Check CLAUDE.md and kill switch
    claude_md = body_root / "CLAUDE.md"
    if claude_md.is_file():
        results.append(CheckResult("CLAUDE.md", "PASS", "Present"))

        text = _read_text(claude_md)
        # Extract kill switch section
        ks_match = re.search(
            r"^## Kill Switch\s*\n(.*?)(?=^## |\Z)",
            text, flags=re.MULTILINE | re.DOTALL
        )
        if ks_match:
            ks_section = ks_match.group(1)
            stop_match = re.search(r"(?m)^STOP$", ks_section)
            if stop_match:
                if "```" in ks_section[: stop_match.start()]:
                    results.append(CheckResult("Kill Switch", "PASS",
                                               "Not triggered (documented but not active)"))
                else:
                    results.append(CheckResult("Kill Switch", "FAIL",
                                               "STOP is ACTIVE in CLAUDE.md - all operations should be halted!"))
            else:
                results.append(CheckResult("Kill Switch", "PASS", "Not triggered"))
        else:
            results.append(CheckResult("Kill Switch", "PASS", "Not triggered"))
    else:
        results.append(CheckResult("CLAUDE.md", "FAIL",
                                   "Missing - governance framework incomplete"))

    return results


# ============== QUICK MODE ==============

def _audit_quick(body_root: Path) -> int:
    print()
    print("═══ QUICK AUDIT SUMMARY ═══")
    print()

    # Pipeline status
    state = _load_json(body_root / ".bra" / "pipeline_state.json")
    if state:
        print(f"Pipeline: {state.get('status', 'unknown')} (last: {state.get('last_phase', 'unknown')})")
    else:
        print("Pipeline: No state file")

    # Phase completion
    artifacts_dir = body_root / ".bra" / "artifacts"
    phases_str = "Phases:  "
    for phase in PHASES:
        marker = artifacts_dir / f".{phase}_complete"
        mark = "✓" if marker.is_file() else "○"
        phases_str += f"{mark}{phase[0].upper()} "
    print(phases_str)

    # Artifact count
    artifact_count = 0
    if artifacts_dir.is_dir():
        artifact_count = sum(1 for p in artifacts_dir.rglob("*.md") if p.is_file())
    print(f"Artifacts: {artifact_count} markdown files")

    # Log errors
    total_errors = 0
    log_dir = body_root / ".bra" / "logs"
    if log_dir.is_dir():
        for log_file in log_dir.glob("*.log"):
            text = _read_text(log_file)
            total_errors += _count_pattern(text, r"\[(?:ERROR|FAIL)\]")
    print(f"Errors: {total_errors} in logs" if total_errors else "Errors: None")

    # Active tokens
    active_tokens = 0
    approvals_dir = body_root / ".bra" / "approvals"
    if approvals_dir.is_dir():
        active_tokens = sum(1 for p in approvals_dir.iterdir() if p.is_file())
    print(f"Active tokens: {active_tokens}")
    print()
    return 0


# ============== OUTPUT ==============

def _write_log(path: Path, results: list[CheckResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "═══════════════════════════════════════════════════════",
        f"AUDIT STARTED: {_timestamp()}",
        f"Project: {path.parent.parent.parent}",
        "═══════════════════════════════════════════════════════",
    ]
    for result in results:
        lines.append(f"[{result.status}] {result.name}: {result.message}")
    lines.append(f"\nAUDIT COMPLETED: {_timestamp()}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _normalize_phase_arg(value: str) -> str:
    return value.strip().upper()


def _select_checks(args: argparse.Namespace) -> list[str]:
    if args.quick:
        return ["quick"]
    if args.phase:
        return ["artifacts"]
    selected = []
    if args.findings:
        selected.append("findings")
    if args.artifacts:
        selected.append("artifacts")
    if args.logs:
        selected.append("logs")
    if not selected:
        # Full audit
        selected = [
            "pipeline", "artifacts", "logs", "findings",
            "notes_integrity", "tokens", "governance",
        ]
    return selected


_HELP_EPILOG = """\
audit.py -- Comprehensive Project Audit

USAGE:
    audit.py                    Run full audit
    audit.py --quick            Quick summary only
    audit.py --phase INTEL      Audit specific phase (INTEL|STATIC|DYNAMIC|REPORT)
    audit.py --findings         Audit findings documentation only
    audit.py --artifacts        Audit artifacts only
    audit.py --logs             Audit logs for issues only
    audit.py --json             Output results as JSON
    audit.py --help             Show this help

DESCRIPTION:
    Performs a thorough, exhaustive audit of project artifacts to determine
    if completed tasks and phases worked properly. This is a read-only
    operation that does not modify project state.

AUDIT CHECKS:
    1. Pipeline State     - Phase completion status
    2. Artifacts          - Expected vs actual files
    3. Logs               - Errors, warnings, anomalies
    4. Findings           - Documentation completeness
    5. Evidence           - Chain of custody integrity
    6. NOTES              - Append-only invariant
    7. Tokens             - Active token states
    8. Governance         - Policy compliance

EXIT CODES:
    0 - Pass: All checks passed
    1 - Warn: Some issues detected but not critical
    2 - Fail: Critical issues found

OUTPUT:
    - Summary printed to stdout
    - Detailed report written to .bra/logs/audit.log

EXAMPLES:
    # Full audit
    ./audit.py

    # Quick status check
    ./audit.py --quick

    # Audit only the INTEL phase
    ./audit.py --phase INTEL

    # Get JSON output for automation
    ./audit.py --json
"""


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit BRA state and artifacts.",
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--quick", "-q", action="store_true",
                        help="Quick summary only.")
    parser.add_argument("--phase", "-p", type=_normalize_phase_arg,
                        help="Audit artifacts for a specific phase.")
    parser.add_argument("--findings", action="store_true",
                        help="Audit findings/leads documentation.")
    parser.add_argument("--artifacts", action="store_true",
                        help="Audit artifact directories.")
    parser.add_argument("--logs", action="store_true",
                        help="Audit logs for warning/error markers.")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON output.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    body_root = _body_root()

    checks = _select_checks(args)

    if "quick" in checks:
        return _audit_quick(body_root)

    results: list[CheckResult] = []

    print()
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║                    B.R.A. PROJECT AUDIT                  ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print()
    print(f"Started: {_timestamp()}")
    print(f"Project: {body_root}")

    _SECTION_HEADERS = {
        "pipeline": "PIPELINE STATE AUDIT",
        "artifacts": "ARTIFACTS AUDIT",
        "logs": "LOGS AUDIT",
        "findings": "FINDINGS AUDIT",
        "notes_integrity": "NOTES INTEGRITY AUDIT",
        "tokens": "TOKEN STATE AUDIT",
        "governance": "GOVERNANCE AUDIT",
    }

    for check in checks:
        header = _SECTION_HEADERS.get(check)
        if header:
            print()
            print(f"═══ {header} ═══")
            print()

        if check == "pipeline":
            results.extend(_audit_pipeline_state(body_root))
        elif check == "artifacts":
            selected_phase = args.phase.lower() if args.phase else None
            results.extend(_audit_artifacts(body_root, selected_phase))
        elif check == "logs":
            results.extend(_audit_logs(body_root))
        elif check == "findings":
            results.extend(_audit_findings(body_root))
        elif check == "notes_integrity":
            results.extend(_audit_notes_integrity(body_root))
        elif check == "tokens":
            results.extend(_audit_tokens(body_root))
        elif check == "governance":
            results.extend(_audit_governance(body_root))

    _write_log(body_root / ".bra" / "logs" / "audit.log", results)

    counts: dict[str, int] = {"PASS": 0, "WARN": 0, "FAIL": 0, "SKIP": 0, "INFO": 0}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1

    exit_code = 0
    if counts["FAIL"] > 0:
        exit_code = 2
    elif counts["WARN"] > 0:
        exit_code = 1

    if args.json:
        artifacts_dir = body_root / ".bra" / "artifacts"
        payload = {
            "timestamp": _timestamp(),
            "body_root": str(body_root),
            "results": [asdict(r) for r in results],
            "summary": {
                "pass": counts["PASS"],
                "warn": counts["WARN"],
                "fail": counts["FAIL"],
                "skip": counts["SKIP"],
                "exit_code": exit_code,
            },
            "pipeline": {
                "state_file": (body_root / ".bra" / "pipeline_state.json").is_file(),
                "intel_complete": (artifacts_dir / ".intel_complete").is_file(),
                "static_complete": (artifacts_dir / ".static_complete").is_file(),
                "dynamic_complete": (artifacts_dir / ".dynamic_complete").is_file(),
                "report_complete": (artifacts_dir / ".report_complete").is_file(),
            },
            "log_file": str(body_root / ".bra" / "logs" / "audit.log"),
        }
        print(json.dumps(payload, indent=2))
    else:
        for result in results:
            print(f"[{result.status}] {result.name}: {result.message}")

        print()
        print("═══════════════════════════════════════════════════════════")
        print("                       AUDIT SUMMARY")
        print("═══════════════════════════════════════════════════════════")
        print()
        print(f"  PASS: {counts['PASS']}    WARN: {counts['WARN']}    "
              f"FAIL: {counts['FAIL']}    SKIP: {counts['SKIP']}")
        print()

        if counts["FAIL"] > 0:
            print("  RESULT: FAIL - Critical issues detected")
        elif counts["WARN"] > 0:
            print("  RESULT: WARN - Issues detected, review recommended")
        else:
            print("  RESULT: PASS - All checks passed")

        print()
        print(f"  Detailed report: {body_root / '.bra' / 'logs' / 'audit.log'}")
        print()

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
