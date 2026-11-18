#!/usr/bin/env python3
"""approval-gate.py - Native pitch approval gate."""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PITCHES_DIR = PROJECT_ROOT / "layer3-engagement" / "pitches"
LOG_DIR = PROJECT_ROOT / ".bra" / "logs"
LOG_FILE = LOG_DIR / "approval_gate.log"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def init() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)


def log(level: str, message: str) -> None:
    try:
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"[{_utc_now()}] [{level}] {message}\n")
    except OSError:
        return


def show_help() -> None:
    print(
        "approval-gate.py -- Pitch Approval Gate for Growth Governance\n"
        "\n"
        "USAGE:\n"
        "    approval-gate.py                     List all pitches with status\n"
        "    approval-gate.py --check <pitch>     Check specific pitch approval status\n"
        "    approval-gate.py --list              List all pitches with status\n"
        "    approval-gate.py --block             Block if any pending approvals (for CI)\n"
        "    approval-gate.py --help              Show this help\n"
        "\n"
        "DESCRIPTION:\n"
        "    Enforces approval gates for B.R.A. growth governance.\n"
        "    New skills, tools, and major changes require pitch approval before\n"
        "    implementation.\n"
        "\n"
        "APPROVAL DETECTION:\n"
        "    A pitch is considered approved if ANY of these conditions are met:\n"
        "    1. Pitch file contains \"APPROVED\" text (case-insensitive)\n"
        "    2. .approved marker file exists alongside pitch\n"
        "    3. Pitch file contains \"STATUS: approved\" marker\n"
        "\n"
        "PITCH STRUCTURE:\n"
        "    layer3-engagement/pitches/\n"
        "    +-- add-skill-foo.md           Pitch file\n"
        "    +-- add-skill-foo.md.approved  Marker file (optional)\n"
        "    +-- add-tool-bar.md\n"
        "    +-- ...\n"
        "\n"
        "EXIT CODES:\n"
        "    0 - All required approvals present (or no pitches)\n"
        "    1 - Missing approvals (blocked)\n"
        "    2 - No pitches directory found\n"
        "\n"
        "EXAMPLES:\n"
        "    # List all pitches\n"
        "    ./approval-gate.py --list\n"
        "\n"
        "    # Check specific pitch\n"
        "    ./approval-gate.py --check layer3-engagement/pitches/add-skill-foo.md\n"
        "\n"
        "    # CI gate check (fails if pending)\n"
        "    ./approval-gate.py --block\n"
        "\n"
        "REFERENCED BY:\n"
        "    # - Prompt approval doc path removed [legacy/deprecated]\n"
        "    - skillset.md (Adding Skills)\n"
        "    - toolset.md (Adding Tools)\n"
    )


def pitch_is_approved(pitch_file: Path) -> bool:
    if not pitch_file.is_file():
        return False

    try:
        text = pitch_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False

    if re.search(r"NOT\s*APPROVED", text, flags=re.IGNORECASE):
        return False
    if re.search(r"APPROVED", text, flags=re.IGNORECASE):
        return True
    if (pitch_file.with_suffix(pitch_file.suffix + ".approved")).is_file():
        return True
    if re.search(r"STATUS:\s*approved", text, flags=re.IGNORECASE):
        return True
    return False


def iter_pitch_files() -> list[Path]:
    if not PITCHES_DIR.is_dir():
        return []
    return sorted(p for p in PITCHES_DIR.glob("*.md") if p.is_file())


def get_pitch_name(pitch_file: Path) -> str:
    return pitch_file.stem


def list_pitches() -> int:
    print("[GATE] Scanning pitches in", PITCHES_DIR)
    print()

    if not PITCHES_DIR.is_dir():
        print(f"No pitches directory. Create one at: {PITCHES_DIR}")
        return 2

    pitches = iter_pitch_files()
    total = len(pitches)
    approved = 0
    pending = 0

    print("| Pitch | Status | Source |")
    print("|-------|--------|--------|")
    for pitch in pitches:
        name = get_pitch_name(pitch)
        source = "-"
        status = "PENDING"
        try:
            text = pitch.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            text = ""

        marker = pitch.with_suffix(pitch.suffix + ".approved")
        if re.search(r"APPROVED", text, flags=re.IGNORECASE) and not re.search(
            r"NOT\s*APPROVED", text, flags=re.IGNORECASE
        ):
            status = "APPROVED"
            source = "text"
        elif marker.is_file():
            status = "APPROVED"
            source = "marker"
        elif re.search(r"STATUS:\s*approved", text, flags=re.IGNORECASE):
            status = "APPROVED"
            source = "status"

        if status == "APPROVED":
            approved += 1
        else:
            pending += 1
        print(f"| {name:<30} | {status:<8} | {source:<6} |")

    print()
    print(f"[INFO] Summary: {total} pitch(es), {approved} approved, {pending} pending")
    log("INFO", f"Summary: {total} pitch(es), {approved} approved, {pending} pending")
    if total == 0:
        print(f"[INFO] No pitches found in {PITCHES_DIR}")
        log("INFO", f"No pitches found in {PITCHES_DIR}")
        return 2
    return 0


def resolve_pitch(raw: str) -> Path | None:
    direct = Path(raw)
    if direct.is_file():
        return direct
    prefixed = PITCHES_DIR / raw
    if prefixed.is_file():
        return prefixed
    with_md = PITCHES_DIR / f"{raw}.md"
    if with_md.is_file():
        return with_md
    return None


def check_specific_pitch(raw: str) -> int:
    pitch = resolve_pitch(raw)
    if pitch is None:
        print(f"[ERROR] Pitch not found: {raw}")
        print("Search locations:")
        print(f"  - {raw}")
        print(f"  - {PITCHES_DIR / raw}")
        print(f"  - {PITCHES_DIR / (raw + '.md')}")
        log("ERROR", f"Pitch not found: {raw}")
        return 1

    name = get_pitch_name(pitch)
    print()
    print(f"[GATE] Checking approval for: {name}")
    print()

    if pitch_is_approved(pitch):
        print(f"[APPROVED] Pitch is APPROVED: {name}")
        print()
        print("Approval verified. Implementation may proceed.")
        log("APPROVED", f"Pitch is APPROVED: {name}")
        return 0

    print(f"[PENDING] Pitch is PENDING: {name}")
    print()
    print("Approval required before implementation.")
    print()
    print("To approve, do one of:")
    print(f"  1. Add 'APPROVED' text to the pitch file")
    print(f"  2. Create marker: touch {pitch}.approved")
    print(f"  3. Add 'STATUS: approved' to the pitch file")
    log("PENDING", f"Pitch is PENDING: {name}")
    return 1


def block_check() -> int:
    print("[GATE] Running approval gate block check")
    print()

    if not PITCHES_DIR.is_dir():
        print("[INFO] No pitches directory - gate OPEN")
        log("INFO", "No pitches directory - gate OPEN")
        return 0

    pending = [pitch for pitch in iter_pitch_files() if not pitch_is_approved(pitch)]
    if pending:
        print(f"[BLOCKED] Found {len(pending)} pending pitch(es) - gate BLOCKED")
        print()
        print("Pending approvals:")
        for p in pending:
            print(f"  - {get_pitch_name(p)}")
        print()
        print("Implementation blocked until approvals obtained.")
        log("BLOCKED", f"Found {len(pending)} pending pitch(es) - gate BLOCKED")
        return 1

    print("[APPROVED] All pitches approved - gate OPEN")
    log("APPROVED", "All pitches approved - gate OPEN")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    init()

    if not args:
        return list_pitches()
    if args[0] in {"--help", "-h"}:
        show_help()
        return 0
    if args[0] in {"--list", "-l"}:
        return list_pitches()
    if args[0] in {"--check", "-c"}:
        if len(args) < 2:
            print("[ERROR] No pitch specified for --check")
            log("ERROR", "No pitch specified for --check")
            show_help()
            return 1
        return check_specific_pitch(args[1])
    if args[0] in {"--block", "-b"}:
        return block_check()

    return check_specific_pitch(args[0])


if __name__ == "__main__":
    raise SystemExit(main())
