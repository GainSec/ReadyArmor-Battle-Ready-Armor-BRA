#!/usr/bin/env python3
"""hunt.py — Lead Hunting & Gap Analysis Engine

Purpose: Derive leads from project artifacts that aren't being analyzed/tested
Invariant: Outputs to pitch document only; user must approve additions to layer3-engagement/NOTES/LEADS.md

Runs:
  - When LEADS.md has entries (Claude offers to run it in /agentic loop)
  - At phase transitions (Claude offers during collaborative execution)
  - On-demand by user

Per-phase hunting with specific detection rules, duplicate checking
against LEADS.md/FINDINGS.md, and change detection via directory hashing.

Exit Codes:
  0 - Success (leads found and pitched)
  1 - Error (write failure)
  2 - No new leads found

Referenced By:
  - .claude/commands/agentic.md (collaborative loop)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable


# ============== PER-PHASE HUNT RULES ==============
# Each rule: (title, regex_pattern, priority, phase_scope)
# phase_scope: "intel", "static", "dynamic", "report", "logs", or "all"

HUNT_RULES: tuple[tuple[str, str, str, str], ...] = (
    # Intel phase rules
    ("Untested Binary", r"(?:\.apk|\.ipa|\.bin|\.elf|\.exe|\.dll|\.so|\.dylib)\b", "HIGH", "intel"),
    ("Missing Scope Coverage", r"\b(?:not[\s]+(?:tested|scanned|reviewed)|out[\s]+of[\s]+scope|untested)\b", "HIGH", "intel"),
    ("Tool Gap", r"\b(?:tool[\s]+(?:not[\s]+(?:found|available|installed)|missing)|no[\s]+(?:tool|scanner))\b", "MEDIUM", "intel"),
    ("Config File Found", r"(?:\.conf|\.cfg|\.ini|\.env|\.properties|\.yaml|\.yml|\.toml)\b", "MEDIUM", "intel"),
    ("Database Found", r"(?:\.db|\.sqlite|\.sqlite3|\.sql)\b", "MEDIUM", "intel"),

    # Static phase rules
    ("Hardcoded Secret", r"\b(?:password|passwd|secret|api[_-]?key|token|credential)\s*[=:]\s*['\"][^'\"]{3,}", "CRITICAL", "static"),
    ("TODO/FIXME Marker", r"\b(?:TODO|FIXME|HACK|XXX|UNDONE)\b", "MEDIUM", "static"),
    ("Dependency Issue", r"\b(?:deprecated|outdated|vulnerable[\s]+(?:version|dependency|package)|CVE-\d{4}-\d+)\b", "HIGH", "static"),
    ("Env File", r"(?:^|\/)\.env(?:\.|$)", "HIGH", "static"),
    ("Debug Code", r"\b(?:console\.log|print\(|printf\(|System\.out|debugger|breakpoint\(\))\b", "LOW", "static"),

    # Dynamic phase rules
    ("Network Service", r"\b(?:open[\s]+port|listening[\s]+on|service[\s]+(?:running|detected)|LISTEN)\b", "HIGH", "dynamic"),
    ("Debug Mode Active", r"\b(?:debug[\s]*=[\s]*(?:true|1|on)|DEBUG_MODE|development[\s]+mode)\b", "HIGH", "dynamic"),
    ("Instrumentation Gap", r"\b(?:no[\s]+(?:coverage|instrumentation|hook)|uninstrumented|unhooked)\b", "MEDIUM", "dynamic"),
    ("Crash/Fault", r"\b(?:segfault|SIGSEGV|crash|abort|core[\s]+dump|panic)\b", "HIGH", "dynamic"),

    # Report phase rules
    ("Incomplete Phase", r"\b(?:incomplete|not[\s]+(?:started|finished)|pending|skipped[\s]+phase)\b", "HIGH", "report"),
    ("Low Finding Count", r"\b(?:no[\s]+findings|0[\s]+findings|zero[\s]+findings)\b", "MEDIUM", "report"),
    ("Missing Section", r"\b(?:section[\s]+(?:missing|empty|incomplete)|TBD|_TBD_)\b", "MEDIUM", "report"),

    # Log phase rules
    ("Error Pattern", r"\[(?:ERROR|FAIL)\]", "HIGH", "logs"),
    ("Blocked Operation", r"\[BLOCKED\]", "MEDIUM", "logs"),
    ("Danger Check Block", r"(?:BLOCKED|danger_check)", "MEDIUM", "logs"),
    ("Timeout", r"\b(?:timeout|timed[\s]+out|connection[\s]+refused)\b", "MEDIUM", "logs"),

    # Universal rules (all phases)
    ("Security Signal", r"\b(?:vulnerab|bypass|injection|auth(?:entication|orization)?\s+fail)\b", "HIGH", "all"),
    ("Operational Blocker", r"\b(?:blocked|denied|unreachable|forbidden|403|401)\b", "MEDIUM", "all"),
)


def _body_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _append_log(log_file: Path, message: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(f"[{_utc_now()}] {message}\n")


def _load_state(state_file: Path) -> dict[str, object]:
    if not state_file.is_file():
        return {"total_leads_proposed": 0, "pending_pitches": 0, "timestamp": _utc_now()}
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    return {"total_leads_proposed": 0, "pending_pitches": 0, "timestamp": _utc_now()}


def _save_state(state_file: Path, payload: dict[str, object]) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# ============== CHANGE DETECTION ==============

def _dir_hash(directory: Path) -> str:
    """Hash directory contents for change detection."""
    h = hashlib.sha256()
    if not directory.is_dir():
        return ""
    for f in sorted(directory.rglob("*")):
        if f.is_file():
            try:
                h.update(f.name.encode())
                h.update(str(f.stat().st_size).encode())
                h.update(str(int(f.stat().st_mtime)).encode())
            except OSError:
                pass
    return h.hexdigest()[:16]


def _has_changed(state: dict[str, object], phase: str, current_hash: str) -> bool:
    """Check if phase directory has changed since last hunt."""
    hashes = state.get("dir_hashes", {})
    if not isinstance(hashes, dict):
        return True
    prev = hashes.get(phase, "")
    return prev != current_hash


def _update_hash(state: dict[str, object], phase: str, current_hash: str) -> None:
    if "dir_hashes" not in state or not isinstance(state.get("dir_hashes"), dict):
        state["dir_hashes"] = {}
    state["dir_hashes"][phase] = current_hash


# ============== DUPLICATE CHECKING ==============

def _load_existing_leads(body_root: Path) -> set[str]:
    """Load existing lead titles/snippets from LEADS.md and FINDINGS.md for dedup."""
    existing: set[str] = set()
    notes_dir = body_root / "layer3-engagement" / "NOTES"

    for filename in ("LEADS.md", "FINDINGS.md"):
        path = notes_dir / filename
        if path.is_file():
            text = _safe_text(path)
            # Extract bullet items and headings as dedup keys
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("- ") or stripped.startswith("* "):
                    # Normalize for comparison
                    existing.add(stripped[2:].strip().lower()[:100])
                elif stripped.startswith("## ") or stripped.startswith("### "):
                    existing.add(stripped.lstrip("#").strip().lower()[:100])

    return existing


def _is_duplicate(lead: dict[str, str], existing: set[str]) -> bool:
    """Check if lead is already documented."""
    hypothesis = lead.get("hypothesis", "").lower()[:100]
    title = lead.get("title", "").lower()[:100]

    for existing_key in existing:
        # Fuzzy match: if significant overlap in text
        if existing_key and (existing_key in hypothesis or hypothesis in existing_key):
            return True
        if existing_key and (existing_key in title or title in existing_key):
            return True

    return False


# ============== FILE COLLECTION ==============

def _iter_source_files(paths: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for source in paths:
        if source.is_file():
            files.append(source)
        elif source.is_dir():
            files.extend(path for path in source.rglob("*") if path.is_file())
    return sorted(files)


def _phase_for_path(file_path: Path, body_root: Path) -> str:
    """Determine which phase a file belongs to based on its path."""
    try:
        rel = file_path.relative_to(body_root).as_posix()
    except ValueError:
        return "all"

    if "intel_work" in rel:
        return "intel"
    elif "static_work" in rel:
        return "static"
    elif "dynamic_work" in rel:
        return "dynamic"
    elif "report_work" in rel:
        return "report"
    elif "/logs/" in rel or rel.endswith(".log"):
        return "logs"
    return "all"


# ============== LEAD DERIVATION ==============

def _derive_leads(files: list[Path], body_root: Path, phase_filter: str | None = None) -> list[dict[str, str]]:
    leads: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    existing = _load_existing_leads(body_root)

    for file_path in files:
        text = _safe_text(file_path)
        if not text:
            continue
        rel = file_path.relative_to(body_root).as_posix() if file_path.is_relative_to(body_root) else str(file_path)
        file_phase = _phase_for_path(file_path, body_root)

        for title, pattern, priority, rule_phase in HUNT_RULES:
            # Skip rules not applicable to this file's phase
            if rule_phase != "all" and rule_phase != file_phase:
                continue
            if phase_filter and rule_phase != "all" and rule_phase != phase_filter:
                continue

            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                start = max(0, match.start() - 70)
                end = min(len(text), match.end() + 70)
                snippet = " ".join(text[start:end].split())
                key = (title, snippet[:100])
                if key in seen:
                    continue
                seen.add(key)

                lead = {
                    "title": title,
                    "hypothesis": f"{title.lower()} observed in {rel}",
                    "evidence": f"`{rel}`: {snippet[:220]}",
                    "priority": priority,
                    "effort": "Quick check" if priority in ("MEDIUM", "LOW") else "Investigation",
                    "next_steps": _suggest_next_steps(title, priority),
                    "phase": file_phase,
                }

                # Dedup against existing leads/findings
                if _is_duplicate(lead, existing):
                    continue

                leads.append(lead)
                if len(leads) >= 40:
                    return leads

    return leads


def _suggest_next_steps(title: str, priority: str) -> str:
    """Generate specific next steps based on lead type."""
    steps = {
        "Hardcoded Secret": "grep -r for the secret pattern; verify if it's a real credential vs. placeholder.",
        "Untested Binary": "Run file/strings on the binary; check for known vulnerability signatures.",
        "Missing Scope Coverage": "Create scope.md defining in-scope and out-of-scope targets.",
        "Tool Gap": "Install missing tools or document why testing is skipped.",
        "Config File Found": "Review config files for hardcoded secrets, debug flags, insecure defaults.",
        "Database Found": "Examine database schema and contents for sensitive data exposure.",
        "TODO/FIXME Marker": "Review TODO comments for security-relevant incomplete features.",
        "Dependency Issue": "Run dependency vulnerability scanner (npm audit, pip-audit, etc.).",
        "Env File": "Review .env files for secrets; check if .env.example exposes patterns.",
        "Debug Code": "Check if debug output leaks sensitive information in production.",
        "Network Service": "Enumerate listening services; test for authentication bypass, injection.",
        "Debug Mode Active": "Verify if debug endpoints exist; check for verbose error disclosure.",
        "Instrumentation Gap": "Install missing tools or document why dynamic analysis is limited.",
        "Crash/Fault": "Analyze crash dump for exploitability; check if it's reproducible.",
        "Incomplete Phase": "Run missing phases or document why they were skipped.",
        "Low Finding Count": "Review methodology coverage; consider additional attack vectors.",
        "Missing Section": "Fill in missing report sections or document why they are not applicable.",
        "Error Pattern": "Review error patterns; blocked paths may reveal security boundaries to test.",
        "Blocked Operation": "Review blocked operations; request DESTRUCTIVE-APPROVAL if testing warranted.",
        "Danger Check Block": "Review blocked operations; request DESTRUCTIVE-APPROVAL if testing warranted.",
        "Timeout": "Investigate timeout root cause; check if it indicates a denial-of-service vector.",
    }
    return steps.get(title, "Validate whether this signal represents a reproducible issue.")


# ============== PITCH GENERATION ==============

def _next_counter(counter_file: Path) -> int:
    counter_file.parent.mkdir(parents=True, exist_ok=True)
    value = 0
    if counter_file.is_file():
        try:
            value = int(counter_file.read_text(encoding="utf-8").strip() or "0")
        except ValueError:
            value = 0
    value += 1
    counter_file.write_text(f"{value}\n", encoding="utf-8")
    return value


def _pitch_path(body_root: Path, counter: int) -> Path:
    return body_root / "layer3-engagement" / "pitches" / f"{date.today().isoformat()}-hunt-{counter:03d}.md"


def _write_pitch(path: Path, leads: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    # Group by priority
    by_priority: dict[str, list[dict[str, str]]] = {}
    for lead in leads:
        p = lead.get("priority", "MEDIUM")
        by_priority.setdefault(p, []).append(lead)

    counter_str = path.stem.rsplit("-", 1)[-1]  # extract NNN from filename
    lines = [
        f"# Hunt Results #{counter_str}",
        "",
        f"> **Generated:** {_utc_now()}",
        "> **Source:** Lead hunting analysis",
        "> **Status:** PENDING REVIEW",
        "",
        "---",
        "",
        "## Overview",
        "",
        f"This document contains **{len(leads)} proposed leads** derived from "
        "analysis of project artifacts. These represent areas that may not have "
        "been fully analyzed or tested.",
        "",
        "**Action Required:** Review each lead and decide whether to add it to "
        "`layer3-engagement/NOTES/LEADS.md`.",
        "",
    ]

    # Summary by priority
    for p in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = len(by_priority.get(p, []))
        if count:
            lines.append(f"- {p}: {count}")
    lines.extend(["", "---", ""])

    for lead in leads:
        lines.extend([
            f"### [{lead['priority']}] {lead['title']}",
            f"- **Hypothesis:** {lead['hypothesis']}",
            f"- **Evidence:** {lead['evidence']}",
            f"- **Priority:** {lead['priority']}",
            f"- **Effort:** {lead['effort']}",
            f"- **Phase:** {lead.get('phase', 'unknown')}",
            f"- **Next Steps:** {lead['next_steps']}",
            "",
        ])

    lines.extend([
        "---",
        "",
        "## Review Instructions",
        "",
        "For each lead above:",
        "",
        "1. **ACCEPT** - Copy to `layer3-engagement/NOTES/LEADS.md` for investigation",
        "2. **DENY** - Lead not relevant or already covered",
        "3. **DEFER** - Revisit later",
        "",
        "### To Accept a Lead",
        "",
        "Copy the lead section to `layer3-engagement/NOTES/LEADS.md`:",
        "",
        "```bash",
        "# Example: Append lead to LEADS.md",
        "cat >> layer3-engagement/NOTES/LEADS.md << 'LEAD'",
        "### [OPEN] Lead Title Here",
        "- **Hypothesis:** ...",
        "- **Evidence:** ...",
        "...",
        "LEAD",
        "```",
        "",
        "Or use notes_guard.py:",
        "```bash",
        "python3 ./layer1/scripts/notes_guard.py append layer3-engagement/NOTES/LEADS.md",
        "```",
        "",
        "---",
        "",
        "## Approval",
        "",
        "| Reviewer | Date | Decision |",
        "|----------|------|----------|",
        "| | | PENDING |",
        "",
        "---",
        "",
        "*Generated by layer1/scripts/hunt.py — Lead Hunting & Gap Analysis Engine*",
    ])

    path.write_text("\n".join(lines), encoding="utf-8")


# ============== STATUS ==============

def _status(body_root: Path, state_file: Path) -> int:
    pitches_dir = body_root / "layer3-engagement" / "pitches"
    pitches = sorted(pitches_dir.glob("*-hunt-*.md")) if pitches_dir.is_dir() else []
    state = _load_state(state_file)

    print()
    print("=== Hunt Status ===")
    print()
    print(f"  Pending pitches:    {len(pitches)}")
    print(f"  Total proposed:     {state.get('total_leads_proposed', 0)}")
    print(f"  Last run:           {state.get('timestamp', 'never')}")
    if pitches:
        print(f"  Latest pitch:       {pitches[-1].name}")
    print()

    # Show recent pitches (last 7 days)
    import time
    seven_days_ago = time.time() - 7 * 86400
    recent = [p for p in pitches if p.stat().st_mtime > seven_days_ago] if pitches else []
    if recent:
        print("Recent Hunt Pitches (last 7 days):")
        for p in recent[-5:]:
            lead_count = sum(1 for line in _safe_text(p).splitlines() if line.startswith("### ["))
            print(f"  - {p} ({lead_count} leads)")
        print()

    # Show LEADS.md status
    leads_file = body_root / "layer3-engagement" / "NOTES" / "LEADS.md"
    if leads_file.is_file():
        existing_count = sum(1 for line in _safe_text(leads_file).splitlines() if line.startswith("### ["))
        print(f"Current layer3-engagement/NOTES/LEADS.md: {existing_count} leads")
    else:
        print("layer3-engagement/NOTES/LEADS.md: Not yet created")
    print()
    return 0


# ============== CLI ==============

HELP_TEXT = """\
hunt.py — Lead Hunting & Gap Analysis Engine

USAGE:
    hunt.py                              Run full hunt across all sources
    hunt.py --intel                      Hunt for leads in intel artifacts
    hunt.py --static                     Hunt for leads in static artifacts
    hunt.py --dynamic                    Hunt for leads in dynamic artifacts
    hunt.py --report                     Hunt for leads in report artifacts
    hunt.py --logs                       Hunt for leads in log files
    hunt.py --status                     Show pending lead proposals
    hunt.py --help                       Show this help

DESCRIPTION:
    Analyzes project artifacts to identify potential investigation leads
    that are either not being analyzed or not thoroughly tested.

    Unlike direct findings, leads are hypotheses requiring validation.
    This script proposes leads via pitch documents - the user must
    review and approve additions to layer3-engagement/NOTES/LEADS.md.

INVOCATION:
    Claude offers to run this script during the /agentic collaborative loop:
    - When LEADS.md has entries
    - At phase transitions
    - When findings suggest new attack surfaces

DATA SOURCES ANALYZED:
    --intel    .bra/artifacts/intel_work/    Untested targets, scope gaps
    --static   .bra/artifacts/static_work/   Unreviewed patterns, deps
    --dynamic  .bra/artifacts/dynamic_work/  Untested runtime paths
    --report   .bra/artifacts/report_work/   Coverage gaps
    --logs     .bra/logs/                    Error patterns, anomalies

OUTPUT:
    layer3-engagement/pitches/YYYY-MM-DD-hunt-NNN.md

    Pitch documents contain proposed leads in LEADS.md format.
    User must review and approve before adding to layer3-engagement/NOTES/LEADS.md.

LEAD FORMAT:
    Each proposed lead follows this format:

    ### [STATUS] Lead Title
    - **Hypothesis:** What we suspect
    - **Evidence:** Supporting observations
    - **Priority:** HIGH|MEDIUM|LOW
    - **Effort:** Quick check|Investigation|Deep dive
    - **Next Steps:** Specific actions to validate/rule out

EXIT CODES:
    0 - Success (leads found and pitched)
    1 - Error (write failure)
    2 - No new leads found

EXAMPLES:
    # Full hunt across all sources
    python3 hunt.py

    # Hunt after intel phase only
    python3 hunt.py --intel

    # Check pending pitches
    python3 hunt.py --status

REFERENCED BY:
    - .claude/commands/agentic.md (collaborative loop)

SEE ALSO:
    - self-improvement.py (improvement proposals)
    - growth.py (full engagement analysis)
"""


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="hunt.py — Lead Hunting & Gap Analysis Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_TEXT,
    )
    parser.add_argument("--intel", action="store_true", help="Hunt for leads in intel artifacts")
    parser.add_argument("--static", action="store_true", help="Hunt for leads in static artifacts")
    parser.add_argument("--dynamic", action="store_true", help="Hunt for leads in dynamic artifacts")
    parser.add_argument("--report", action="store_true", help="Hunt for leads in report artifacts")
    parser.add_argument("--logs", action="store_true", help="Hunt for leads in log files")
    parser.add_argument("--status", "-s", action="store_true", help="Show pending lead proposals")
    parser.add_argument("--auto", action="store_true", help="Suppress guidance text for automation callers.")
    parser.add_argument("--force", action="store_true", help="Hunt even if no changes detected.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    body_root = _body_root()
    artifacts_dir = body_root / ".bra" / "artifacts"
    log_dir = body_root / ".bra" / "logs"
    hunt_log = log_dir / "hunt.log"
    state_file = body_root / ".bra" / "hunt_state.json"
    counter_file = artifacts_dir / ".hunt_counter"

    if args.status:
        return _status(body_root, state_file)

    # Determine sources and phase filter
    phase_filter: str | None = None
    selected: list[Path] = []

    if args.intel:
        selected.append(artifacts_dir / "intel_work")
        phase_filter = "intel"
    if args.static:
        selected.append(artifacts_dir / "static_work")
        phase_filter = "static"
    if args.dynamic:
        selected.append(artifacts_dir / "dynamic_work")
        phase_filter = "dynamic"
    if args.report:
        selected.append(artifacts_dir / "report_work")
        phase_filter = "report"
    if args.logs:
        selected.append(log_dir)
        phase_filter = "logs"

    if not selected:
        selected = [
            artifacts_dir / "intel_work",
            artifacts_dir / "static_work",
            artifacts_dir / "dynamic_work",
            artifacts_dir / "report_work",
            log_dir,
        ]

    mode_label = phase_filter if phase_filter else "all"
    _append_log(hunt_log, f"Hunt started: mode={mode_label}")

    # Change detection
    state = _load_state(state_file)
    if not args.force:
        any_changed = False
        for source in selected:
            if source.is_dir():
                current_hash = _dir_hash(source)
                phase_name = source.name.replace("_work", "")
                if _has_changed(state, phase_name, current_hash):
                    any_changed = True
                    _update_hash(state, phase_name, current_hash)
                else:
                    print(f"[SKIP] {phase_name.capitalize()} artifacts unchanged since last hunt")
        if not any_changed:
            if not args.auto:
                print("No changes detected since last hunt. Use --force to hunt anyway.")
            return 0

    # Report which phases are being hunted
    for source in selected:
        phase_label = source.name.replace("_work", "")
        if source.is_dir():
            print(f"[HUNT] Hunting in {phase_label} artifacts...")
        else:
            print(f"[SKIP] No {phase_label} artifacts to hunt in")

    files = _iter_source_files(selected)
    leads = _derive_leads(files, body_root, phase_filter)

    # Report each lead found
    for lead in leads:
        print(f"[LEAD] {lead['title']}")

    if not leads:
        _append_log(hunt_log, "No new leads found")
        if not args.auto:
            print("[HUNT] No new leads found")
        _save_state(state_file, state)
        return 2

    counter = _next_counter(counter_file)
    pitch_path = _pitch_path(body_root, counter)
    _write_pitch(pitch_path, leads)

    total_prev = int(state.get("total_leads_proposed", 0))
    pending_prev = int(state.get("pending_pitches", 0))
    state.update({
        "total_leads_proposed": total_prev + len(leads),
        "pending_pitches": pending_prev + 1,
        "last_pitch": pitch_path.name,
        "timestamp": _utc_now(),
    })
    _save_state(state_file, state)

    _append_log(hunt_log, f"Generated {pitch_path.name} with {len(leads)} lead(s)")

    print(f"Generated pitch: {pitch_path}")
    print(f"Leads proposed: {len(leads)}")

    # Summary by priority
    by_priority: dict[str, int] = {}
    for lead in leads:
        p = lead.get("priority", "MEDIUM")
        by_priority[p] = by_priority.get(p, 0) + 1
    for p in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if by_priority.get(p):
            print(f"  {p}: {by_priority[p]}")

    if not args.auto:
        _notify_user(pitch_path, len(leads))
    return 0


def _notify_user(pitch_path: Path, lead_count: int) -> None:
    """Display boxed banner prompting the user to review the pitch."""
    width = 60
    bar = "═" * width
    inner = f"  HUNT COMPLETE ─ {lead_count} LEADS REQUIRE YOUR REVIEW  "
    padded = inner.ljust(width)
    print()
    print(f"╔{bar}╗")
    print(f"║{padded}║")
    print(f"╚{bar}╝")
    print()
    print("  Leads have been identified that may warrant investigation.")
    print("  Review the pitch and decide which leads to add to layer3-engagement/NOTES/LEADS.md.")
    print()
    print(f"  Pitch: {pitch_path}")
    print()
    print("  To review:")
    print(f"    cat {pitch_path}")
    print()
    print("  After review:")
    print("    - Copy accepted leads to layer3-engagement/NOTES/LEADS.md")
    print("    - Move pitch to layer3-engagement/pitches/accepted/ or layer3-engagement/pitches/rejected/")
    print()


if __name__ == "__main__":
    raise SystemExit(main())
