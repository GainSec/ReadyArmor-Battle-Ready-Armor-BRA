#!/usr/bin/env python3
"""Native lead selection and test-plan generation."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import re
import sys


LEAD_HEADER_RE = re.compile(r"^###\s+\[([A-Z-]+)\]\s+(.+?)\s*$")


@dataclass(slots=True)
class Lead:
    index: int
    status: str
    title: str
    hypothesis: str = ""
    evidence: str = ""
    priority: str = ""
    effort: str = ""
    next_steps: str = ""


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _find_body_root(script_path: Path) -> Path:
    script_root = script_path.resolve().parents[2]
    for candidate in (Path.cwd().resolve(), script_root):
        if (candidate / ".bra").exists() or (candidate / "layer3-engagement").exists():
            return candidate
    return script_root


def _append_log(log_file: Path, level: str, message: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(f"[{_utc_now()}] [{level}] {message}\n")


def _parse_leads(leads_file: Path) -> list[Lead]:
    if not leads_file.is_file():
        return []

    lines = leads_file.read_text(encoding="utf-8", errors="replace").splitlines()
    parsed: list[Lead] = []
    current: dict[str, str] | None = None

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        parsed.append(
            Lead(
                index=len(parsed) + 1,
                status=current.get("status", "OPEN"),
                title=current.get("title", "Untitled lead"),
                hypothesis=current.get("hypothesis", ""),
                evidence=current.get("evidence", ""),
                priority=current.get("priority", ""),
                effort=current.get("effort", ""),
                next_steps=current.get("next_steps", ""),
            )
        )
        current = None

    for raw in lines:
        header = LEAD_HEADER_RE.match(raw)
        if header:
            flush()
            current = {"status": header.group(1), "title": header.group(2)}
            continue
        if current is None:
            continue

        line = raw.strip()
        for key, prefix in (
            ("hypothesis", "- **Hypothesis:**"),
            ("evidence", "- **Evidence:**"),
            ("priority", "- **Priority:**"),
            ("effort", "- **Effort:**"),
            ("next_steps", "- **Next Steps:**"),
        ):
            if line.startswith(prefix):
                current[key] = line[len(prefix) :].strip()

    flush()
    return parsed


def _parse_selection(selection: str, total: int, leads: list[Lead] | None = None) -> list[int]:
    value = selection.strip().lower()
    if value == "all":
        # Select only OPEN leads (matching shell behavior)
        if leads:
            return [i for i in range(total) if leads[i].status == "OPEN"]
        return list(range(total))

    picks: list[int] = []
    for token in (part.strip() for part in selection.split(",")):
        if not token:
            continue
        number = int(token)
        if number < 1 or number > total:
            raise ValueError(f"Selection index out of range: {number}")
        idx = number - 1
        if idx not in picks:
            picks.append(idx)

    if not picks:
        raise ValueError("No valid selections provided")
    return picks


def _keyword_test_steps(title: str, hypothesis: str) -> list[str]:
    """Generate keyword-based test steps from lead title/hypothesis."""
    combined = f"{title} {hypothesis}".lower()
    steps: list[str] = []

    if any(kw in combined for kw in ("secret", "credential", "password", "api key", "token", "hardcoded")):
        steps.extend([
            "grep -r for the secret pattern across source files",
            "Verify if value is a real credential vs placeholder/example",
            "Check if secret is rotatable and document exposure scope",
        ])
    elif any(kw in combined for kw in ("injection", "sqli", "xss", "command injection")):
        steps.extend([
            "Identify injection point and input vector",
            "Craft test payloads (save to NOTES/reqs/)",
            "Attempt reproduction and capture evidence",
        ])
    elif any(kw in combined for kw in ("dependency", "outdated", "cve", "vulnerable version")):
        steps.extend([
            "Run dependency scanner (npm audit / pip-audit / etc.)",
            "Cross-reference versions against NVD/advisory databases",
            "Document affected packages with version and CVE IDs",
        ])
    elif any(kw in combined for kw in ("config", "configuration", "misconfigur")):
        steps.extend([
            "Review configuration file for sensitive values and debug flags",
            "Compare against security baseline/best practices",
            "Document misconfigurations with remediation guidance",
        ])
    elif any(kw in combined for kw in ("binary", "firmware", "elf", "apk", "ipa")):
        steps.extend([
            "Run file/strings/binwalk on the binary",
            "Check for known vulnerability signatures and hardcoded data",
            "Document binary metadata and interesting strings",
        ])
    elif any(kw in combined for kw in ("network", "port", "service", "listen")):
        steps.extend([
            "Verify service is in scope per SCOPE.md",
            "Enumerate service version and check for known CVEs",
            "Test for authentication bypass and default credentials",
        ])
    elif any(kw in combined for kw in ("crash", "fault", "segfault", "panic")):
        steps.extend([
            "Reproduce the crash condition",
            "Analyze crash dump for exploitability",
            "Document crash trigger and potential impact",
        ])
    else:
        steps.extend([
            "Reproduce baseline behavior",
            "Capture artifact evidence",
            "Record result in FINDINGS.md or LEADS.md",
        ])

    return steps


def _render_plan(leads: list[Lead], selected: list[int], immediate: bool) -> str:
    mode = "IMMEDIATE" if immediate else "PITCH"
    rows = [
        "# Lead Test Plan",
        "",
        f"> Generated: {_utc_now()}",
        f"> Mode: {mode}",
        f"> Leads Selected: {len(selected)}",
    ]
    if not immediate:
        rows.append("> Status: PENDING APPROVAL")
    rows.append("")
    rows.append("---")
    rows.append("")
    rows.append("## Selected Leads")
    rows.append("")
    for idx in selected:
        rows.append(f"- {leads[idx].title}")
    rows.append("")
    rows.append("---")
    rows.append("")
    for order, idx in enumerate(selected, start=1):
        lead = leads[idx]
        rows.append(f"## Test Plan: {lead.title}")
        rows.append("")
        rows.append(f"**Status:** {lead.status} → INVESTIGATING")
        if lead.priority:
            rows.append(f"**Priority:** {lead.priority}")
        if lead.effort:
            rows.append(f"**Estimated Effort:** {lead.effort}")
        rows.append("")
        if lead.hypothesis:
            rows.append("### Hypothesis")
            rows.append("")
            rows.append(lead.hypothesis)
            rows.append("")
        if lead.evidence:
            rows.append("### Supporting Evidence")
            rows.append("")
            rows.append(lead.evidence)
            rows.append("")

        rows.append("### Test Steps")
        rows.append("")
        step_num = 1

        # Always start with status update
        rows.append(f"{step_num}. Update lead status to INVESTIGATING in NOTES/LEADS.md")
        step_num += 1

        # Parse next_steps (semicolon-separated) from the lead
        if lead.next_steps:
            for step in lead.next_steps.split(";"):
                step = step.strip()
                if step:
                    rows.append(f"{step_num}. {step}")
                    step_num += 1

        # Add keyword-based test steps
        kw_steps = _keyword_test_steps(lead.title, lead.hypothesis or "")
        for step in kw_steps:
            rows.append(f"{step_num}. {step}")
            step_num += 1

        # Always end with documentation
        rows.append(f"{step_num}. Document findings in NOTES/FINDINGS.md if confirmed")
        step_num += 1
        rows.append(f"{step_num}. Update lead status to CONFIRMED or RULED-OUT")
        rows.append("")

        rows.append("### Expected Outcomes")
        rows.append("")
        rows.append("- **If CONFIRMED:** Document as finding with evidence, impact, and remediation")
        rows.append("- **If RULED-OUT:** Document negative result with reasoning")
        rows.append("")
        rows.append("---")
        rows.append("")

    if not immediate:
        rows.extend([
            "## Approval",
            "",
            "Before executing this test plan:",
            "",
            "- [ ] Review test steps for safety",
            "- [ ] Verify scope coverage",
            "- [ ] Check for required approval tokens (DESTRUCTIVE-APPROVAL if needed)",
            "- [ ] Confirm test environment is ready",
            "",
            "| Reviewer | Date | Decision |",
            "|----------|------|----------|",
            "| | | PENDING |",
            "",
            "---",
            "",
            "## Execution Notes",
            "",
            "After approval, execute the test plan and document results.",
            "",
            "To update lead status after testing:",
            "",
            "```bash",
            "# Mark as investigating",
            "sed -i '' 's/\\[OPEN\\]/[INVESTIGATING]/' layer3-engagement/NOTES/LEADS.md",
            "",
            "# Mark as confirmed (after finding)",
            "sed -i '' 's/\\[INVESTIGATING\\]/[CONFIRMED]/' layer3-engagement/NOTES/LEADS.md",
            "",
            "# Mark as ruled out",
            "sed -i '' 's/\\[INVESTIGATING\\]/[RULED-OUT]/' layer3-engagement/NOTES/LEADS.md",
            "```",
            "",
            "---",
            "",
            "*Generated by leads.py - Lead Selection & Test Planning Interface*",
        ])

    return "\n".join(rows).rstrip() + "\n"


def _next_counter(counter_file: Path) -> int:
    counter_file.parent.mkdir(parents=True, exist_ok=True)
    current = 0
    if counter_file.is_file():
        try:
            current = int(counter_file.read_text(encoding="utf-8", errors="replace").strip() or "0")
        except ValueError:
            current = 0
    nxt = current + 1
    counter_file.write_text(str(nxt), encoding="utf-8")
    return nxt


def _priority_indicator(priority: str) -> str:
    return {"HIGH": "▲", "MEDIUM": "●", "LOW": "▼"}.get(priority, "")


def _print_leads(leads: list[Lead], open_only: bool) -> None:
    filtered = [lead for lead in leads if (lead.status == "OPEN" or not open_only)]

    print()
    print("=== Available Leads ===")
    print()

    if not filtered:
        print("No leads found in layer3-engagement/NOTES/LEADS.md")
        print()
        print("Generate leads with: ./layer1/scripts/hunt.py")
        return

    for lead in filtered:
        indicator = _priority_indicator(lead.priority)
        suffix = f" {indicator}" if indicator else ""
        print(f"  {lead.index:>2}. [{lead.status}] {lead.title}{suffix}")
        effort = lead.effort if lead.effort else "Unknown"
        print(f"      Effort: {effort}")

    print()
    print(f"Total: {len(filtered)} leads")
    print()


def _interactive_flow(
    leads: list[Lead],
    pitches_dir: Path,
    artifacts_dir: Path,
    log_file: Path,
    open_only: bool,
) -> int:
    if not leads:
        print()
        print("No leads file found. Generate leads with:")
        print("  ./layer1/scripts/hunt.py")
        return 2

    _print_leads(leads, open_only=open_only)
    if not sys.stdin.isatty():
        print("Interactive selection requires a TTY. Use --select or --list for non-interactive use.")
        return 0

    selection = input("Select leads to test (comma-separated or 'all'): ").strip()
    if not selection:
        print("[LEADS] No selection made", file=sys.stderr)
        return 1

    try:
        selected_indexes = _parse_selection(selection, len(leads), leads)
    except ValueError as exc:
        print(f"[LEADS] Invalid selection: {exc}", file=sys.stderr)
        return 1

    immediate = input("Run immediate mode? [y/N]: ").strip().lower().startswith("y")
    plan = _render_plan(leads, selected_indexes, immediate=immediate)
    if immediate:
        print()
        print("════════════════════════════════════════════════════════════════")
        print(f"  IMMEDIATE TEST PLAN - {len(selected_indexes)} LEAD(S) SELECTED")
        print("════════════════════════════════════════════════════════════════")
        print()
        print(plan, end="")
        print()
        print("════════════════════════════════════════════════════════════════")
        print("  READY FOR EXECUTION")
        print("════════════════════════════════════════════════════════════════")
        print()
        return 0

    pitches_dir.mkdir(parents=True, exist_ok=True)
    counter = _next_counter(artifacts_dir / ".leads_counter")
    pitch_path = pitches_dir / f"{_today()}-lead-plan-{counter:03d}.md"
    pitch_path.write_text(plan, encoding="utf-8")
    print()
    print("════════════════════════════════════════════════════════════════")
    print("  TEST PLAN GENERATED")
    print("════════════════════════════════════════════════════════════════")
    print()
    print("  Review the test plan before execution:")
    print()
    print(f"  Pitch: {pitch_path}")
    print()
    print("  To view:")
    print(f"    cat {pitch_path}")
    print()
    print("  After approval, execute the test steps and document results.")
    print()
    _append_log(log_file, "INFO", f"Generated lead pitch: {pitch_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    _epilog = """\
DESCRIPTION:
    Interactive interface for selecting leads from layer3-engagement/NOTES/LEADS.md and
    generating test plans. Supports two modes:

    1. PITCH MODE (default): Generates a test plan pitch document
       for review before taking action.

    2. IMMEDIATE MODE (--immediate): Outputs test plan directly for
       immediate execution without creating a pitch document.

WORKFLOW:
    1. Run leads.py to see numbered list of leads
    2. Use --select to choose leads (comma-separated, or 'all')
    3. Choose pitch mode or immediate mode (--immediate)
    4. Review/execute the generated test plan

EXAMPLES:
    # List all leads
    leads.py --list

    # List only open leads
    leads.py --open

    # Select specific leads and generate pitch
    leads.py --select 1,3,5

    # Select and execute immediately
    leads.py --select 2 --immediate

    # Check lead statistics
    leads.py --status

EXIT CODES:
    0 - Success
    1 - Error
    2 - No leads found

LEAD STATUSES:
    OPEN          - New lead, not yet investigated
    INVESTIGATING - Currently being validated
    CONFIRMED     - Validated, may become finding
    RULED-OUT     - Investigated, not exploitable
    DEFERRED      - Postponed for later

SEE ALSO:
    - hunt.py (lead generation)
    - notes_guard.py (layer3-engagement/NOTES/ management)
"""
    parser = argparse.ArgumentParser(
        description="leads.py - Lead Selection & Test Planning Interface",
        epilog=_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--list", "-l", action="store_true", help="List leads and exit")
    parser.add_argument("--open", "-o", action="store_true", dest="open_only", help="List only OPEN leads")
    parser.add_argument("--select", metavar="NUMBERS", help="Comma-separated lead indexes or 'all'")
    parser.add_argument("--immediate", "-i", action="store_true", help="Output plan to stdout instead of writing a pitch")
    parser.add_argument("--status", "-s", action="store_true", help="Show lead statistics")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    body_root = _find_body_root(Path(__file__))
    notes_dir = body_root / "layer3-engagement" / "NOTES"
    pitches_dir = body_root / "layer3-engagement" / "pitches"
    artifacts_dir = body_root / ".bra" / "artifacts"
    log_file = body_root / ".bra" / "logs" / "leads.log"
    leads_file = notes_dir / "LEADS.md"

    leads = _parse_leads(leads_file)
    _append_log(log_file, "INFO", f"Loaded {len(leads)} lead(s) from {leads_file}")

    if args.status:
        if not leads:
            print()
            print("No layer3-engagement/NOTES/LEADS.md found")
            print()
            print("Generate leads with: ./layer1/scripts/hunt.py")
            return 0
        print()
        print("=== Lead Statistics ===")
        print()
        print("By Status:")
        status_counts = Counter(lead.status for lead in leads)
        known_statuses = ("OPEN", "INVESTIGATING", "CONFIRMED", "RULED-OUT", "DEFERRED")
        status_labels = {
            "OPEN": "OPEN:         ",
            "INVESTIGATING": "INVESTIGATING:",
            "CONFIRMED": "CONFIRMED:    ",
            "RULED-OUT": "RULED-OUT:    ",
            "DEFERRED": "DEFERRED:     ",
        }
        for status in known_statuses:
            print(f"  {status_labels[status]} {status_counts.get(status, 0)}")
        other = sum(c for s, c in status_counts.items() if s not in known_statuses)
        if other:
            print(f"  OTHER:          {other}")
        print()
        print("By Priority:")
        priority_counts = Counter(lead.priority for lead in leads if lead.priority)
        for p in ("HIGH", "MEDIUM", "LOW"):
            print(f"  {p}:   {priority_counts.get(p, 0)}")
        print()
        print(f"Total: {len(leads)} leads")
        print()
        # Show recent test plans
        import time
        recent_plans = sorted(pitches_dir.glob("*-lead-plan-*.md")) if pitches_dir.is_dir() else []
        seven_days_ago = time.time() - 7 * 86400
        recent = [p for p in recent_plans if p.stat().st_mtime > seven_days_ago]
        if recent:
            print("Recent Test Plans (last 7 days):")
            for p in recent[-5:]:
                print(f"  - {p}")
            print()
        return 0

    if not leads:
        print()
        print("No leads file found. Generate leads with:")
        print("  ./layer1/scripts/hunt.py")
        return 2

    if args.select:
        try:
            selected_indexes = _parse_selection(args.select, len(leads), leads)
        except ValueError as exc:
            print(f"[LEADS] Invalid --select value: {exc}", file=sys.stderr)
            return 1

        plan = _render_plan(leads, selected_indexes, immediate=args.immediate)
        if args.immediate:
            print()
            print("════════════════════════════════════════════════════════════════")
            print(f"  IMMEDIATE TEST PLAN - {len(selected_indexes)} LEAD(S) SELECTED")
            print("════════════════════════════════════════════════════════════════")
            print()
            print(plan, end="")
            print()
            print("════════════════════════════════════════════════════════════════")
            print("  READY FOR EXECUTION")
            print("════════════════════════════════════════════════════════════════")
            print()
            print("  Execute the steps above to test the selected lead(s).")
            print()
            print("  Remember to:")
            print("    1. Update lead status in layer3-engagement/NOTES/LEADS.md")
            print("    2. Document findings in layer3-engagement/NOTES/FINDINGS.md")
            print("    3. Request DESTRUCTIVE-APPROVAL if needed")
            print()
            _append_log(log_file, "INFO", "Generated immediate lead test plan")
            return 0

        pitches_dir.mkdir(parents=True, exist_ok=True)
        counter = _next_counter(artifacts_dir / ".leads_counter")
        pitch_path = pitches_dir / f"{_today()}-lead-plan-{counter:03d}.md"
        pitch_path.write_text(plan, encoding="utf-8")
        print()
        print("════════════════════════════════════════════════════════════════")
        print("  TEST PLAN GENERATED")
        print("════════════════════════════════════════════════════════════════")
        print()
        print("  Review the test plan before execution:")
        print()
        print(f"  Pitch: {pitch_path}")
        print()
        print("  To view:")
        print(f"    cat {pitch_path}")
        print()
        print("  After approval, execute the test steps and document results.")
        print()
        _append_log(log_file, "INFO", f"Generated lead pitch: {pitch_path}")
        return 0

    return _interactive_flow(leads, pitches_dir, artifacts_dir, log_file, args.open_only)


if __name__ == "__main__":
    raise SystemExit(main())
