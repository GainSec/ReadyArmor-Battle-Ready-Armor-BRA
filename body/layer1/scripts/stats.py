#!/usr/bin/env python3
"""Native engagement statistics generator (shell-less mode safe)."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import re
import sys


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_body_root(script_path: Path) -> Path:
    candidates = [Path.cwd().resolve(), script_path.resolve().parents[2]]
    for candidate in candidates:
        if (candidate / ".bra").exists() or (candidate / "layer3-engagement").exists():
            return candidate
    return script_path.resolve().parents[2]


def _append_log(log_file: Path, level: str, message: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(f"[{_utc_now()}] [{level}] {message}\n")


def _read_state(state_file: Path) -> dict[str, object]:
    if not state_file.is_file():
        return {}
    try:
        return json.loads(state_file.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}


def _phase_metrics(artifacts_dir: Path, state_file: Path) -> list[str]:
    state = _read_state(state_file)

    if not state:
        return [
            "## Phase Completion Status",
            "",
            "No pipeline state found. Run /agentic first.",
        ]

    last_phase = str(state.get("last_phase", "unknown"))
    status = str(state.get("status", "unknown"))
    timestamp = str(state.get("timestamp", "unknown"))

    lines = [
        "## Phase Completion Status",
        "",
        "| Phase | Status | Artifacts |",
        "|-------|--------|-----------|",
    ]

    for phase in ("intel", "static", "dynamic", "report"):
        marker = artifacts_dir / f".{phase}_complete"
        phase_status = "Complete" if marker.exists() else "Not run"
        work_dir = artifacts_dir / f"{phase}_work"
        artifact_count = 0
        if work_dir.is_dir():
            artifact_count = sum(1 for path in work_dir.rglob("*") if path.is_file())
        lines.append(f"| {phase.upper()} | {phase_status} | {artifact_count} |")

    lines.extend(["", f"Last activity: {last_phase} ({status}) at {timestamp}"])
    return lines


def _extract_findings_severity(findings_file: Path) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    if not findings_file.is_file():
        return counts

    text = findings_file.read_text(encoding="utf-8", errors="replace")

    current_has_finding = False
    for line in text.splitlines():
        if line.startswith("## [FINDING-"):
            current_has_finding = True
            continue
        match = re.match(r"\|\s*\*\*Severity\*\*\s*\|\s*([^|]+?)\s*\|", line)
        if match and current_has_finding:
            sev = match.group(1).strip().upper()
            if sev in counts:
                counts[sev] += 1
            current_has_finding = False

    # Fallback for legacy heading severities.
    if sum(counts.values()) == 0:
        for sev in counts:
            counts[sev] = len(re.findall(rf"^###.*\[{sev}\]", text, flags=re.MULTILINE))

    return counts


def _finding_stats(notes_dir: Path) -> list[str]:
    findings_file = notes_dir / "FINDINGS.md"
    lines = ["## Finding Statistics", ""]
    if not findings_file.is_file():
        lines.append("No FINDINGS.md found in layer3-engagement/NOTES/")
        return lines

    counts = _extract_findings_severity(findings_file)
    total = sum(counts.values())
    line_count = len(findings_file.read_text(encoding="utf-8", errors="replace").splitlines())

    lines.extend(
        [
            "| Severity | Count |",
            "|----------|-------|",
            f"| CRITICAL | {counts['CRITICAL']} |",
            f"| HIGH     | {counts['HIGH']} |",
            f"| MEDIUM   | {counts['MEDIUM']} |",
            f"| LOW      | {counts['LOW']} |",
            f"| INFO     | {counts['INFO']} |",
            "|----------|-------|",
            f"| **Total**| **{total}** |",
            "",
            f"FINDINGS.md: {line_count} lines",
        ]
    )
    return lines


def _coverage_gaps(body_root: Path, artifacts_dir: Path, notes_dir: Path) -> list[str]:
    gaps: list[str] = []

    if not (artifacts_dir / ".intel_complete").exists():
        gaps.append("- [ ] **INTEL**: Phase not completed")
    else:
        if not (artifacts_dir / "intel_work" / "target_enumeration.md").is_file():
            gaps.append("- [ ] **INTEL**: Target enumeration missing")
        if not (artifacts_dir / "intel_work" / "scope_verification.md").is_file():
            gaps.append("- [ ] **INTEL**: Scope verification missing")

    if not (artifacts_dir / ".static_complete").exists():
        gaps.append("- [ ] **STATIC**: Phase not completed")
    if not (artifacts_dir / ".dynamic_complete").exists():
        gaps.append("- [ ] **DYNAMIC**: Phase not completed")

    if not (notes_dir / "FINDINGS.md").is_file():
        gaps.append("- [ ] **NOTES**: FINDINGS.md not created")
    if not (notes_dir / "SESSION.md").is_file():
        gaps.append("- [ ] **NOTES**: SESSION.md not created")

    # Check governance files
    if not (body_root / "layer1" / "rules" / "scope.md").is_file():
        gaps.append("- [ ] **GOVERNANCE**: scope.md not defined")
    if not (body_root / "layer1" / "rules" / "roe.md").is_file():
        gaps.append("- [ ] **GOVERNANCE**: roe.md not defined")

    lines = ["## Coverage Gaps", ""]
    if gaps:
        lines.extend(gaps)
        lines.extend(["", f"**{len(gaps)} gap(s) identified**"])
    else:
        lines.append("No critical coverage gaps identified.")
    return lines


def _recommendations(gaps_lines: list[str], artifacts_dir: Path) -> list[str]:
    lines = [
        "## Recommendations",
        "",
        "### Process Improvements",
        "",
    ]

    # Check tool availability gaps
    tool_avail = artifacts_dir / "intel_work" / "tool_availability.md"
    if tool_avail.is_file():
        try:
            text = tool_avail.read_text(encoding="utf-8", errors="replace")
            missing_count = text.count("[ ]")
            if missing_count > 0:
                lines.append(f"- Install {missing_count} missing tools from intel phase")
        except OSError:
            pass

    # Check for hardcoded secrets in static analysis
    code_quality = artifacts_dir / "static_work" / "code_quality.md"
    if code_quality.is_file():
        try:
            text = code_quality.read_text(encoding="utf-8", errors="replace")
            if "Hardcoded Secrets" in text:
                lines.append("- Address hardcoded secrets found during static analysis")
        except OSError:
            pass

    missing = [line for line in gaps_lines if line.startswith("- [ ]")]
    if missing:
        lines.extend(missing[:10])

    if len(lines) == 4:  # only header lines
        lines.append("- [ ] Keep current workflow and continue trend tracking")

    lines.extend(["", "### Template Suggestions", ""])
    lines.append("Based on engagement type, consider:")
    lines.append("")

    # Check for mobile/firmware targets
    target_enum = artifacts_dir / "intel_work" / "target_enumeration.md"
    if target_enum.is_file():
        try:
            text = target_enum.read_text(encoding="utf-8", errors="replace")
            if re.search(r"\.apk|\.ipa", text):
                lines.append("- layer2-templates/methodologies/mobile-assessment.md")
            if re.search(r"\.bin|\.img", text):
                lines.append("- layer2-templates/methodologies/firmware-extraction.md")
        except OSError:
            pass

    lines.extend(
        [
            "",
            "### Skill Development",
            "",
            "Areas for future focus:",
            "- Review gaps identified above",
            "- Expand coverage in incomplete phases",
        ]
    )
    return lines


def _write_report(output: Path, sections: list[list[str]]) -> None:
    lines = [
        "# Engagement Statistics",
        "",
        f"Generated: {_utc_now()}",
        "",
    ]
    for section in sections:
        lines.extend(section)
        lines.append("")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _print_block(title: str, lines: list[str]) -> None:
    print("")
    print("=" * 42)
    print(f"  {title}")
    print("=" * 42)
    print("")
    print("\n".join(lines))


def _show_help() -> None:
    print(
        "stats.py — Engagement Statistics and Metrics Tracker\n\n"
        "USAGE:\n"
        "    stats.py                            Generate stats skeleton\n"
        "    stats.py --metrics                  Show time allocation and finding counts\n"
        "    stats.py --gaps                     Identify coverage gaps\n"
        "    stats.py --recommendations          Aggregate suggestions\n"
        "    stats.py --full                     Generate comprehensive stats report\n"
        "    stats.py --help                     Show this help\n\n"
        "DESCRIPTION:\n"
        "    Generates statistics reports for engagement self-improvement.\n"
        "    Collects metrics from pipeline state, layer3-engagement/NOTES/, and artifacts.\n\n"
        "METRICS COLLECTED:\n"
        "    - Phase timing from agentic pipeline state\n"
        "    - Finding counts by severity from layer3-engagement/NOTES/FINDINGS.md\n"
        "    - Coverage gaps from static/dynamic phases\n"
        "    - Tool utilization statistics\n\n"
        "OUTPUT:\n"
        "    Default output: layer3-engagement/STATS.md\n"
        "    Logs written to: .bra/logs/stats.log\n\n"
        "EXIT CODES:\n"
        "    0 - Success\n"
        "    1 - Error (missing data, template not found)\n\n"
        "EXAMPLES:\n"
        "    # Quick metrics overview\n"
        "    ./stats.py --metrics\n\n"
        "    # Identify coverage gaps\n"
        "    ./stats.py --gaps\n\n"
        "    # Full statistics report\n"
        "    ./stats.py --full\n\n"
        "REFERENCED BY:\n"
        "    - CLAUDE.md Session Lifecycle (Phase 6: Stats)\n"
        "    - layer2-templates/stats.md"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate engagement statistics.", add_help=False)
    parser.add_argument("--metrics", "-m", action="store_true", help="Show phase/finding metrics")
    parser.add_argument("--gaps", "-g", action="store_true", help="Show coverage gaps")
    parser.add_argument("--recommendations", "-r", action="store_true", help="Show recommendations")
    parser.add_argument("--full", "-f", action="store_true", help="Generate full STATS.md report")
    parser.add_argument("--help", "-h", action="store_true", help="Show this help")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if args.help:
        _show_help()
        return 0

    script_path = Path(__file__)
    body_root = _find_body_root(script_path)

    artifacts_dir = body_root / ".bra" / "artifacts"
    notes_dir = body_root / "layer3-engagement" / "NOTES"
    stats_output = body_root / "layer3-engagement" / "STATS.md"
    state_file = body_root / ".bra" / "pipeline_state.json"
    log_file = body_root / ".bra" / "logs" / "stats.log"

    _append_log(log_file, "INFO", "Stats script started")

    metrics = _phase_metrics(artifacts_dir, state_file)
    finding = _finding_stats(notes_dir)
    gaps = _coverage_gaps(body_root, artifacts_dir, notes_dir)
    recs = _recommendations(gaps, artifacts_dir)

    if args.metrics:
        _print_block("ENGAGEMENT METRICS", metrics + [""] + finding)
        return 0

    if args.gaps:
        _print_block("COVERAGE GAP ANALYSIS", gaps)
        return 0

    if args.recommendations:
        _print_block("RECOMMENDATIONS", recs)
        return 0

    if args.full:
        executive = [
            "## Executive Summary",
            "",
            "This report captures lessons learned and metrics from the engagement.",
        ]
        lessons = [
            "## Lessons Learned",
            "",
            "### Technical",
            "",
            "- ",
            "",
            "### Process",
            "",
            "- ",
        ]
        next_steps = [
            "## Next Steps",
            "",
            "- [ ] ",
        ]
        _write_report(stats_output, [
            executive, ["---"], metrics, ["---"], finding,
            ["---"], gaps, ["---"], recs, ["---"], lessons, ["---"], next_steps,
        ])
        print("")
        print("=" * 42)
        print("  [STATS] STATISTICS REPORT COMPLETE")
        print("=" * 42)
        print(f"  Output: {stats_output}")
        _append_log(log_file, "INFO", f"Full report written: {stats_output}")
        return 0

    # Default: skeleton + append metrics sections.
    _write_report(stats_output, [
        [
            "## Overview",
            "",
            "| Field | Value |",
            "|-------|-------|",
            "| Engagement | [Name] |",
            "| Duration | [Start] to [End] |",
            "| Target | [Target description] |",
            "| Scope | [In-scope items] |",
            "",
            "## What Went Well",
            "",
            "-",
            "",
            "## What Could Improve",
            "",
            "-",
            "",
            "## Action Items",
            "",
            "- [ ]",
            "",
            "---",
        ],
        metrics,
        finding,
        gaps,
        recs,
    ])
    print("")
    print("=" * 42)
    print("  [STATS] STATISTICS REPORT COMPLETE")
    print("=" * 42)
    print(f"  Output: {stats_output}")
    _append_log(log_file, "INFO", f"Skeleton report written: {stats_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
