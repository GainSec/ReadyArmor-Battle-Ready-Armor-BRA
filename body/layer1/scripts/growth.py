#!/usr/bin/env python3
"""Native growth proposal generator (shell-less mode safe)."""

from __future__ import annotations

import argparse
import re
from datetime import UTC, datetime
from pathlib import Path
import subprocess
import sys


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


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


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _has_analyzable_data(lessons_file: Path, findings_file: Path) -> bool:
    return lessons_file.is_file() or findings_file.is_file()


def _recent_proposals(pitches_dir: Path, suffix: str) -> list[Path]:
    if not pitches_dir.exists():
        return []
    files = sorted(
        (p for p in pitches_dir.glob(f"*{suffix}") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return files[:5]


# ── Extraction functions ──────────────────────────────────────────────────

def _extract_attack_patterns(findings_file: Path) -> list[str]:
    """Extract finding titles from FINDINGS.md."""
    return [
        line.removeprefix("## ").strip()
        for line in _read_lines(findings_file)
        if line.startswith("## [FINDING-")
    ][:20]


def _extract_tool_gaps(lessons_file: Path, stats_file: Path) -> list[str]:
    """Extract tool gaps from lessons-learned and stats."""
    gaps: list[str] = []

    if lessons_file.is_file():
        text = lessons_file.read_text(encoding="utf-8", errors="replace")
        in_section = False
        for line in text.splitlines():
            if "Skill/Tool Gaps" in line:
                in_section = True
                continue
            if in_section and (line.startswith("##") or line.startswith("---")):
                break
            if in_section:
                stripped = line.strip()
                if (stripped.startswith("- ") or stripped.startswith("[ ]")) and \
                   not stripped.startswith("- Run ") and not stripped.startswith("- No ") and \
                   not stripped.startswith("- See "):
                    gaps.append(stripped)

    if stats_file.is_file():
        for line in _read_lines(stats_file):
            if re.search(r"missing|not found|unavailable", line, re.IGNORECASE):
                gaps.append(line.strip())
            if len(gaps) >= 10:
                break

    return gaps[:10]


def _extract_methodology_insights(lessons_file: Path) -> list[str]:
    """Extract methodologies used section from lessons-learned."""
    if not lessons_file.is_file():
        return []
    text = lessons_file.read_text(encoding="utf-8", errors="replace")
    in_section = False
    items: list[str] = []
    for line in text.splitlines():
        if "Methodologies Used" in line:
            in_section = True
            continue
        if in_section and (line.startswith("##") or line.startswith("---")):
            break
        if in_section and line.strip().startswith("- "):
            items.append(line.strip())
    return items[:10]


def _extract_coverage_gaps(lessons_file: Path, review_file: Path) -> list[str]:
    """Extract coverage gaps from lessons-learned and review."""
    gaps: list[str] = []

    if lessons_file.is_file():
        text = lessons_file.read_text(encoding="utf-8", errors="replace")
        in_section = False
        for line in text.splitlines():
            if "Coverage Gaps" in line:
                in_section = True
                continue
            if in_section and (line.startswith("##") or line.startswith("---")):
                break
            if in_section:
                stripped = line.strip()
                if stripped.startswith("- ") or stripped.startswith("[ ]"):
                    gaps.append(stripped)

    if review_file.is_file():
        for line in _read_lines(review_file):
            if "[ ]" in line:
                gaps.append(line.strip())
            if len(gaps) >= 10:
                break

    return gaps[:10]


def _extract_future_vectors(leads_file: Path) -> list[str]:
    """Extract open investigation leads."""
    if not leads_file.is_file():
        return []
    items: list[str] = []
    for line in _read_lines(leads_file):
        stripped = line.strip()
        if re.match(r"^###|^-.*\[OPEN\]|^-.*\[INVESTIGATING\]|^-.*\[TODO\]", stripped):
            if not re.search(r"RULED.OUT|CLOSED", stripped):
                items.append(stripped.lstrip("#").strip())
        if len(items) >= 15:
            break
    return items


def _extract_successful_techniques(lessons_file: Path) -> list[str]:
    """Extract successful techniques section from lessons-learned."""
    if not lessons_file.is_file():
        return []
    text = lessons_file.read_text(encoding="utf-8", errors="replace")
    in_section = False
    items: list[str] = []
    for line in text.splitlines():
        if "Successful Techniques" in line:
            in_section = True
            continue
        if in_section and (line.startswith("##") or line.startswith("---")):
            break
        if in_section and line.strip().startswith("- "):
            items.append(line.strip())
    return items[:15]


# ── Proposal section generators ──────────────────────────────────────────

def _generate_skill_proposals(findings_file: Path, lessons_file: Path) -> list[str]:
    techniques = _extract_successful_techniques(lessons_file)
    patterns = _extract_attack_patterns(findings_file)

    if not techniques and not patterns:
        return ["No new skill proposals derived from this engagement."]

    lines = [
        "> **Note:** Run `/brainblast` to analyze raw findings and derive meaningful, recognizable skill patterns.",
        "> Keyword-based proposals have been removed in favor of LLM-driven analysis.",
        "",
        "- [ ] Review raw findings with /brainblast to identify skills",
        "",
    ]

    if patterns:
        lines.append("**Raw Finding Titles (for reference):**")
        lines.append("")
        for p in patterns[:10]:
            lines.append(f"- {p}")

    return lines


def _generate_methodology_proposals(
    lessons_file: Path, review_file: Path, methodologies_dir: Path
) -> list[str]:
    methodologies = _extract_methodology_insights(lessons_file)
    gaps = _extract_coverage_gaps(lessons_file, review_file)

    lines = ["Based on methodologies used and coverage gaps:", ""]

    if methodologies:
        for item in methodologies:
            method_clean = item.lstrip("- ").strip()
            if not method_clean or method_clean.startswith("No specific") or len(method_clean) < 3:
                continue
            method_file = re.sub(r"[^a-z0-9-]", "", method_clean.lower().replace(" ", "-"))
            if not (methodologies_dir / f"{method_file}.md").is_file():
                lines.append(f"- [ ] **New Methodology**: {method_clean}")

    if gaps:
        filtered = [g for g in gaps if g.strip() and not g.startswith("No specific")][:5]
        if filtered:
            lines.extend(["", "Coverage gaps suggest methodology improvements:"])
            for gap in filtered:
                lines.append(f"- [ ] Address: {gap.lstrip('- ').strip()}")

    return lines


def _generate_attack_chain_proposals(findings_file: Path, lessons_file: Path) -> list[str]:
    patterns = _extract_attack_patterns(findings_file)
    techniques = _extract_successful_techniques(lessons_file)

    if not patterns and not techniques:
        return ["No new attack chain patterns identified."]

    lines = ["Successful attack patterns to document as reusable chains:", ""]

    if len(patterns) > 1:
        lines.append("- [ ] **Multi-Stage Chain**: Document the kill chain progression from this engagement")

    for tech in techniques[:5]:
        lines.append(f"- [ ] **Technique Pattern**: {tech.lstrip('- ').strip()}")

    return lines


def _generate_attack_surface_proposals(leads_file: Path, lessons_file: Path, review_file: Path) -> list[str]:
    leads = _extract_future_vectors(leads_file)
    gaps = _extract_coverage_gaps(lessons_file, review_file)

    lines = ["Attack surface areas to expand based on leads and gaps:", ""]

    if leads:
        lines.append("From open investigation leads:")
        for lead in leads[:5]:
            lines.append(f"- [ ] Explore: {lead}")
        lines.append("")

    if gaps:
        filtered = [g for g in gaps if g.strip()][:5]
        if filtered:
            lines.append("From coverage gaps:")
            for gap in filtered:
                lines.append(f"- [ ] Expand: {gap.lstrip('- ').strip()}")

    return lines


def _generate_tool_proposals(lessons_file: Path, stats_file: Path) -> list[str]:
    gaps = _extract_tool_gaps(lessons_file, stats_file)

    if not gaps:
        return ["No tool gaps identified in this engagement."]

    lines = ["Tools to add or configure based on gaps:", ""]
    for gap in gaps[:10]:
        lines.append(f"- [ ] {gap}")
    return lines


# ── Main document builder ────────────────────────────────────────────────

def _build_proposal_document(
    body_root: Path,
    lessons_file: Path,
    findings_file: Path,
    leads_file: Path,
    review_file: Path,
    disclosure_file: Path,
    stats_file: Path,
    methodologies_dir: Path,
) -> str:
    def status(path: Path) -> str:
        return "Analyzed" if path.is_file() else "Not found"

    # Raw findings/leads for LLM analysis
    raw_findings = findings_file.read_text(encoding="utf-8", errors="replace") if findings_file.is_file() else "*No findings file found*"
    raw_leads = leads_file.read_text(encoding="utf-8", errors="replace") if leads_file.is_file() else "*No leads file found*"

    skill_lines = _generate_skill_proposals(findings_file, lessons_file)
    methodology_lines = _generate_methodology_proposals(lessons_file, review_file, methodologies_dir)
    chain_lines = _generate_attack_chain_proposals(findings_file, lessons_file)
    surface_lines = _generate_attack_surface_proposals(leads_file, lessons_file, review_file)
    tool_lines = _generate_tool_proposals(lessons_file, stats_file)

    engagement = body_root.name
    return "\n".join([
        "# Growth Proposals",
        "",
        f"> **Generated:** {_utc_now()}",
        f"> **Engagement:** {engagement}",
        "> **Status:** NEEDS /brainblast REVIEW",
        "",
        "---",
        "",
        "## Overview",
        "",
        "This document contains proposed improvements derived from engagement artifacts.",
        "**Human review required** before any changes are applied to the framework.",
        "",
        "### Action Required",
        "",
        "Review each proposal and add to the appropriate location:",
        "",
        "| Type | Destination |",
        "|------|-------------|",
        "| New skill/technique | `layer2-templates/skillset.md` |",
        "| New tool | `layer2-templates/toolset.md` |",
        "| Methodology update | `layer2-templates/methodologies/` |",
        "| New workflow | `layer2-templates/workflows/` |",
        "",
        "Mark each proposal:",
        "- `[x]` ADDED - Copied to framework",
        "- `[-]` SKIP - Not adding",
        "- `[?]` DEFER - Revisit later",
        "",
        "---",
        "",
        "## Data Sources Analyzed",
        "",
        "| Source | Status |",
        "|--------|--------|",
        f"| LESSONS-LEARNED.md | {status(lessons_file)} |",
        f"| FINDINGS.md | {status(findings_file)} |",
        f"| LEADS.md | {status(leads_file)} |",
        f"| disclosure-package.md | {status(disclosure_file)} |",
        f"| REVIEW.md | {status(review_file)} |",
        "",
        "---",
        "",
        "## Raw Findings (for LLM analysis)",
        "",
        "<details>",
        "<summary>Click to expand raw findings</summary>",
        "",
        raw_findings,
        "",
        "</details>",
        "",
        "---",
        "",
        "## Raw Leads (for LLM analysis)",
        "",
        "<details>",
        "<summary>Click to expand raw leads</summary>",
        "",
        raw_leads,
        "",
        "</details>",
        "",
        "---",
        "",
        "## 1. Skill Additions",
        "",
        "> Target: `skillset.md`",
        "",
        *skill_lines,
        "",
        "---",
        "",
        "## 2. Methodology Improvements",
        "",
        "> Target: `layer2-templates/methodologies/`",
        "",
        *methodology_lines,
        "",
        "---",
        "",
        "## 3. Attack Chain Patterns",
        "",
        "> Target: `layer2-templates/attack-chains/` (new)",
        "",
        *chain_lines,
        "",
        "---",
        "",
        "## 4. Attack Surface Expansion",
        "",
        "> Target: Scope templates, intelligence checklists",
        "",
        *surface_lines,
        "",
        "---",
        "",
        "## 5. Tool Additions",
        "",
        "> Target: `toolset.md`",
        "",
        *tool_lines,
        "",
        "---",
        "",
        "## Review Checklist",
        "",
        "Before accepting proposals:",
        "",
        "- [ ] Verify proposals are actionable and specific",
        "- [ ] Check for duplicates in existing skillset/toolset",
        "- [ ] Ensure methodology proposals have clear scope",
        "- [ ] Validate attack chains are reproducible",
        "- [ ] Confirm tool additions are accessible/licensable",
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
        "**This document requires human review. No changes will be applied automatically.**",
        "",
    ])


def _show_help() -> None:
    print("""\
growth.py ── Engagement Growth & Self-Improvement Engine

NOTE: This script auto-runs after lessons-learned.py completes.
      It should NOT be called directly by users.

USAGE (internal):
    growth.py                           Generate growth proposals
    growth.py --status                  Check if proposals pending review
    growth.py --promote                 Promote approved PRJ-* items to Layer 1
    growth.py --help                    Show this help

DESCRIPTION:
    Analyzes engagement artifacts to derive actionable improvements:
    - New skills to add to skillset.md
    - New methodologies for templates/methodologies/
    - Attack chain patterns to document
    - Attack surface expansions
    - Tool gaps to address

    Outputs a pitch document requiring human review before any
    changes are applied to the framework.

    Use /brainblast to apply approved items from pitch documents
    to their Layer 2 counterparts (skillset.md, toolset.md, etc.).

DATA SOURCES ANALYZED:
    - layer3-engagement/LESSONS-LEARNED.md           Engagement narrative
    - layer3-engagement/NOTES/FINDINGS.md            Confirmed vulnerabilities
    - layer3-engagement/NOTES/LEADS.md               Investigation leads
    - layer3-engagement/disclosure/                  Disclosure documents
    - layer3-engagement/REVIEW.md                    Coverage gaps

OUTPUT:
    layer3-engagement/pitches/YYYY-MM-DD-growth-proposals.md

EXIT CODES:
    0 - Success
    1 - Error

REFERENCED BY:
    - layer1/scripts/lessons-learned.py (auto-invoke)""")


def _notify_user(output_file: Path) -> None:
    print()
    print("════════════════════════════════════════════════════════════════")
    print("  GROWTH PROPOSALS REQUIRE YOUR REVIEW")
    print("════════════════════════════════════════════════════════════════")
    print()
    print("  A growth proposal document has been generated based on this engagement.")
    print("  Please review and accept/deny the proposed improvements.")
    print()
    print(f"  Document: {output_file}")
    print()
    print("  To review:")
    print(f"    cat {output_file}")
    print()
    print("  After review:")
    print("    - Mark proposals as [x] ACCEPT, [-] DENY, or [?] DEFER")
    print("    - Move to layer3-engagement/pitches/accepted/ or layer3-engagement/pitches/rejected/")
    print()
    print("════════════════════════════════════════════════════════════════")
    print()


def _check_status(pending_marker: Path, pitches_dir: Path) -> int:
    print("\n=== Growth Proposal Status ===\n")
    if pending_marker.is_file():
        pending = pending_marker.read_text(encoding="utf-8", errors="replace").strip()
        print(f"PENDING REVIEW: {pending}")
        print("\nAction required: Review the proposal and accept/deny additions")
        pending_path = Path(pending)
        if pending_path.is_file():
            print(f"\nTo review: cat {pending}")
    else:
        print("No pending or recent growth proposals")

    recent_growth = _recent_proposals(pitches_dir, "-growth-proposals.md")
    if recent_growth:
        print("\nRecent proposals (last 7 days):")
        for path in recent_growth:
            print(f"  - {path}")

    recent_additions = _recent_proposals(pitches_dir, "-additions.md")
    if recent_additions:
        print("\nIntegration pitches (last 7 days):")
        for path in recent_additions:
            print(f"  - {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate growth proposals from engagement artifacts.",
        add_help=False,
    )
    parser.add_argument("--help", "-h", action="store_true", default=False, help="Show detailed help")
    parser.add_argument("--status", "-s", action="store_true", help="Show pending/recent growth proposals")
    parser.add_argument("--promote", "-p", action="store_true", help="Promote approved PRJ-* items to Layer 1")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if args.help:
        _show_help()
        return 0

    script_path = Path(__file__)
    body_root = _find_body_root(script_path)

    artifacts_dir = body_root / ".bra" / "artifacts"
    log_file = body_root / ".bra" / "logs" / "growth.log"
    pitches_dir = body_root / "layer3-engagement" / "pitches"
    pitches_dir.mkdir(parents=True, exist_ok=True)

    lessons_file = body_root / "layer3-engagement" / "LESSONS-LEARNED.md"
    notes_dir = body_root / "layer3-engagement" / "NOTES"
    findings_file = notes_dir / "FINDINGS.md"
    leads_file = notes_dir / "LEADS.md"
    review_file = body_root / "layer3-engagement" / "REVIEW.md"
    disclosure_file = body_root / "layer3-engagement" / "disclosure" / "disclosure-package.md"
    stats_file = body_root / "layer3-engagement" / "STATS.md"
    methodologies_dir = body_root / "layer2-templates" / "methodologies"

    pending_marker = artifacts_dir / ".growth_pending"
    output_file = pitches_dir / f"{_today()}-growth-proposals.md"

    _append_log(log_file, "INFO", "Growth script started")

    if args.status:
        return _check_status(pending_marker, pitches_dir)

    if args.promote:
        _append_log(log_file, "INFO", "Layer 3 to Layer 1 promotion started")
        print()
        print("════════════════════════════════════════════════════════════════")
        print("  LAYER 3 ─► LAYER 1 PROMOTION")
        print("════════════════════════════════════════════════════════════════")
        print()
        promotion_lib = body_root / "layer1" / "lib" / "promotion.py"
        if promotion_lib.is_file():
            try:
                result = subprocess.run(
                    [sys.executable, "-c", f"import sys; sys.path.insert(0, '{promotion_lib.parent}'); import promotion; promotion.promote_all('{body_root}')"],
                    cwd=str(body_root), capture_output=True, text=True, check=False,
                )
                if result.stdout:
                    print(result.stdout, end="")
                _append_log(log_file, "INFO", "Promotion complete")
                return result.returncode
            except OSError as exc:
                _append_log(log_file, "ERROR", f"Promotion failed: {exc}")
                print(f"Promotion failed: {exc}", file=sys.stderr)
                return 1
        else:
            print(f"Promotion library not found: {promotion_lib}", file=sys.stderr)
            _append_log(log_file, "ERROR", f"Promotion library not found: {promotion_lib}")
            return 1

    if not _has_analyzable_data(lessons_file, findings_file):
        _append_log(log_file, "INFO", "No analyzable data found; exiting silently")
        return 0

    print("[GROWTH] Analyzing engagement artifacts...")
    _append_log(log_file, "INFO", "Growth analysis started")

    print("[GROWTH] Generating growth proposals...")
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    proposal = _build_proposal_document(
        body_root, lessons_file, findings_file, leads_file, review_file,
        disclosure_file, stats_file, methodologies_dir,
    )
    output_file.write_text(proposal, encoding="utf-8")
    pending_marker.write_text(str(output_file), encoding="utf-8")

    _append_log(log_file, "INFO", f"Proposals generated: {output_file}")
    print(f"[GROWTH] Proposals generated: {output_file}")
    _notify_user(output_file)
    _append_log(log_file, "INFO", "Growth analysis complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
