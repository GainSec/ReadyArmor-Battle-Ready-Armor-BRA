#!/usr/bin/env python3
"""Native lessons-learned document generator (shell-less mode safe)."""

from __future__ import annotations

import argparse
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


def _read_text_or(path: Path, fallback: str) -> str:
    if not path.is_file():
        return fallback
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    return text if text else fallback


def _extract_bullet_lines(path: Path, limit: int = 8) -> list[str]:
    if not path.is_file():
        return []
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("- "):
            lines.append(line)
        if len(lines) >= limit:
            break
    return lines


def _extract_findings_table(findings_file: Path) -> tuple[list[str], dict[str, int]]:
    """Extract findings table and severity counts."""
    severity_counts: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }
    if not findings_file.is_file():
        return (["| Finding | Severity |", "|---------|----------|", "| None | N/A |"],
                severity_counts)

    rows = ["| Finding | Severity | CVSS |", "|---------|----------|------|"]
    current_title = ""
    current_cvss = ""
    import re as _re

    text = findings_file.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## [FINDING-"):
            current_title = stripped.removeprefix("## ").strip()
            current_cvss = ""
            continue
        if "**Severity**" in stripped and current_title:
            parts = stripped.split("|")
            sev = parts[2].strip() if len(parts) > 2 else "UNKNOWN"
            # Normalize severity
            sev_upper = sev.upper().split("(")[0].strip().split("/")[0].strip()
            for level in severity_counts:
                if level in sev_upper:
                    severity_counts[level] += 1
                    break
            rows.append(f"| {current_title} | {sev} | {current_cvss} |")
            current_title = ""
        if "CVSS" in stripped and current_title:
            cvss_match = _re.search(r"(\d+\.?\d*)", stripped)
            if cvss_match:
                current_cvss = cvss_match.group(1)

    if len(rows) == 2:
        # Try simpler heading-based count
        finding_count = text.count("## [FINDING-")
        if finding_count:
            rows.append(f"| {finding_count} finding(s) present | severity metadata unavailable | — |")
        else:
            rows.append("| None documented | N/A | — |")

    return rows, severity_counts


def _detect_methodologies(body_root: Path) -> list[str]:
    """Detect methodologies used from artifact patterns."""
    artifacts_dir = body_root / ".bra" / "artifacts"
    methodologies: list[str] = []

    if not artifacts_dir.is_dir():
        return ["Manual review"]

    # Collect all text content from artifacts for pattern matching
    all_text = ""
    for f in artifacts_dir.rglob("*"):
        if f.is_file() and f.suffix in (".md", ".txt", ".log"):
            try:
                all_text += f.read_text(encoding="utf-8", errors="ignore").lower() + "\n"
            except OSError:
                pass

    patterns = [
        (r"(?:android|apk|adb|dalvik|smali|jadx)", "Mobile Security Assessment"),
        (r"(?:ios|ipa|objection|frida.*ios|swift)", "iOS Security Assessment"),
        (r"(?:firmware|binwalk|squashfs|rootfs|uboot|flash)", "Firmware Analysis"),
        (r"(?:iot|mqtt|coap|zigbee|bluetooth|ble|homekit)", "IoT/Embedded Security"),
        (r"(?:nmap|burp|zap|nikto|dirb|gobuster|wfuzz|sqlmap)", "Web Application Testing"),
        (r"(?:command.?injection|rce|remote.?code)", "Command Injection Analysis"),
        (r"(?:path.?traversal|directory.?traversal|lfi|rfi)", "Path Traversal Analysis"),
        (r"(?:credential|password|brute|hydra|spray)", "Credential Analysis"),
        (r"(?:fuzz|afl|honggfuzz|radamsa|boofuzz)", "Fuzzing Campaign"),
        (r"(?:reverse.?engineer|ida|ghidra|r2|radare|disassembl)", "Reverse Engineering"),
        (r"(?:selinux|sepolicy|mac.?policy)", "SELinux Policy Analysis"),
        (r"(?:thick.?client|dotnet|dnspy|ilspy|assembly)", "Thick Client Assessment"),
    ]

    import re as _re
    for pattern, name in patterns:
        if _re.search(pattern, all_text):
            methodologies.append(name)

    return methodologies or ["Manual review", "Artifact-driven synthesis"]


def _extract_tokens_table(body_root: Path) -> list[str]:
    """Build tokens-in-effect table from all 3 sources."""
    import os as _os
    import re as _re

    approvals_dir = body_root / ".bra" / "approvals"
    roe_file = body_root / "layer3-engagement" / "ROE.md"
    roe_text = ""
    if roe_file.is_file():
        roe_text = roe_file.read_text(encoding="utf-8", errors="ignore")

    tokens = [
        "ACTIVE-TESTING-APPROVAL", "DESTRUCTIVE-APPROVAL", "PUSH-APPROVAL",
        "SCOPE-CONFIRMED", "WATCH", "TRACK", "NEGATIVE-RESULTS",
    ]

    rows = ["| Token | Status | Source |", "|-------|--------|--------|"]
    for token in tokens:
        sources: list[str] = []
        env_var = token.replace("-", "_")
        if _os.environ.get(env_var) == "1":
            sources.append("env")
        if approvals_dir.is_dir() and (approvals_dir / token).is_file():
            sources.append("file")
        if roe_text and _re.search(rf"{_re.escape(token)}:\s*(?:GRANTED|ENABLED)", roe_text):
            sources.append("ROE")

        if sources:
            rows.append(f"| {token} | **ACTIVE** | {', '.join(sources)} |")
        else:
            rows.append(f"| {token} | not set | — |")

    return rows


def _extract_timeline(body_root: Path) -> list[str]:
    """Extract engagement timeline from PLAN.md and pipeline state."""
    lines: list[str] = []
    plan_file = body_root / "layer3-engagement" / "PLAN.md"
    state_file = body_root / ".bra" / "pipeline_state.json"

    if plan_file.is_file():
        text = plan_file.read_text(encoding="utf-8", errors="replace")
        import re as _re
        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if _re.match(r"^-\s+\d{4}-\d{2}", stripped) or _re.match(r"^-\s+Phase", stripped, _re.IGNORECASE):
                lines.append(stripped)

    if state_file.is_file():
        import json as _json
        try:
            state = _json.loads(state_file.read_text(encoding="utf-8"))
            ts = state.get("timestamp", "")
            phase = state.get("last_phase", "unknown")
            if ts:
                lines.append(f"- Pipeline last: {phase} ({ts})")
        except Exception:
            pass

    if not lines:
        lines = [f"- Generated on {_today()}"]

    return lines


def _extract_ruled_out(leads_file: Path) -> list[str]:
    """Extract RULED-OUT items from LEADS.md."""
    if not leads_file.is_file():
        return ["- No explicit ruled-out list recorded"]

    items: list[str] = []
    text = leads_file.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if "RULED" in stripped.upper() or "CLOSED" in stripped.upper() or "FALSE" in stripped.upper():
            items.append(f"- {stripped[:200]}")

    return items or ["- No explicit ruled-out items found in LEADS.md"]


def _has_minimum_data(findings_file: Path, leads_file: Path, review_file: Path, session_file: Path) -> bool:
    return any(path.is_file() for path in (findings_file, leads_file, review_file, session_file))


def _check_data_availability(files: list[tuple[str, Path]]) -> int:
    file_map = {label: path for label, path in files}
    data_score = 0
    max_score = 10

    print("\n=== Data Availability Check ===\n")

    print("Core Documents:")
    for label in ("scope.md", "roe.md"):
        if file_map[label].is_file():
            print(f"  [x] {label}")
            data_score += 1
        else:
            print(f"  [ ] {label}")

    plan_file = file_map.get("PLAN.md")
    if plan_file and plan_file.is_file():
        print("  [x] layer3-engagement/PLAN.md")
        data_score += 1
    else:
        print("  [ ] layer3-engagement/PLAN.md")

    print("\nNOTES Directory:")
    findings_file = file_map["FINDINGS.md"]
    if findings_file.is_file():
        finding_count = findings_file.read_text(encoding="utf-8", errors="replace").count("## [FINDING-")
        print(f"  [x] FINDINGS.md ({finding_count} findings)")
        data_score += 1
    else:
        print("  [ ] FINDINGS.md")

    for label in ("LEADS.md", "SESSION.md"):
        if file_map[label].is_file():
            print(f"  [x] {label}")
            data_score += 1
        else:
            print(f"  [ ] {label}")

    if file_map["REVIEW.md"].is_file():
        print("  [x] REVIEW.md")
        data_score += 1
    else:
        print("  [ ] REVIEW.md")

    print("\nRuntime State:")
    for label in ("manifest.json", "pipeline_state.json"):
        if file_map[label].is_file():
            print(f"  [x] {label}")
            data_score += 1
        else:
            print(f"  [ ] {label}")

    approvals_dir = file_map["pipeline_state.json"].parents[1] / "approvals"
    if approvals_dir.is_dir():
        token_count = sum(1 for item in approvals_dir.iterdir() if item.is_file())
        print(f"  [x] .bra/approvals/ ({token_count} token files)")
        data_score += 1
    else:
        print("  [ ] .bra/approvals/")

    print(f"\nData score: {data_score}/{max_score}")
    return 0


def _extract_successful_techniques(findings_file: Path) -> list[str]:
    """Extract finding headings as successful techniques."""
    if not findings_file.is_file():
        return ["- No confirmed findings documented"]

    import re as _re
    text = findings_file.read_text(encoding="utf-8", errors="replace")
    headings = _re.findall(r"^## (\[FINDING-\d+\].*)$", text, _re.MULTILINE)

    if not headings:
        return ["- No confirmed findings documented"]

    lines = ["Confirmed findings that demonstrate successful techniques:", ""]
    for heading in headings[:10]:
        lines.append(f"- {heading}")
    if len(headings) > 10:
        lines.append(f"- ... and {len(headings) - 10} more")
    return lines


def _extract_open_leads(leads_file: Path) -> list[str]:
    """Extract open/investigating leads (excluding ruled-out)."""
    if not leads_file.is_file():
        return ["- No leads documentation found"]

    import re as _re
    lines: list[str] = []
    for raw in leads_file.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw.strip()
        if _re.match(r"^###|^-.*\[OPEN\]|^-.*\[INVESTIGATING\]|^-.*\[TODO\]", stripped):
            if not _re.search(r"RULED.OUT|CLOSED|FALSE.POSITIVE", stripped):
                lines.append(f"- {stripped.lstrip('#').strip()}")
        if len(lines) >= 10:
            break

    if lines:
        return ["Open investigations for future work:", ""] + lines
    return ["- No open leads documented"]


def _summarize_evidence_manifest(manifest_file: Path, artifacts_dir: Path) -> list[str]:
    """Summarize evidence manifest with artifact counts."""
    if not manifest_file.is_file():
        return ["- No evidence manifest found"]

    import json as _json
    rows = ["| Field | Value |", "|-------|-------|"]
    try:
        data = _json.loads(manifest_file.read_text(encoding="utf-8"))
        count = data.get("artifact_count", 0)
        created = data.get("created", "Unknown")
        rows.append(f"| Artifact Count | {count} |")
        rows.append(f"| Manifest Created | {created} |")
    except (OSError, _json.JSONDecodeError):
        rows.append("| Artifact Count | unknown |")
        rows.append("| Manifest Created | unknown |")

    rows.append("| Location | .bra/artifacts/manifest.json |")

    if artifacts_dir.is_dir():
        work_dirs = sum(1 for d in artifacts_dir.iterdir() if d.is_dir() and d.name.endswith("_work"))
        rows.append(f"| Work Directories | {work_dirs} |")

    return rows


def _generate_recommendations(
    body_root: Path, leads_file: Path, review_file: Path
) -> list[str]:
    """Generate data-driven recommendations."""
    import re as _re
    artifacts_dir = body_root / ".bra" / "artifacts"
    lines = ["### Future Priorities", ""]

    # Open lead count
    if leads_file.is_file():
        text = leads_file.read_text(encoding="utf-8", errors="replace")
        open_count = len(_re.findall(r"\[OPEN\]|\[INVESTIGATING\]|\[TODO\]", text))
        if open_count > 0:
            lines.append(f"- Investigate {open_count} open leads from this engagement")

    # Coverage gap count
    if review_file.is_file():
        text = review_file.read_text(encoding="utf-8", errors="replace")
        gap_count = text.count("[ ]")
        if gap_count > 0:
            lines.append(f"- Address {gap_count} coverage gaps from review phase")

    # Incomplete phases
    for phase, label in (("intel", "intelligence"), ("static", "static analysis"), ("dynamic", "dynamic analysis")):
        if not (artifacts_dir / f".{phase}_complete").is_file():
            lines.append(f"- Complete {label} phase")

    lines.extend(["", "### Skill/Tool Gaps", ""])

    tool_avail = artifacts_dir / "intel_work" / "tool_availability.md"
    if tool_avail.is_file():
        text = tool_avail.read_text(encoding="utf-8", errors="replace")
        missing = [l.strip() for l in text.splitlines() if l.strip().startswith("[ ]")][:5]
        if missing:
            lines.append("Missing tools identified during intel:")
            lines.append("")
            lines.extend(missing)
        else:
            lines.append("- No missing tools identified")
    else:
        lines.append("- Run intel phase to identify tool gaps")

    return lines


def _generate_document(
    body_root: Path,
    output_file: Path,
    complete_marker: Path,
    scope_file: Path,
    roe_file: Path,
    tokens_file: Path,
    findings_file: Path,
    leads_file: Path,
    review_file: Path,
    session_file: Path,
    state_file: Path,
    manifest_file: Path,
    log_file: Path,
) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)

    scope_summary = _read_text_or(scope_file, "Scope not defined")
    roe_summary = _read_text_or(roe_file, "ROE not defined")

    # Use structured tokens table instead of raw file dump
    tokens_table = _extract_tokens_table(body_root)

    # Use extracted timeline instead of hardcoded date
    timeline_lines = _extract_timeline(body_root)

    # Detect methodologies from artifacts
    methodology_list = _detect_methodologies(body_root)

    # Extract successful techniques from FINDINGS.md headings
    success_lines = _extract_successful_techniques(findings_file)

    # Extract ruled-out items from LEADS.md
    ruled_out_lines = _extract_ruled_out(leads_file)

    # Extract coverage gaps from REVIEW.md
    review_gaps = _extract_bullet_lines(review_file, limit=8)
    if not review_gaps:
        review_gaps = ["- No explicit coverage gaps recorded"]

    # Severity summary table (shell-style)
    findings_table_rows, severity_counts = _extract_findings_table(findings_file)
    total_findings = sum(severity_counts.values())
    severity_table = [
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        severity_table.append(f"| {sev} | {severity_counts[sev]} |")
    severity_table.append("|----------|-------|")
    severity_table.append(f"| **Total**| **{total_findings}** |")

    # Open leads extraction
    open_lead_lines = _extract_open_leads(leads_file)

    # Evidence manifest summary
    artifacts_dir = body_root / ".bra" / "artifacts"
    manifest_lines = _summarize_evidence_manifest(manifest_file, artifacts_dir)

    # Data-driven recommendations
    recommendation_lines = _generate_recommendations(body_root, leads_file, review_file)

    sources = [
        ("Scope", scope_file),
        ("ROE", roe_file),
        ("Tokens", tokens_file),
        ("Findings", findings_file),
        ("Leads", leads_file),
        ("Review", review_file),
        ("Session", session_file),
        ("Manifest", manifest_file),
        ("Pipeline State", state_file),
    ]

    lines = [
        "# Lessons Learned",
        "",
        f"> Generated: {_utc_now()}",
        "> Document: Comprehensive Engagement Narrative",
        "",
        "---",
        "",
        "## 1. Engagement Context",
        "",
        "### Scope Summary",
        "",
        scope_summary,
        "",
        "### Rules of Engagement",
        "",
        roe_summary,
        "",
        "### Tokens in Effect",
        "",
        *tokens_table,
        "",
        "### Timeline",
        "",
        *timeline_lines,
        "",
        "---",
        "",
        "## 2. Attack Chains & Paths",
        "",
        "### Methodologies Used",
        "",
    ]
    for meth in methodology_list:
        lines.append(f"- {meth}")

    lines.extend([
        "",
        "### Kill Chain Progression",
        "",
        "Based on pipeline phase completion:",
        "",
        "| Phase | Status | Notes |",
        "|-------|--------|-------|",
    ])

    phase_notes = {
        "intel": "Target enumeration performed",
        "static": "Code/config review performed",
        "dynamic": "Runtime analysis performed",
        "report": "Findings documented",
    }
    phases = (
        ("intel", "Intelligence"),
        ("static", "Static Analysis"),
        ("dynamic", "Dynamic Analysis"),
        ("report", "Reporting"),
    )
    for key, label in phases:
        marker = artifacts_dir / f".{key}_complete"
        if marker.is_file():
            lines.append(f"| {label} | Complete | {phase_notes[key]} |")
        else:
            lines.append(f"| {label} | Not Complete | - |")

    lines.extend([
        "",
        "---",
        "",
        "## 3. What Worked vs What Didn't",
        "",
        "### Successful Techniques",
        "",
        *success_lines,
        "",
        "### Failed Attempts / Ruled Out",
        "",
        *ruled_out_lines,
        "",
        "### Coverage Gaps Identified",
        "",
        *review_gaps,
        "",
        "---",
        "",
        "## 4. Current State",
        "",
        "### Findings Summary",
        "",
        *severity_table,
        "",
        "### Open Leads",
        "",
        *open_lead_lines,
        "",
        "### Evidence Manifest",
        "",
        *manifest_lines,
        "",
        "---",
        "",
        "## 5. Recommendations",
        "",
        *recommendation_lines,
        "",
        "---",
        "",
        "## Appendix: Data Sources",
        "",
        "This document was synthesized from the following sources:",
        "",
        "| Source | Path | Status |",
        "|--------|------|--------|",
    ])

    for label, path in sources:
        rel = path.relative_to(body_root) if path.is_absolute() and str(path).startswith(str(body_root)) else path
        lines.append(f"| {label} | {rel} | {'Found' if path.is_file() else 'Not Found'} |")

    lines.extend(["", "---", "", "**Generated by lessons-learned.py**", ""])

    output_file.write_text("\n".join(lines), encoding="utf-8")
    complete_marker.parent.mkdir(parents=True, exist_ok=True)
    complete_marker.touch()

    _append_log(log_file, "INFO", f"Lessons document written: {output_file}")


def _run_post_lessons_automation(script_path: Path, body_root: Path, log_file: Path) -> None:
    scripts_dir = script_path.parent

    # Auto-invoke growth.py for self-improvement proposals
    growth_script = scripts_dir / "growth.py"
    if growth_script.is_file():
        try:
            result = subprocess.run(
                [sys.executable, str(growth_script)],
                cwd=str(body_root),
                capture_output=True,
                text=True,
                check=False,
            )
            _append_log(log_file, "INFO", f"growth.py exited with code {result.returncode}")
        except OSError as exc:
            _append_log(log_file, "WARN", f"Unable to run growth.py: {exc}")
    else:
        _append_log(log_file, "INFO", "growth.py not present; skipping post-lessons growth")

    # Build override recommendation pitches from engagement decisions
    si_script = scripts_dir / "self-improvement.py"
    if si_script.is_file():
        for si_args in (["--auto", "--overrides"], ["--auto", "--promote-overrides"]):
            try:
                result = subprocess.run(
                    [sys.executable, str(si_script)] + si_args,
                    cwd=str(body_root),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                _append_log(log_file, "INFO", f"self-improvement.py {' '.join(si_args)} exited with code {result.returncode}")
            except OSError as exc:
                _append_log(log_file, "WARN", f"Unable to run self-improvement.py {' '.join(si_args)}: {exc}")


_HELP_TEXT = """\
lessons-learned.py — Engagement Narrative Generator

USAGE:
    lessons-learned.py                  Generate full document
    lessons-learned.py --auto           Auto-mode (silent on no data)
    lessons-learned.py --status         Show data availability
    lessons-learned.py --help           Show this help

DESCRIPTION:
    Generates a comprehensive engagement narrative in layer3-engagement/LESSONS-LEARNED.md.
    Synthesizes data from multiple sources to create a complete post-engagement record.

POST-LESSONS AUTOMATION:
    - Runs growth.py to generate framework improvement pitches
    - Runs self-improvement.py --overrides to generate override recommendation pitches
    - Runs self-improvement.py --promote-overrides to promote approved override recommendations
      to layer2-templates/overrides.md
      and delete denied override proposals

OUTPUT DOCUMENT STRUCTURE:
    layer3-engagement/LESSONS-LEARNED.md
    +-- 1. Engagement Context (scope, ROE, tokens, timeline)
    +-- 2. Attack Chains & Paths (methodologies, kill chain)
    +-- 3. What Worked vs What Didn't (successes, failures, gaps)
    +-- 4. Current State (findings table, open leads, evidence)
    +-- 5. Recommendations (future priorities, skill/tool gaps)

DATA SOURCES:
    - scope.md              In-scope targets, constraints
    - roe.md                Authorization, safety rules
    - tokens.md             Token policies in effect
    - .bra/approvals/     Active approval tokens
    - layer3-engagement/PLAN.md    Timeline, engagement name
    - layer3-engagement/NOTES/FINDINGS.md  Confirmed findings, severity
    - layer3-engagement/NOTES/LEADS.md     Open/ruled-out investigations
    - layer3-engagement/REVIEW.md  Coverage gaps
    - .bra/artifacts/     Evidence manifest
    - .bra/pipeline_state.json Phase metrics

EXIT CODES:
    0 - Success
    1 - Error (template error, write failure)
    2 - No data (insufficient data to generate)

EXAMPLES:
    # Generate full lessons learned document
    python3 lessons-learned.py

    # Check data availability
    python3 lessons-learned.py --status

    # Auto-mode (for CI integration, silent on no data)
    python3 lessons-learned.py --auto

REFERENCED BY:
    - CLAUDE.md Session Lifecycle (Phase 8: Lessons)
    - agentic.md (wrap-up sequence)
    - layer1/scripts/disclose.py (auto-invoke after generate_all)
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate lessons learned narrative.",
        epilog=_HELP_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--auto", "-a", action="store_true", help="Silent mode on no data (returns 2)")
    parser.add_argument("--status", "-s", action="store_true", help="Show source data availability")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    script_path = Path(__file__)
    body_root = _find_body_root(script_path)

    artifacts_dir = body_root / ".bra" / "artifacts"
    output_file = body_root / "layer3-engagement" / "LESSONS-LEARNED.md"
    complete_marker = artifacts_dir / ".lessons_complete"
    log_file = body_root / ".bra" / "logs" / "lessons_learned.log"

    scope_file = body_root / "layer1" / "rules" / "scope.md"
    roe_file = body_root / "layer1" / "rules" / "roe.md"
    tokens_file = body_root / "layer1" / "rules" / "tokens.md"
    findings_file = body_root / "layer3-engagement" / "NOTES" / "FINDINGS.md"
    leads_file = body_root / "layer3-engagement" / "NOTES" / "LEADS.md"
    review_file = body_root / "layer3-engagement" / "REVIEW.md"
    plan_file = body_root / "layer3-engagement" / "PLAN.md"
    session_file = body_root / "layer3-engagement" / "NOTES" / "SESSION.md"
    state_file = body_root / ".bra" / "pipeline_state.json"
    manifest_file = artifacts_dir / "manifest.json"

    files = [
        ("scope.md", scope_file),
        ("roe.md", roe_file),
        ("tokens.md", tokens_file),
        ("PLAN.md", plan_file),
        ("FINDINGS.md", findings_file),
        ("LEADS.md", leads_file),
        ("REVIEW.md", review_file),
        ("SESSION.md", session_file),
        ("manifest.json", manifest_file),
        ("pipeline_state.json", state_file),
    ]

    _append_log(log_file, "INFO", "Lessons script started")

    if args.status:
        return _check_data_availability(files)

    if not _has_minimum_data(findings_file, leads_file, review_file, session_file):
        _append_log(log_file, "INFO", "Insufficient data for lessons generation")
        if not args.auto:
            print("Insufficient data to generate document. Use --status for availability.")
        return 2

    if not args.auto:
        print()
        print("════════════════════════════════════════════════════════════════")
        print("  GENERATING LESSONS LEARNED")
        print("════════════════════════════════════════════════════════════════")
        print()

    _generate_document(
        body_root=body_root,
        output_file=output_file,
        complete_marker=complete_marker,
        scope_file=scope_file,
        roe_file=roe_file,
        tokens_file=tokens_file,
        findings_file=findings_file,
        leads_file=leads_file,
        review_file=review_file,
        session_file=session_file,
        state_file=state_file,
        manifest_file=manifest_file,
        log_file=log_file,
    )

    if not args.auto:
        print(f"Lessons learned written: {output_file}")
        print()
        print("════════════════════════════════════════════════════════════════")
        print("  LESSONS LEARNED COMPLETE")
        print("════════════════════════════════════════════════════════════════")
        print()

    _run_post_lessons_automation(script_path, body_root, log_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
