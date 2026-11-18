#!/usr/bin/env python3
"""Phase context generation and improvement-capture helpers."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LIB_DIR = str(Path(__file__).resolve().parent)
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

try:
    import methodology_loader as _ml  # type: ignore
except Exception:  # pragma: no cover
    _ml = None  # type: ignore

try:
    import pipeline_state as _ps  # type: ignore
except Exception:  # pragma: no cover
    _ps = None  # type: ignore

try:
    import tool_resolver as _tr  # type: ignore
except Exception:  # pragma: no cover
    _tr = None  # type: ignore


def _detect_body_root() -> Path:
    if os.environ.get("PROJECT_ROOT"):
        return Path(os.environ["PROJECT_ROOT"]).expanduser().resolve()
    script = Path(__file__).resolve()
    for parent in script.parents:
        if parent.name == "body":
            return parent
    cwd = Path.cwd().resolve()
    for parent in (cwd, *cwd.parents):
        if parent.name == "body":
            return parent
    return cwd


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pi_log(message: str, body_root: Path | None = None) -> None:
    root = _detect_body_root() if body_root is None else body_root
    try:
        log_file = root / ".bra" / "logs" / "ci.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(f"[{_utc_now()}] [PHASE-INVOKER] {message}\n")
    except OSError:
        pass


def get_context_file(body_root: Path | None = None) -> Path:
    """Return phase-context file path."""
    root = _detect_body_root() if body_root is None else body_root
    return root / ".bra" / "phase_context.md"


def _phase_slug(phase_pattern: str) -> str:
    cleaned = phase_pattern.lower().replace(" ", "")
    prefix = cleaned.split(":", 1)[0]
    if prefix.startswith("intelligence"):
        return "intel"
    if prefix.startswith("static"):
        return "static"
    if prefix.startswith("dynamic"):
        return "dynamic"
    if prefix.startswith("report"):
        return "report"
    return prefix or "phase"


def _phase_number(phase_pattern: str) -> str:
    match = re.search(r"phase\s*([0-9]+)", phase_pattern, re.IGNORECASE)
    return match.group(1) if match else "?"


def _phase_name(phase_pattern: str) -> str:
    if ":" in phase_pattern:
        return phase_pattern.split(":", 1)[1].strip()
    return phase_pattern.strip()


def _methodology_objectives(methodology_file: str, phase_pattern: str) -> list[str]:
    if _ml is None:
        return ["- Execute phase techniques"]
    try:
        objectives = _ml.extract_phase_objectives(methodology_file, phase_pattern)
    except Exception:
        objectives = []
    return objectives or ["- Execute phase techniques"]


def _methodology_code_blocks(methodology_file: str, phase_pattern: str) -> list[str]:
    if _ml is None:
        return ["# See methodology file for techniques"]
    try:
        blocks = _ml.extract_code_blocks(methodology_file, phase_pattern)
    except Exception:
        blocks = []
    return blocks or ["# See methodology file for techniques"]


def _methodology_deliverables(methodology_file: str, phase_pattern: str) -> list[str]:
    if _ml is None:
        return ["Complete phase objectives"]
    try:
        deliverables = _ml.extract_deliverables(methodology_file, phase_pattern)
    except Exception:
        deliverables = []
    return deliverables or ["Complete phase objectives"]


def _token_status(body_root: Path) -> str:
    """Return token status table for phase context."""
    lines = [
        "| Token | Status |",
        "|-------|--------|",
    ]
    for token_name, env_key in (
        ("ACTIVE-TESTING-APPROVAL", "ACTIVE_TESTING_APPROVAL"),
        ("DESTRUCTIVE-APPROVAL", "DESTRUCTIVE_APPROVAL"),
        ("WATCH", "WATCH"),
        ("TRACK", "TRACK"),
    ):
        granted = False
        if os.environ.get(env_key) == "1":
            granted = True
        elif (body_root / ".bra" / "approvals" / token_name).is_file():
            granted = True
        label = "**GRANTED**" if granted else "Not Set"
        if token_name in ("WATCH", "TRACK") and granted:
            label = "ENABLED"
        elif token_name in ("WATCH", "TRACK"):
            label = "Disabled"
        lines.append(f"| {token_name} | {label} |")
    return "\n".join(lines)


def _tool_status(methodology_file: str) -> str:
    if _tr is None:
        return "Unable to resolve tools"
    try:
        resolved = _tr.resolve_tools_for_methodology(methodology_file)
    except Exception:
        return "Unable to resolve tools"

    lines = [f"Available: {len(resolved.get('available', []))}"]
    for item in resolved.get("available", [])[:10]:
        lines.append(f"  - {item.get('tool', '')}")
    missing = resolved.get("missing", [])
    if missing:
        lines.append(f"Missing: {len(missing)}")
        for item in missing[:10]:
            lines.append(f"  - {item.get('tool', '')}")
    return "\n".join(lines)


def output_phase_context(phase_pattern: str, methodology_file: str, body_root: Path | None = None) -> Path:
    """Generate `.bra/phase_context.md` for current phase and return path."""
    root = _detect_body_root() if body_root is None else body_root
    context_file = get_context_file(root)
    context_file.parent.mkdir(parents=True, exist_ok=True)

    phase_num = _phase_number(phase_pattern)
    phase_name = _phase_name(phase_pattern)
    phase_slug = _phase_slug(phase_pattern)

    # In SLOWPATH-FINDINGS mode, use canonical raw store instead of per-phase dirs.
    slowpath = False
    slowpath_token = root / ".bra" / "approvals" / "SLOWPATH-FINDINGS"
    if slowpath_token.is_file() or os.environ.get("SLOWPATH_FINDINGS") == "1":
        slowpath = True

    if slowpath:
        artifact_dir = root / ".bra" / "artifacts" / "raw"
    else:
        if phase_num.isdigit() and (root / ".bra" / "artifacts" / f"phase{phase_num}_work").is_dir():
            artifact_dir = root / ".bra" / "artifacts" / f"phase{phase_num}_work"
        else:
            artifact_dir = root / ".bra" / "artifacts" / f"{phase_slug}_work"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    objectives = _methodology_objectives(methodology_file, phase_pattern)
    code_blocks = _methodology_code_blocks(methodology_file, phase_pattern)
    deliverables = _methodology_deliverables(methodology_file, phase_pattern)

    lines = [
        "# Phase Execution Context",
        "",
        f"> **Generated:** {_utc_now()}",
        f"> **Methodology:** {Path(methodology_file).stem}",
        f"> **Phase:** {phase_num} - {phase_name}",
        "",
        "---",
        "",
        "## Current Phase",
        "",
        f"**{phase_pattern}**",
        "",
        "---",
        "",
        "## Objectives",
        "",
        *objectives,
        "",
        "---",
        "",
        "## Techniques",
        "",
        "The following techniques are available for this phase. Adapt based on available tools and scope constraints.",
        "",
        "```bash",
        *[line for block in code_blocks for line in block.splitlines()],
        "```",
        "",
        "---",
        "",
        "## Tool Status",
        "",
        _tool_status(methodology_file),
        "",
        "---",
        "",
        "## Token Status",
        "",
        _token_status(root),
        "",
        "---",
        "",
        "## Artifacts Directory",
        "",
        "All artifacts should be saved to:",
        f"`{artifact_dir.relative_to(root)}/`",
        "",
        "---",
        "",
        "## Deliverables Checklist",
        "",
        *[f"- [ ] {item}" for item in deliverables],
        "",
        "---",
        "",
        "## Execution Instructions",
        "",
        "**Claude:** Read the methodology techniques above and execute appropriate commands based on:",
        "1. Available tools (check status above)",
        "2. Scope constraints (see layer3-engagement/SCOPE.md)",
        "3. Token permissions (active testing requires ACTIVE-TESTING-APPROVAL)",
        "",
        "After completing each deliverable, mark it complete and proceed to the next.",
        "",
        "When the phase is complete, tell Claude \"next phase\" or \"advance\" to move to the next phase.",
        "Claude will mark phase state files and load the next phase from the methodology.",
        "",
        "---",
        "",
        "## Phase Checkpoint",
        "",
        "After completing this phase, you will be presented with options:",
        "1. Continue to next phase",
        "2. Discuss findings first",
        "3. Re-run this phase with different parameters",
        "",
        "This gives explicit control while Claude drives the methodology.",
    ]

    context_file.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"Phase context written to: {context_file}")
    _pi_log(f"Context file generated: {context_file}", root)
    return context_file


def show_phase_checkpoint(phase_pattern: str, methodology_file: str = "", body_root: Path | None = None) -> str:
    """Return checkpoint prompt for post-phase control flow."""
    phase_num = _phase_number(phase_pattern)
    phase_name = _phase_name(phase_pattern)

    next_phase = ""
    if _ml is not None and methodology_file:
        try:
            next_phase = _ml.get_next_phase(methodology_file, phase_pattern)
        except Exception:
            next_phase = ""

    deliverables: list[str] = []
    if _ml is not None and methodology_file:
        try:
            deliverables = _ml.extract_deliverables(methodology_file, phase_pattern)
        except Exception:
            deliverables = []

    border = "═" * 63
    lines = [
        "",
        border,
        f"  Phase {phase_num}: {phase_name} complete.",
        border,
        "",
        "Deliverables:",
    ]
    for d in deliverables:
        lines.append(f"  - [?] {d}")
    lines.append("")
    lines.append("Options:")
    if next_phase:
        lines.append(f"  1. Continue to {next_phase}")
    else:
        lines.append("  1. All phases complete - generate report")
    lines.append("  2. Discuss findings first")
    lines.append("  3. Re-run this phase with different parameters")
    lines.append("")
    return "\n".join(lines)


def complete_phase(phase_pattern: str, body_root: Path | None = None) -> None:
    """Mark phase complete in artifacts/state/session logs."""
    root = _detect_body_root() if body_root is None else body_root
    phase_slug = _phase_slug(phase_pattern)

    marker = root / ".bra" / "artifacts" / f".{phase_slug}_complete"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()

    if _ps is not None:
        try:
            _ps.update_pipeline_state(phase_slug, "complete", root)
            _ps.update_session("Phase Complete", phase_pattern, root)
        except Exception:
            pass

    _pi_log(f"Phase completed: {phase_slug}", root)


def _append_improvement_log(filename: str, line: str, body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    path = root / ".bra" / "improvements" / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line.rstrip() + "\n")
    return path


def log_technique_used(technique: str, source: str = "discovered", body_root: Path | None = None) -> Path:
    """Append technique usage entry and return log path."""
    phase = os.environ.get("CURRENT_PHASE", "unknown")
    entry = f"{_utc_now()} | {phase} | {technique} | {source}"
    path = _append_improvement_log("techniques.log", entry, body_root)
    _pi_log(f"Technique logged: {technique} (source: {source})", body_root)
    return path


def log_tool_used(tool_name: str, context: str = "phase execution", body_root: Path | None = None) -> Path:
    """Append tool usage entry and return log path."""
    entry = f"{_utc_now()} | {tool_name} | {context}"
    return _append_improvement_log("tools.log", entry, body_root)


def log_methodology_gap(description: str, category: str = "general", body_root: Path | None = None) -> Path:
    """Append methodology gap entry and return log path."""
    entry = f"{_utc_now()} | {category} | {description}"
    path = _append_improvement_log("gaps.log", entry, body_root)
    _pi_log(f"Gap logged: {description}", body_root)
    return path


def _write_pitch(
    filename: str,
    title: str,
    sections: list[str],
    body_root: Path | None = None,
    metadata: list[str] | None = None,
) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    pitches = root / "layer3-engagement" / "pitches"
    pitches.mkdir(parents=True, exist_ok=True)
    path = pitches / filename
    payload = [f"# {title}", "", f"> **Generated:** {_utc_now()}", "> **Status:** PENDING REVIEW"]
    if metadata:
        payload.extend(metadata)
    payload.extend(["", "---", "", *sections])
    path.write_text("\n".join(payload).rstrip() + "\n", encoding="utf-8")
    return path


def propose_methodology_update(description: str, code_block: str = "", methodology: str = "unknown", body_root: Path | None = None) -> Path:
    """Create methodology-update pitch document and return its path."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    sections = ["## Description", "", description, "", "---", "", "## Proposed Addition", ""]
    if code_block.strip():
        sections.extend(["```bash", code_block, "```", ""])
    sections.extend(
        [
            "---",
            "",
            "## Rationale",
            "",
            "This technique was discovered during engagement execution and proved useful.",
            "Consider adding to the methodology for future engagements.",
            "",
            "---",
            "",
            "## Approval",
            "",
            "- [ ] Reviewed by operator",
            "- [ ] Approved for integration",
            "- [ ] Integrated into methodology",
        ]
    )
    path = _write_pitch(
        f"auto-methodology-{timestamp}.md",
        "Methodology Update Proposal",
        sections,
        body_root,
        metadata=[f"> **Methodology:** {methodology}"],
    )
    _pi_log(f"Methodology pitch created: {path}", body_root)
    return path


def propose_tool_addition(tool_name: str, purpose: str, install_command: str = "# See documentation", body_root: Path | None = None) -> Path:
    """Create tool-addition pitch document and return its path."""
    timestamp = datetime.now().strftime("%Y%m%d")
    sections = [
        "## Tool Details",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Name | `{tool_name}` |",
        f"| Purpose | {purpose} |",
        f"| Install | `{install_command}` |",
        "",
        "---",
        "",
        "## Usage Context",
        "",
        "This tool was used during engagement execution and proved useful for:",
        "",
        "- (Add specific use cases)",
        "",
        "---",
        "",
        "## Approval",
        "",
        "- [ ] Reviewed by operator",
        "- [ ] Approved for toolset.md",
        "- [ ] Added to toolset.md",
    ]
    path = _write_pitch(f"auto-tool-{tool_name}-{timestamp}.md", f"Tool Addition Proposal: {tool_name}", sections, body_root)
    _pi_log(f"Tool pitch created: {path}", body_root)
    return path


def consolidate_improvements(body_root: Path | None = None) -> Path:
    """Summarize logged improvements and generate markdown report."""
    root = _detect_body_root() if body_root is None else body_root
    improvements = root / ".bra" / "improvements"

    summary: dict[str, Any] = {"techniques": 0, "tools": 0, "gaps": 0, "files": {}}
    for name, key in (("techniques.log", "techniques"), ("tools.log", "tools"), ("gaps.log", "gaps")):
        path = improvements / name
        if path.is_file():
            lines = [line for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
            summary[key] = len(lines)
            summary["files"][key] = str(path)

    # Generate markdown report
    output_file = improvements / "engagement-summary.md"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    report_lines = [
        "# Engagement Improvement Summary",
        "",
        f"> **Generated:** {_utc_now()}",
        "",
        "---",
        "",
        "## Techniques Discovered",
        "",
    ]

    tech_path = improvements / "techniques.log"
    if tech_path.is_file():
        report_lines.extend([
            "| Timestamp | Phase | Technique | Source |",
            "|-----------|-------|-----------|--------|",
        ])
        for raw_line in tech_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not raw_line.strip():
                continue
            parts = raw_line.split("|")
            ts = parts[0].strip() if len(parts) > 0 else ""
            phase = parts[1].strip() if len(parts) > 1 else ""
            tech = parts[2].strip() if len(parts) > 2 else ""
            src = parts[3].strip() if len(parts) > 3 else ""
            report_lines.append(f"| {ts} | {phase} | {tech} | {src} |")
    else:
        report_lines.append("None logged.")

    report_lines.extend([
        "",
        "---",
        "",
        "## Tools Used",
        "",
    ])

    tools_path = improvements / "tools.log"
    if tools_path.is_file():
        seen: set[str] = set()
        tool_entries: list[str] = []
        for raw_line in tools_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not raw_line.strip():
                continue
            parts = raw_line.split("|")
            tool = parts[1].strip() if len(parts) > 1 else ""
            ctx = parts[2].strip() if len(parts) > 2 else ""
            entry = f"- {tool} ({ctx})"
            if entry not in seen:
                seen.add(entry)
                tool_entries.append(entry)
        tool_entries.sort()
        report_lines.extend(tool_entries)
    else:
        report_lines.append("None logged.")

    report_lines.extend([
        "",
        "---",
        "",
        "## Gaps Identified",
        "",
    ])

    gaps_path = improvements / "gaps.log"
    if gaps_path.is_file():
        for raw_line in gaps_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not raw_line.strip():
                continue
            parts = raw_line.split("|")
            cat = parts[1].strip() if len(parts) > 1 else ""
            desc = parts[2].strip() if len(parts) > 2 else ""
            report_lines.append(f"- [{cat}] {desc}")
    else:
        report_lines.append("None logged.")

    report_lines.extend([
        "",
        "---",
        "",
        "## Pending Pitches",
        "",
    ])

    pitches_dir = root / "layer3-engagement" / "pitches"
    if pitches_dir.is_dir():
        pipeline_state = root / ".bra" / "pipeline_state.json"
        found_pitches = False
        for f in sorted(pitches_dir.glob("auto-*.md")):
            if not pipeline_state.is_file() or f.stat().st_mtime > pipeline_state.stat().st_mtime:
                report_lines.append(f"- {f.name}")
                found_pitches = True
        if not found_pitches:
            report_lines.append("None.")
    else:
        report_lines.append("None.")

    output_file.write_text("\n".join(report_lines).rstrip() + "\n", encoding="utf-8")
    print(f"Improvement summary: {output_file}")

    _pi_log(f"Improvements consolidated: {json.dumps(summary, sort_keys=True)}", root)
    return output_file


def has_valid_context(max_age: int = 3600, body_root: Path | None = None) -> bool:
    """Return whether phase context file exists and is recent enough."""
    path = get_context_file(body_root)
    if not path.is_file():
        return False
    file_age = datetime.now(timezone.utc).timestamp() - path.stat().st_mtime
    return file_age < max_age


def show_context_summary(body_root: Path | None = None) -> str:
    """Return compact context summary from generated context file."""
    path = get_context_file(body_root)
    if not path.is_file():
        return (
            "No phase context file found.\n"
            "Run: ./layer1/scripts/agentic-handler.py to generate context"
        )

    text = path.read_text(encoding="utf-8", errors="ignore")

    # Extract key metadata lines
    metadata_lines: list[str] = []
    for line in text.splitlines():
        if re.match(r">\s*\*\*(Generated|Methodology|Phase):", line):
            metadata_lines.append(line)
        if len(metadata_lines) >= 3:
            break

    lines = [
        "",
        "Current Phase Context",
        "======================",
        "",
    ]
    lines.extend(metadata_lines)
    lines.append("")
    lines.append(f"Context file: {path}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        print("phase_invoker.py --context <phase> <methodology.md> | --summary")
        return 0

    if args[0] == "--context" and len(args) >= 3:
        print(output_phase_context(args[1], args[2]))
        return 0

    if args[0] == "--summary":
        print(show_context_summary())
        return 0

    print("Invalid arguments", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
