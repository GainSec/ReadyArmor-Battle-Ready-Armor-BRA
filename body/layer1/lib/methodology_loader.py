#!/usr/bin/env python3
"""Markdown methodology parsing utilities."""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_PHASE_HEADER_RE = re.compile(r"^##\s+(Phase\s+[0-9]+:.*)$", re.MULTILINE)
_ML_CYAN = "\033[0;36m"
_ML_GREEN = "\033[0;32m"
_ML_DIM = "\033[2m"
_ML_NC = "\033[0m"


def _detect_body_root() -> Path:
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


def _ml_log(message: str, body_root: Path | None = None) -> None:
    root = _detect_body_root() if body_root is None else body_root
    log_file = root / ".bra" / "logs" / "ci.log"
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(f"[{_utc_now()}] [METHODOLOGY] {message}\n")
    except OSError:
        pass


def _load_text(methodology_file: str | Path) -> str:
    try:
        return Path(methodology_file).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _methodology_exists(methodology_file: str | Path) -> bool:
    path = Path(methodology_file)
    if path.is_file():
        return True
    _ml_log(f"Methodology file not found: {path}")
    return False


def extract_phases(methodology_file: str | Path) -> list[str]:
    """Return phase headers formatted like `Phase N: Name`."""
    text = _load_text(methodology_file)
    return [match.group(1).strip() for match in _PHASE_HEADER_RE.finditer(text)]


def get_phase_count(methodology_file: str | Path) -> int:
    """Return number of phases."""
    return len(extract_phases(methodology_file))


def get_phase_number(phase_line: str) -> str:
    """Extract phase number from phase title."""
    match = re.search(r"Phase\s+([0-9]+)", phase_line)
    return match.group(1) if match else ""


def get_phase_name(phase_line: str) -> str:
    """Extract phase name from phase title."""
    match = re.search(r"Phase\s+[0-9]+:\s*(.*)", phase_line)
    return match.group(1).strip() if match else phase_line.strip()


def _phase_span(text: str, phase_pattern: str) -> tuple[int, int] | None:
    candidates = list(_PHASE_HEADER_RE.finditer(text))
    if not candidates:
        return None

    phase_norm = phase_pattern.strip().lower()
    selected_idx = None
    for idx, candidate in enumerate(candidates):
        header = candidate.group(1).strip().lower()
        if phase_norm == header or phase_norm in header:
            selected_idx = idx
            break
    if selected_idx is None:
        return None

    start = candidates[selected_idx].end()
    end = candidates[selected_idx + 1].start() if selected_idx + 1 < len(candidates) else len(text)
    return start, end


def extract_phase_section(methodology_file: str | Path, phase_pattern: str) -> str:
    """Return raw markdown section body for a phase."""
    text = _load_text(methodology_file)
    span = _phase_span(text, phase_pattern)
    if span is None:
        return ""
    start, end = span
    return text[start:end].strip("\n")


def _extract_subsection(section: str, heading: str) -> str:
    pattern = re.compile(rf"^###\s+{re.escape(heading)}\s*$", re.MULTILINE)
    match = pattern.search(section)
    if not match:
        return ""

    start = match.end()
    rest = section[start:]
    next_heading = re.search(r"^###\s+", rest, re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(section)
    return section[start:end].strip("\n")


def extract_phase_objectives(methodology_file: str | Path, phase_pattern: str) -> list[str]:
    """Return objective bullet lines for phase."""
    section = extract_phase_section(methodology_file, phase_pattern)
    block = _extract_subsection(section, "Objectives")
    objectives: list[str] = []
    for line in block.splitlines():
        line = line.strip()
        if line.startswith("- "):
            objectives.append(line)
    return objectives


def extract_phase_techniques(methodology_file: str | Path, phase_pattern: str) -> str:
    """Return techniques subsection text for phase."""
    section = extract_phase_section(methodology_file, phase_pattern)
    return _extract_subsection(section, "Techniques")


def extract_code_blocks(methodology_file: str | Path, phase_pattern: str) -> list[str]:
    """Extract fenced code blocks from phase section."""
    section = extract_phase_section(methodology_file, phase_pattern)
    blocks: list[str] = []
    current: list[str] = []
    in_block = False

    for line in section.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_block:
                blocks.append("\n".join(current).strip("\n"))
                current = []
                in_block = False
            else:
                in_block = True
            continue
        if in_block:
            current.append(line)

    return blocks


def extract_code_blocks_with_lang(methodology_file: str | Path, phase_pattern: str) -> list[tuple[str, str]]:
    """Return list of ``(language, code)`` extracted from fenced blocks."""
    section = extract_phase_section(methodology_file, phase_pattern)
    blocks: list[tuple[str, str]] = []
    current: list[str] = []
    lang = "bash"
    in_block = False

    for line in section.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_block:
                blocks.append((lang, "\n".join(current).strip("\n")))
                current = []
                lang = "bash"
                in_block = False
            else:
                lang = stripped[3:].strip() or "bash"
                in_block = True
            continue
        if in_block:
            current.append(line)

    return blocks


def extract_primary_tools(methodology_file: str | Path, phase_pattern: str) -> list[str]:
    """Extract unique first command tokens from phase code blocks."""
    tools: set[str] = set()
    for block in extract_code_blocks(methodology_file, phase_pattern):
        for line in block.splitlines():
            striped = line.strip()
            if not striped or striped.startswith("#"):
                continue
            token = striped.split()[0]
            tools.add(token)
    return sorted(tools)


def extract_deliverables(methodology_file: str | Path, phase_pattern: str) -> list[str]:
    """Return deliverable checklist items without checkbox marker."""
    section = extract_phase_section(methodology_file, phase_pattern)
    block = _extract_subsection(section, "Deliverables")
    items: list[str] = []
    for line in block.splitlines():
        stripped = line.strip()
        match = re.match(r"-\s+\[[ xX]\]\s+(.*)", stripped)
        if match:
            items.append(match.group(1).strip())
    return items


def is_deliverable_complete(methodology_file: str | Path, phase_pattern: str, deliverable_text: str) -> bool:
    """Return ``True`` if matching deliverable is marked complete."""
    section = extract_phase_section(methodology_file, phase_pattern)
    pattern = re.compile(rf"-\s+\[[xX]\]\s+.*{re.escape(deliverable_text)}", re.IGNORECASE)
    return bool(pattern.search(section))


def get_current_phase(methodology_file: str | Path, state_dir: str | Path | None = None) -> str:
    """Return first phase without completion marker in state directory."""
    root = _detect_body_root()
    phase_state = Path(state_dir) if state_dir is not None else root / ".bra" / "phase_state"
    phase_state.mkdir(parents=True, exist_ok=True)

    for phase in extract_phases(methodology_file):
        phase_num = get_phase_number(phase)
        marker = phase_state / f"phase_{phase_num}.complete"
        if not marker.is_file():
            return phase
    return ""


def get_next_phase(methodology_file: str | Path, current_phase: str) -> str:
    """Return phase after current one, else empty string."""
    phases = extract_phases(methodology_file)
    current_norm = current_phase.strip().lower()
    for idx, phase in enumerate(phases):
        if current_norm == phase.lower() or current_norm in phase.lower():
            return phases[idx + 1] if idx + 1 < len(phases) else ""
    return ""


def mark_phase_complete(methodology_file: str | Path, phase_pattern: str, state_dir: str | Path | None = None) -> Path:
    """Write completion marker file for phase and return marker path."""
    root = _detect_body_root()
    phase_state = Path(state_dir) if state_dir is not None else root / ".bra" / "phase_state"
    phase_state.mkdir(parents=True, exist_ok=True)

    phase_num = get_phase_number(phase_pattern)
    marker = phase_state / f"phase_{phase_num}.complete"
    marker.write_text(
        f"Phase: {phase_pattern}\nCompleted: {_utc_now()}\nMethodology: {Path(methodology_file).name}\n",
        encoding="utf-8",
    )
    _ml_log(f"Phase {phase_num} marked complete")
    return marker


def reset_phase_state(state_dir: str | Path | None = None) -> Path:
    """Delete and recreate phase state directory."""
    root = _detect_body_root()
    phase_state = Path(state_dir) if state_dir is not None else root / ".bra" / "phase_state"
    if phase_state.exists():
        for marker in phase_state.glob("*.complete"):
            try:
                marker.unlink()
            except OSError:
                pass
    phase_state.mkdir(parents=True, exist_ok=True)
    _ml_log("Phase state reset")
    return phase_state


def get_methodology_title(methodology_file: str | Path) -> str:
    """Return first level-1 heading text."""
    for line in _load_text(methodology_file).splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return ""


def get_methodology_version(methodology_file: str | Path) -> str:
    """Extract methodology version marker, if present."""
    text = _load_text(methodology_file)
    match = re.search(r"Template Version:\*\*\s*([0-9]+\.[0-9]+)", text)
    return match.group(1) if match else "unknown"


def get_tools_reference(methodology_file: str | Path) -> str:
    """Return markdown block under `## Tools Reference`."""
    text = _load_text(methodology_file)
    match = re.search(r"^##\s+Tools\s+Reference\s*$", text, re.MULTILINE)
    if not match:
        return ""
    rest = text[match.end() :]
    next_header = re.search(r"^##\s+", rest, re.MULTILINE)
    end = match.end() + next_header.start() if next_header else len(text)
    return text[match.end() : end].strip("\n")


def show_methodology_summary(methodology_file: str | Path) -> str:
    """Build a concise printable summary for methodology."""
    if not _methodology_exists(methodology_file):
        return f"Methodology file not found: {methodology_file}"

    title = get_methodology_title(methodology_file) or str(methodology_file)
    version = get_methodology_version(methodology_file)
    phases = extract_phases(methodology_file)

    lines = [
        f"{_ML_CYAN}{title}{_ML_NC}",
        f"{_ML_DIM}Version: {version} | Phases: {len(phases)}{_ML_NC}",
        "",
        "Phases:",
    ]
    for phase in phases:
        lines.append(f"  {get_phase_number(phase)}. {get_phase_name(phase)}")
    return "\n".join(lines)


def show_phase_detail(methodology_file: str | Path, phase_pattern: str) -> str:
    """Return formatted phase details (objectives/tools/deliverables)."""
    if not _methodology_exists(methodology_file):
        return f"Methodology file not found: {methodology_file}"

    lines = ["", f"{_ML_CYAN}{phase_pattern}{_ML_NC}", "", f"{_ML_GREEN}Objectives:{_ML_NC}"]
    lines.extend(extract_phase_objectives(methodology_file, phase_pattern) or ["- (none)"])
    lines.append("")
    lines.append(f"{_ML_GREEN}Primary Tools:{_ML_NC}")
    tools = extract_primary_tools(methodology_file, phase_pattern)
    lines.extend([f"  {tool}" for tool in tools] or ["  (none)"])
    lines.append("")
    lines.append(f"{_ML_GREEN}Deliverables:{_ML_NC}")
    deliverables = extract_deliverables(methodology_file, phase_pattern)
    lines.extend([f"  - [ ] {item}" for item in deliverables] or ["  - [ ] (none)"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        print("methodology_loader.py --summary <file> | --phase <file> <phase>")
        return 0

    if args[0] == "--summary" and len(args) >= 2:
        output = show_methodology_summary(args[1])
        print(output)
        return 1 if output.startswith("Methodology file not found:") else 0

    if args[0] == "--phase" and len(args) >= 3:
        output = show_phase_detail(args[1], args[2])
        print(output)
        return 1 if output.startswith("Methodology file not found:") else 0

    print("Invalid arguments", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
