#!/usr/bin/env python3
"""Comprehensive structured audit-trail helpers."""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

_TRACK_ENABLED_CACHE: bool | None = None
_BOX_WIDTH = 78


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


def _track_log_file(body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    return root / ".bra" / "logs" / "track.log"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def track_enabled(body_root: Path | None = None, *, use_cache: bool = True) -> bool:
    """Return whether TRACK logging is enabled (default enabled)."""
    global _TRACK_ENABLED_CACHE

    if use_cache and _TRACK_ENABLED_CACHE is not None:
        return _TRACK_ENABLED_CACHE

    root = _detect_body_root() if body_root is None else body_root
    approvals = root / ".bra" / "approvals"

    enabled = True
    if os.environ.get("TRACK") == "0":
        enabled = False
    elif (approvals / "TRACK_DISABLED").is_file():
        enabled = False
    elif os.environ.get("TRACK") == "1":
        enabled = True
    elif (approvals / "TRACK").is_file():
        enabled = True
    else:
        roe_files = [root / "layer3-engagement" / "ROE.md", root / "layer1" / "rules" / "roe.md"]
        for roe_file in roe_files:
            text = _read_text(roe_file)
            if "TRACK: DISABLED" in text:
                enabled = False
                break
            if "TRACK: ENABLED" in text:
                enabled = True
                break

    if use_cache:
        _TRACK_ENABLED_CACHE = enabled
    return enabled


def track_reset_cache() -> None:
    """Clear cached enabled-state."""
    global _TRACK_ENABLED_CACHE
    _TRACK_ENABLED_CACHE = None


def _append_lines(lines: list[str], body_root: Path | None = None) -> None:
    log_file = _track_log_file(body_root)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def _track_hline(char: str = "─", width: int = _BOX_WIDTH) -> str:
    """Return repeated horizontal line string."""
    return char * max(width, 1)


def _track_box_top(category: str) -> str:
    label = f" {category} "
    remaining = max(_BOX_WIDTH - len(label) - 2, 0)
    return f"┌─{label}{'─' * remaining}┐"


def _track_box_mid() -> str:
    return f"├{'─' * (_BOX_WIDTH - 2)}┤"


def _track_box_bottom() -> str:
    return f"└{'─' * (_BOX_WIDTH - 2)}┘"


def _track_box_line(content: str) -> str:
    trimmed = content[: _BOX_WIDTH - 4]
    return f"│ {trimmed}"


def _track_indent_output(output: str, max_lines: int = 50) -> list[str]:
    lines: list[str] = []
    for idx, line in enumerate(output.splitlines(), start=1):
        if idx > max_lines:
            lines.append(f"│   ... (truncated, {idx}+ lines)")
            break
        snippet = line[:72] + ("..." if len(line) > 72 else "")
        lines.append(f"│   {snippet}")
    if not lines and output:
        snippet = output[:72] + ("..." if len(output) > 72 else "")
        lines.append(f"│   {snippet}")
    return lines


def track_init(body_root: Path | None = None) -> None:
    """Append session-start marker if track logging is enabled."""
    if not track_enabled(body_root):
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _append_lines(["", _track_hline("═"), f"SESSION START: {ts}", _track_hline("═"), ""], body_root)


def track_end(body_root: Path | None = None) -> None:
    """Append session-end marker if track logging is enabled."""
    if not track_enabled(body_root):
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _append_lines(["", _track_hline("═"), f"SESSION END: {ts}", _track_hline("═"), ""], body_root)


def track_log(category: str, operation: str, reason: str, output: str = "", body_root: Path | None = None) -> None:
    """Write structured track entry with optional output body."""
    if not track_enabled(body_root):
        return

    now = datetime.now().strftime("%H:%M:%S")
    lines = [
        _track_box_top(category),
        _track_box_line(f"Time:    {now}"),
        _track_box_line(f"Action:  {operation}"),
        _track_box_line(f"Reason:  {reason}"),
    ]

    if output:
        lines.append(_track_box_mid())
        lines.append(_track_box_line("Output:"))
        lines.extend(_track_indent_output(output))

    lines.extend([_track_box_bottom(), ""])
    _append_lines(lines, body_root)


def track_cmd(command: str, reason: str, output: str = "", body_root: Path | None = None) -> None:
    track_log("CMD", command, reason, output, body_root)


def track_script(script_name: str, reason: str, output: str = "", body_root: Path | None = None) -> None:
    track_log("SCRIPT", script_name, reason, output, body_root)


def track_phase(phase_name: str, reason: str, details: str = "", body_root: Path | None = None) -> None:
    track_log("PHASE", phase_name, reason, details, body_root)


def track_skill(skill_name: str, reason: str, output: str = "", body_root: Path | None = None) -> None:
    track_log("SKILL", skill_name, reason, output, body_root)


def track_action(action: str, reason: str, result: str = "", body_root: Path | None = None) -> None:
    track_log("ACTION", action, reason, result, body_root)


def track_danger(result: str, command: str, reason: str, pattern: str = "", body_root: Path | None = None) -> None:
    details = f"Matched pattern: {pattern}" if pattern else ""
    track_log("DANGER", f"{result}: {command}", reason, details, body_root)


def track_gate(gate_name: str, result: str, reason: str, body_root: Path | None = None) -> None:
    track_log("GATE", f"{gate_name} \u2192 {result}", reason, "", body_root)


def track_artifact(operation: str, source: str, reason: str, details: str = "", body_root: Path | None = None) -> None:
    track_log("ARTIFACT", f"{operation}: {source}", reason, details, body_root)


def track_token(token_name: str, result: str, reason: str, body_root: Path | None = None) -> None:
    track_log("TOKEN", f"{token_name} \u2192 {result}", reason, "", body_root)


def track_decision(decision: str, options_considered: str, reason: str, body_root: Path | None = None) -> None:
    track_log("DECISION", decision, reason, f"Options considered: {options_considered}", body_root)


def track_finding(finding_type: str, description: str, evidence: str = "", body_root: Path | None = None) -> None:
    track_log("FINDING", finding_type, description, evidence, body_root)


def track_error(operation: str, error_message: str, reason: str = "Error occurred", body_root: Path | None = None) -> None:
    track_log("ERROR", operation, reason, error_message, body_root)


def track_warn(operation: str, warning_message: str, reason: str = "Warning", body_root: Path | None = None) -> None:
    track_log("WARN", operation, reason, warning_message, body_root)


def track_log_path(body_root: Path | None = None) -> Path:
    """Return path to track log file."""
    return _track_log_file(body_root)


def track_has_logs(body_root: Path | None = None) -> bool:
    """Return ``True`` when track log exists and contains content."""
    log_file = _track_log_file(body_root)
    return log_file.is_file() and log_file.stat().st_size > 0


def track_tail(lines: int = 50, body_root: Path | None = None) -> str:
    """Return last ``lines`` lines from track log."""
    log_file = _track_log_file(body_root)
    if not log_file.is_file():
        return f"No track log found at {log_file}"
    content = _read_text(log_file).splitlines()
    return "\n".join(content[-max(lines, 1) :])


def track_exec(reason: str, command: list[str], body_root: Path | None = None) -> tuple[int, str]:
    """Execute command and log stdout/stderr with decision context."""
    result = subprocess.run(command, capture_output=True, text=True)
    output = (result.stdout or "") + (result.stderr or "")
    command_text = " ".join(command)
    if result.returncode == 0:
        track_cmd(command_text, reason, output, body_root)
    else:
        track_error(command_text, output, f"{reason} (exit code: {result.returncode})", body_root)
    return result.returncode, output


def _show_help() -> None:
    print(
        "track.py\n\n"
        "Usage:\n"
        "  track.py --init\n"
        "  track.py --log <CATEGORY> <operation> <reason> [output]\n"
        "  track.py --tail [lines]\n"
        "  track.py --enabled\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        _show_help()
        return 0

    if args[0] == "--init":
        track_init()
        return 0

    if args[0] == "--log" and len(args) >= 4:
        output = " ".join(args[4:]) if len(args) >= 5 else ""
        track_log(args[1], args[2], args[3], output)
        return 0

    if args[0] == "--tail":
        lines = int(args[1]) if len(args) >= 2 and args[1].isdigit() else 50
        print(track_tail(lines))
        return 0

    if args[0] == "--enabled":
        print("1" if track_enabled(use_cache=False) else "0")
        return 0

    print("Invalid arguments", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
