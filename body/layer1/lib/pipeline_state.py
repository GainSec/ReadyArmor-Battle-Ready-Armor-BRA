#!/usr/bin/env python3
"""Pipeline/session state tracking utilities."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PHASE_KEYS = ("intel", "static", "dynamic", "report")


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


def _ps_log(message: str, body_root: Path | None = None) -> None:
    root = _detect_body_root() if body_root is None else body_root
    try:
        log_file = root / ".bra" / "logs" / "ci.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(f"[{_utc_now()}] [PIPELINE-STATE] {message}\n")
    except OSError:
        pass


def get_state_file(body_root: Path | None = None) -> Path:
    """Return canonical pipeline-state file path."""
    root = _detect_body_root() if body_root is None else body_root
    return root / ".bra" / "pipeline_state.json"


def get_session_file(body_root: Path | None = None) -> Path:
    """Return canonical session log file path."""
    root = _detect_body_root() if body_root is None else body_root
    return root / "layer3-engagement" / "NOTES" / "SESSION.md"


def _normalize_phase(phase: str) -> str:
    return phase.strip().lower().replace(" ", "").split(":", 1)[0]


def _default_state() -> dict[str, Any]:
    phases = {phase: {"status": "pending"} for phase in _PHASE_KEYS}
    state: dict[str, Any] = {
        "last_phase": "",
        "status": "initialized",
        "timestamp": _utc_now(),
        "phases": phases,
    }
    for phase in _PHASE_KEYS:
        state[f"{phase}_complete"] = False
    return state


def _load_state(body_root: Path | None = None) -> dict[str, Any]:
    path = get_state_file(body_root)
    if not path.is_file():
        return _default_state()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _default_state()
    if not isinstance(payload, dict):
        return _default_state()
    payload.setdefault("phases", {})
    if not isinstance(payload["phases"], dict):
        payload["phases"] = {}
    for phase in _PHASE_KEYS:
        payload["phases"].setdefault(phase, {"status": "pending"})
        payload.setdefault(f"{phase}_complete", False)
    return payload


def _save_state(state: dict[str, Any], body_root: Path | None = None) -> None:
    path = get_state_file(body_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def update_pipeline_state(phase: str, phase_status: str, body_root: Path | None = None) -> dict[str, Any]:
    """Update phase status and persist pipeline state."""
    normalized = _normalize_phase(phase)
    state = _load_state(body_root)

    state["last_phase"] = normalized
    state["timestamp"] = _utc_now()
    state.setdefault("phases", {}).setdefault(normalized, {})["status"] = phase_status
    if phase_status == "complete":
        state[f"{normalized}_complete"] = True

    _save_state(state, body_root)
    _ps_log(f"State updated: phase={normalized} status={phase_status}", body_root)
    return state


def phase_start(phase: str, body_root: Path | None = None) -> dict[str, Any]:
    """Mark phase in progress and append session event."""
    state = update_pipeline_state(phase, "in_progress", body_root)
    update_session("Phase Started", phase, body_root)
    return state


def phase_complete(phase: str, body_root: Path | None = None) -> dict[str, Any]:
    """Mark phase complete and create completion marker file."""
    root = _detect_body_root() if body_root is None else body_root
    normalized = _normalize_phase(phase)

    marker = root / ".bra" / "artifacts" / f".{normalized}_complete"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()

    state = update_pipeline_state(normalized, "complete", root)
    update_session("Phase Complete", phase, root)
    _ps_log(f"Phase complete: {normalized} (marker created)", root)
    return state


def init_phase_work_dir(phase: str, body_root: Path | None = None) -> Path:
    """Create and return artifacts work directory for phase."""
    root = _detect_body_root() if body_root is None else body_root
    normalized = _normalize_phase(phase)
    work_dir = root / ".bra" / "artifacts" / f"{normalized}_work"

    if not work_dir.exists():
        work_dir.mkdir(parents=True, exist_ok=True)
        readme = work_dir / "README.md"
        readme.write_text(
            "\n".join(
                [
                    f"# Phase: {phase}",
                    "",
                    f"> **Created:** {_utc_now()}",
                    "",
                    "---",
                    "",
                    "## Purpose",
                    "",
                    f"This directory contains artifacts from the **{phase}** phase.",
                    "",
                    "## Contents",
                    "",
                    "| File | Description |",
                    "|------|-------------|",
                    "| (artifacts will be added during execution) | |",
                    "",
                    "---",
                    "",
                    "## Notes",
                    "",
                    "Add phase-specific notes here during execution.",
                    "",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        _ps_log(f"Work directory created: {work_dir}", root)

    return work_dir


def init_session(body_root: Path | None = None) -> Path:
    """Create session markdown if missing or skeletal."""
    root = _detect_body_root() if body_root is None else body_root
    session_path = get_session_file(root)
    session_path.parent.mkdir(parents=True, exist_ok=True)

    needs_init = True
    if session_path.is_file():
        try:
            needs_init = len(session_path.read_text(encoding="utf-8", errors="ignore").splitlines()) < 10
        except OSError:
            needs_init = True

    if needs_init:
        scope_path = root / "layer3-engagement" / "SCOPE.md"
        target = "Unknown"
        if scope_path.is_file():
            scope_lines = scope_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            for index, line in enumerate(scope_lines):
                if re.match(r"^##\s+Target\b", line.strip(), flags=re.IGNORECASE):
                    if index + 1 < len(scope_lines):
                        candidate = scope_lines[index + 1].strip()[:50]
                        target = candidate or "See SCOPE.md"
                    else:
                        target = "See SCOPE.md"
                    break
                if "**Name:**" in line:
                    target = line.split("**Name:**", 1)[1].strip() or "Unknown"
                    break
        session_path.write_text(
            "\n".join(
                [
                    "# Session Log",
                    "",
                    f"> **Started:** {_utc_now()}",
                    "> **Methodology:** Pending detection",
                    f"> **Target:** {target}",
                    "",
                    "---",
                    "",
                    "## Session Timeline",
                    "",
                    "| Timestamp | Event | Details |",
                    "|-----------|-------|---------|",
                    f"| {_utc_now()} | Session Initialized | Agentic loop started |",
                    "",
                    "---",
                    "",
                    "## Notes",
                    "",
                    "(Session notes will be appended as phases progress)",
                    "",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        _ps_log("SESSION.md initialized", root)

    return session_path


def update_session(event: str, details: str = "", body_root: Path | None = None) -> None:
    """Append timeline row to session markdown."""
    root = _detect_body_root() if body_root is None else body_root
    session_path = init_session(root)

    row = f"| {_utc_now()} | {event} | {details} |"
    text = session_path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()

    insert_after = None
    for idx, line in enumerate(lines):
        if line.strip() == "|-----------|-------|---------|":
            insert_after = idx
            break

    if insert_after is None:
        lines.extend(["", "| Timestamp | Event | Details |", "|-----------|-------|---------|"])
        insert_after = len(lines) - 1

    lines.insert(insert_after + 1, row)
    session_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    _ps_log(f"Session updated: {event} - {details}", root)


def get_phase_status(phase: str, body_root: Path | None = None) -> str:
    """Return status for phase, or ``unknown``."""
    normalized = _normalize_phase(phase)
    state = _load_state(body_root)
    phase_entry = state.get("phases", {}).get(normalized, {})
    status = phase_entry.get("status") if isinstance(phase_entry, dict) else None
    return str(status) if isinstance(status, str) else "unknown"


def is_phase_complete(phase: str, body_root: Path | None = None) -> bool:
    """Return ``True`` when phase completion marker or state flag exists."""
    root = _detect_body_root() if body_root is None else body_root
    normalized = _normalize_phase(phase)
    marker = root / ".bra" / "artifacts" / f".{normalized}_complete"
    if marker.is_file():
        return True

    state = _load_state(root)
    if bool(state.get(f"{normalized}_complete", False)):
        return True
    return get_phase_status(normalized, root) == "complete"


def _show_help() -> None:
    print(
        "pipeline_state.py\n\n"
        "Usage:\n"
        "  pipeline_state.py --start <phase>\n"
        "  pipeline_state.py --complete <phase>\n"
        "  pipeline_state.py --status <phase>\n"
        "  pipeline_state.py --init-session\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        _show_help()
        return 0

    if args[0] == "--start" and len(args) >= 2:
        phase_start(args[1])
        return 0

    if args[0] == "--complete" and len(args) >= 2:
        phase_complete(args[1])
        return 0

    if args[0] == "--status" and len(args) >= 2:
        print(get_phase_status(args[1]))
        return 0

    if args[0] == "--init-session":
        print(init_session())
        return 0

    print("Invalid arguments", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
