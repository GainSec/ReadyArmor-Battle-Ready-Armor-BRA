#!/usr/bin/env python3
"""Human-readable audit log helpers."""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

_WATCH_ENABLED_CACHE: bool | None = None


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


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _watch_log_file(body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    return root / ".bra" / "logs" / "watch.log"


def watch_enabled(body_root: Path | None = None, *, use_cache: bool = True) -> bool:
    """Return whether WATCH logging is enabled (default enabled)."""
    global _WATCH_ENABLED_CACHE

    if use_cache and _WATCH_ENABLED_CACHE is not None:
        return _WATCH_ENABLED_CACHE

    root = _detect_body_root() if body_root is None else body_root
    approvals = root / ".bra" / "approvals"

    enabled = True
    if os.environ.get("WATCH") == "0":
        enabled = False
    elif (approvals / "WATCH_DISABLED").is_file():
        enabled = False
    elif os.environ.get("WATCH") == "1":
        enabled = True
    elif (approvals / "WATCH").is_file():
        enabled = True
    else:
        roe_files = [root / "layer3-engagement" / "ROE.md", root / "layer1" / "rules" / "roe.md"]
        for roe_file in roe_files:
            text = _read_text(roe_file)
            if "WATCH: DISABLED" in text:
                enabled = False
                break
            if "WATCH: ENABLED" in text:
                enabled = True
                break

    if use_cache:
        _WATCH_ENABLED_CACHE = enabled
    return enabled


def watch_reset_cache() -> None:
    """Clear cached enabled-state."""
    global _WATCH_ENABLED_CACHE
    _WATCH_ENABLED_CACHE = None


def _append_line(line: str, body_root: Path | None = None) -> None:
    log_file = _watch_log_file(body_root)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(line)


def watch_init(body_root: Path | None = None) -> None:
    """Append session-start marker if watch logging is enabled."""
    if not watch_enabled(body_root):
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _append_line(f"\n=== SESSION START: {ts} ===\n", body_root)


def watch_end(body_root: Path | None = None) -> None:
    """Append session-end marker if watch logging is enabled."""
    if not watch_enabled(body_root):
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _append_line(f"=== SESSION END: {ts} ===\n\n", body_root)


def watch_log(category: str, operation: str, context: str = "", body_root: Path | None = None) -> None:
    """Write one aligned watch log line."""
    if not watch_enabled(body_root):
        return
    now = datetime.now().strftime("%H:%M:%S")
    padded = f"{category:<8}"[:8]
    if context:
        _append_line(f"[{now}] [{padded}] {operation} | {context}\n", body_root)
    else:
        _append_line(f"[{now}] [{padded}] {operation}\n", body_root)


def watch_cmd(command: str, status: str = "executed", body_root: Path | None = None) -> None:
    watch_log("CMD", command, status, body_root)


def watch_script(script_name: str, context: str = "", body_root: Path | None = None) -> None:
    watch_log("SCRIPT", script_name, context, body_root)


def watch_phase(phase_name: str, status: str, body_root: Path | None = None) -> None:
    watch_log("PHASE", phase_name, status, body_root)


def watch_gate(gate_name: str, result: str, body_root: Path | None = None) -> None:
    watch_log("GATE", gate_name, result, body_root)


def watch_danger(result: str, command: str, pattern: str = "", body_root: Path | None = None) -> None:
    if pattern:
        watch_log("DANGER", f"{result}: {command}", f"pattern: {pattern}", body_root)
    else:
        watch_log("DANGER", f"{result}: {command}", "", body_root)


def watch_skill(skill_name: str, args: str = "", body_root: Path | None = None) -> None:
    watch_log("SKILL", skill_name, args, body_root)


def watch_artifact(artifact_type: str, source: str, body_root: Path | None = None) -> None:
    watch_log("ARTIFACT", artifact_type, source, body_root)


def watch_token(token_name: str, result: str, body_root: Path | None = None) -> None:
    watch_log("TOKEN", token_name, result, body_root)


def watch_approval(action: str, context: str = "", body_root: Path | None = None) -> None:
    watch_log("APPROVAL", action, context, body_root)


def watch_harvest(operation: str, source: str, body_root: Path | None = None) -> None:
    watch_log("HARVEST", operation, source, body_root)


def watch_error(operation: str, error_message: str = "", body_root: Path | None = None) -> None:
    watch_log("ERROR", operation, error_message, body_root)


def watch_warn(operation: str, warning_message: str = "", body_root: Path | None = None) -> None:
    watch_log("WARN", operation, warning_message, body_root)


def watch_info(operation: str, info_message: str = "", body_root: Path | None = None) -> None:
    watch_log("INFO", operation, info_message, body_root)


def watch_log_path(body_root: Path | None = None) -> Path:
    """Return current watch log path."""
    return _watch_log_file(body_root)


def watch_has_logs(body_root: Path | None = None) -> bool:
    """Return ``True`` when watch log exists and contains data."""
    log_file = _watch_log_file(body_root)
    return log_file.is_file() and log_file.stat().st_size > 0


def watch_tail(lines: int = 20, body_root: Path | None = None) -> str:
    """Return the last ``lines`` entries from watch log."""
    log_file = _watch_log_file(body_root)
    if not log_file.is_file():
        return f"No watch log found at {log_file}"

    content = _read_text(log_file).splitlines()
    return "\n".join(content[-max(lines, 1) :])


def _show_help() -> None:
    print(
        "watch.py\n\n"
        "Usage:\n"
        "  watch.py --init\n"
        "  watch.py --log <CATEGORY> <operation> [context]\n"
        "  watch.py --tail [lines]\n"
        "  watch.py --enabled\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        _show_help()
        return 0

    if args[0] == "--init":
        watch_init()
        return 0

    if args[0] == "--log" and len(args) >= 3:
        context = " ".join(args[3:]) if len(args) > 3 else ""
        watch_log(args[1], args[2], context)
        return 0

    if args[0] == "--tail":
        lines = int(args[1]) if len(args) >= 2 and args[1].isdigit() else 20
        print(watch_tail(lines))
        return 0

    if args[0] == "--enabled":
        print("1" if watch_enabled(use_cache=False) else "0")
        return 0

    print("Invalid arguments", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
