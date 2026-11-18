#!/usr/bin/env python3
"""Kill-switch state helpers for runtime governance."""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


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


def _log(body_root: Path, message: str) -> None:
    try:
        log_file = body_root / ".bra" / "logs" / "killswitch.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(f"[{_utc_now()}] [KILLSWITCH] {message}\n")
    except OSError:
        pass


def _extract_killswitch_code_block(text: str) -> str:
    section_match = re.search(r"##\s*Kill\s*Switch(?P<section>.*?)(?:\n##\s|\Z)", text, re.IGNORECASE | re.DOTALL)
    if not section_match:
        return ""
    section = section_match.group("section")
    code_match = re.search(r"```(?:\w+)?\s*(?P<code>.*?)```", section, re.DOTALL)
    return code_match.group("code") if code_match else ""


def _detect_killswitch(body_root: Path | None = None) -> tuple[bool, str]:
    """Return ``(active, reason)`` for current kill-switch state."""
    root = _detect_body_root() if body_root is None else body_root

    if os.environ.get("BRA_STOP") == "1":
        return True, "Environment variable BRA_STOP=1"

    claude_path = root / "CLAUDE.md"
    if claude_path.is_file():
        try:
            text = claude_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            text = ""
        code_block = _extract_killswitch_code_block(text)
        if re.search(r"^\s*STOP\s*$", code_block, re.MULTILINE):
            return True, "CLAUDE.md Kill Switch section contains STOP"

    stop_file = root / ".bra" / "STOP"
    if stop_file.is_file():
        return True, f"Stop file exists: {stop_file}"

    return False, ""


def killswitch_reset_cache() -> None:
    """Compatibility no-op; checks are always fresh."""


def is_killswitch_active(body_root: Path | None = None) -> bool:
    """Return ``True`` when kill switch is active."""
    active, _ = _detect_killswitch(body_root)
    return active


def check_killswitch(body_root: Path | None = None) -> None:
    """Raise ``SystemExit(99)`` if kill switch is active."""
    root = _detect_body_root() if body_root is None else body_root
    active, reason = _detect_killswitch(root)
    if not active:
        return

    _log(root, f"HALT triggered: {reason}")

    print()
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║                    KILL SWITCH ACTIVATED                      ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    print()
    print(f"Reason: {reason}")
    print()
    print("All operations have been halted.")
    print()
    print("To resume operations:")
    print("  1. Remove STOP from CLAUDE.md Kill Switch section")
    print("  2. Or: unset BRA_STOP environment variable")
    print("  3. Or: rm .bra/STOP")
    print()

    raise SystemExit(99)


def get_killswitch_status(body_root: Path | None = None) -> str:
    """Return ``ACTIVE`` or ``INACTIVE``."""
    return "ACTIVE" if is_killswitch_active(body_root) else "INACTIVE"


def activate_killswitch(reason: str = "Manual activation", body_root: Path | None = None) -> Path:
    """Create stop marker file and return path."""
    root = _detect_body_root() if body_root is None else body_root
    stop_file = root / ".bra" / "STOP"
    stop_file.parent.mkdir(parents=True, exist_ok=True)
    stop_file.write_text(f"Kill switch activated: {reason}\nTimestamp: {_utc_now()}\n", encoding="utf-8")
    _log(root, f"Activated: {reason}")
    print(f"Kill switch ACTIVATED: {reason}")
    return stop_file


def deactivate_killswitch(body_root: Path | None = None) -> bool:
    """Remove stop marker file if it exists."""
    root = _detect_body_root() if body_root is None else body_root
    stop_file = root / ".bra" / "STOP"
    try:
        stop_file.unlink()
    except FileNotFoundError:
        print("No stop file to remove")
        if os.environ.get("BRA_STOP") == "1":
            print("Warning: BRA_STOP environment variable still set")
        return True
    _log(root, "Deactivated (stop file removed)")
    print("Kill switch deactivated (stop file removed)")
    if os.environ.get("BRA_STOP") == "1":
        print("Warning: BRA_STOP environment variable still set")
    return True


def _show_help() -> None:
    print(
        "killswitch.py\n\n"
        "Usage:\n"
        "  killswitch.py --status\n"
        "  killswitch.py --check\n"
        "  killswitch.py --activate [reason]\n"
        "  killswitch.py --deactivate\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        _show_help()
        return 0

    if args[0] == "--status":
        print(get_killswitch_status())
        return 0

    if args[0] == "--check":
        try:
            check_killswitch()
        except SystemExit as exc:
            return int(exc.code) if isinstance(exc.code, int) else 99
        return 0

    if args[0] == "--activate":
        reason = " ".join(args[1:]).strip() or "Manual activation"
        activate_killswitch(reason=reason)
        return 0

    if args[0] == "--deactivate":
        return 0 if deactivate_killswitch() else 1

    print(f"Unknown option: {args[0]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
