#!/usr/bin/env python3
"""Offensive testing approval and command classification helpers."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

OFFENSIVE_PATTERNS: tuple[str, ...] = (
    r"\bradamsa\b",
    r"\bboofuzz\b",
    r"\bafl-fuzz\b",
    r"\blibfuzzer\b",
    r"\bhonggfuzz\b",
    r"\bzzuf\b",
    r"\bwfuzz\b",
    r"\bffuf\b",
    r"\bgobuster\b",
    r"\bmetasploit\b",
    r"\bmsf(console|venom)?\b",
    r"\bexploitdb\b",
    r"\bsearchsploit\b",
    r"\bpwntools\b",
    r"\bflashrom\b",
    r"\bopenocd\b",
    r"\bavrdude\b",
    r"\bstm32flash\b",
    r"\besptool\b",
    r"\bbinwalk\s+-e\b",
    r"\bfirmware-mod-kit\b",
    r"\bexploit/",
    r"--exploit\b",
    r"-x\s+exploit\b",
    r"payload/",
    r"\bshellcode\b",
    r"\breverse\s+shell\b",
    r"\bbind\s+shell\b",
    r"\bsqlmap\b",
    r"\bcommix\b",
    r"\bbeef-xss\b",
    r"\bbettercap\b",
    r"\b(sulley|peach|spike)\b",
)

_OFFENSIVE_CACHE: bool | None = None


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


def _approval_file(body_root: Path) -> Path:
    return body_root / ".bra" / "approvals" / "OFFENSIVE-TESTING-APPROVAL"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _has_roe_marker(text: str) -> bool:
    table_match = re.search(r"^\|\s*OFFENSIVE-TESTING-APPROVAL\s*\|\s*Set\b", text, re.IGNORECASE | re.MULTILINE)
    marker_match = re.search(r"OFFENSIVE-TESTING-APPROVAL\s*:\s*(GRANTED|SET|ENABLED)", text, re.IGNORECASE)
    return bool(table_match or marker_match)


def check_offensive_approval(body_root: Path | None = None, *, use_cache: bool = True) -> bool:
    """Return ``True`` when offensive testing is approved."""
    global _OFFENSIVE_CACHE

    if use_cache and _OFFENSIVE_CACHE is not None:
        return _OFFENSIVE_CACHE

    root = _detect_body_root() if body_root is None else body_root
    approved = False

    if os.environ.get("OFFENSIVE_TESTING_APPROVAL") == "1":
        approved = True
    elif _approval_file(root).is_file():
        approved = True
    else:
        roe_files = [root / "layer3-engagement" / "ROE.md", root / "layer1" / "rules" / "roe.md"]
        approved = any(_has_roe_marker(_read_text(path)) for path in roe_files if path.is_file())

    if use_cache:
        _OFFENSIVE_CACHE = approved
    return approved


def offensive_reset_cache() -> None:
    """Clear in-process offensive approval cache."""
    global _OFFENSIVE_CACHE
    _OFFENSIVE_CACHE = None


def get_offensive_scope_setting(body_root: Path | None = None) -> str:
    """Get scope policy for offensive testing: ``APPROVED``, ``DENIED``, ``PROMPT``."""
    root = _detect_body_root() if body_root is None else body_root
    candidates = [root / "layer3-engagement" / "SCOPE.md", root / "layer3-engagement" / "ROE.md"]
    text = "\n".join(_read_text(path) for path in candidates if path.is_file())

    marker = re.search(r"OFFENSIVE[-_ ]TESTING[-_ ]APPROVAL\s*:\s*([A-Za-z_-]+)", text, re.IGNORECASE)
    raw_value = marker.group(1).upper() if marker else ""

    if raw_value in {"APPROVED", "YES", "SET", "GRANTED", "ALLOW", "ALLOWED", "TRUE", "1"}:
        return "APPROVED"
    if raw_value in {"DENIED", "NO", "BLOCKED", "DENY", "FALSE", "0"}:
        return "DENIED"
    return "PROMPT"


def get_offensive_pattern(command: str) -> str | None:
    """Return matched offensive pattern for ``command``."""
    for pattern in OFFENSIVE_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return pattern
    return None


def is_offensive_activity(command: str) -> bool:
    """Return ``True`` when command maps to offensive testing behavior."""
    return get_offensive_pattern(command) is not None


def set_offensive_approval(body_root: Path | None = None, *, reason: str = "Set via offensive_check.py") -> Path:
    """Create offensive approval marker and return its path."""
    root = _detect_body_root() if body_root is None else body_root
    token_file = _approval_file(root)
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(f"Token: OFFENSIVE-TESTING-APPROVAL\nReason: {reason}\n", encoding="utf-8")
    offensive_reset_cache()
    return token_file


def unset_offensive_approval(body_root: Path | None = None) -> None:
    """Remove offensive approval marker file if present."""
    root = _detect_body_root() if body_root is None else body_root
    try:
        _approval_file(root).unlink()
    except FileNotFoundError:
        pass
    offensive_reset_cache()


def list_offensive_patterns() -> list[str]:
    """Print and return known offensive activity patterns."""
    print("Offensive Activity Patterns:")
    print("============================")
    for i, pattern in enumerate(OFFENSIVE_PATTERNS, start=1):
        print(f"{i:3d}. {pattern}")
    return list(OFFENSIVE_PATTERNS)


def offensive_token_path(body_root: Path | None = None) -> Path:
    """Return absolute path for the offensive approval token."""
    root = _detect_body_root() if body_root is None else body_root
    return _approval_file(root)


def _show_help() -> None:
    print(
        "offensive_check.py\n\n"
        "Usage:\n"
        "  offensive_check.py --check\n"
        "  offensive_check.py --scope\n"
        "  offensive_check.py --classify <command...>\n"
        "  offensive_check.py --set [reason]\n"
        "  offensive_check.py --unset\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        _show_help()
        return 0

    if args[0] == "--check":
        return 0 if check_offensive_approval() else 1
    if args[0] == "--scope":
        print(get_offensive_scope_setting())
        return 0
    if args[0] == "--set":
        reason = " ".join(args[1:]).strip() or "Set via CLI"
        print(set_offensive_approval(reason=reason))
        return 0
    if args[0] == "--unset":
        unset_offensive_approval()
        return 0
    if args[0] == "--classify":
        command = " ".join(args[1:]).strip()
        if not command:
            print("Missing command to classify", file=sys.stderr)
            return 2
        print("OFFENSIVE" if is_offensive_activity(command) else "NOT-OFFENSIVE")
        return 0

    print(f"Unknown option: {args[0]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
