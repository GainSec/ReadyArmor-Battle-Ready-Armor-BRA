#!/usr/bin/env python3
"""Active testing approval and activity classification helpers."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

NETWORK_ACTIVITY_PATTERNS: tuple[str, ...] = (
    r"\bnmap\b",
    r"\bmasscan\b",
    r"\bzmap\b",
    r"\brustscan\b",
    r"\bunicornscan\b",
    r"\bwfuzz\s+-u\s+https?://",
    r"\bffuf\s+-u\s+https?://",
    r"\bgobuster\s+(dir|dns|vhost)\b",
    r"\bferoxbuster\b",
    r"\bdirsearch\b",
    r"\bnikto\b",
    r"\bmetasploit\b",
    r"\bmsf(console|venom)?\b",
    r"\bsqlmap\b",
    r"\bcommix\b",
    r"\bbeef-xss\b",
    r"\bbettercap\b",
    r"\bhping3?\b",
    r"\bettercap\b",
    r"\barpspoof\b",
    r"\bresponder\b",
    r"\bmitm\b",
    r"\breverse\s+shell\b",
    r"\bbind\s+shell\b",
    r"\bnc\s+-[elp]\b",
    r"\b(sulley|peach|spike|boofuzz)\b",
)

STATIC_ANALYSIS_PATTERNS: tuple[str, ...] = (
    r"\bghidra\b",
    r"\bradare2?\b",
    r"\bida(64|t)?\b",
    r"\bhopper\b",
    r"\bcutter\b",
    r"\bobjdump\b",
    r"\bstrings\b",
    r"\breadelf\b",
    r"\bnm\b",
    r"\bsemgrep\b",
    r"\bcodeql\b",
    r"\bbandit\b",
    r"\bflawfinder\b",
    r"\bbrakeman\b",
    r"\beslint\b",
    r"\bpylint\b",
    r"\bshellcheck\b",
    r"\bbinwalk\b",
    r"\bfile\b",
    r"\bhexdump\b",
    r"\bxxd\b",
    r"\bobjcopy\b",
    r"\bafl-fuzz\b",
    r"\blibfuzzer\b",
    r"\bhonggfuzz\b",
    r"\bzzuf\b",
    r"\bradamsa\b",
)

LOCALHOST_PATTERNS: tuple[str, ...] = (
    r"127\.0\.0\.1",
    r"localhost",
    r"0\.0\.0\.0",
    r"::1",
)

_ACTIVE_CACHE: bool | None = None


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
    return body_root / ".bra" / "approvals" / "ACTIVE-TESTING-APPROVAL"


def _has_roe_marker(text: str) -> bool:
    table_match = re.search(r"^\|\s*ACTIVE-TESTING-APPROVAL\s*\|\s*Set\b", text, re.IGNORECASE | re.MULTILINE)
    key_value_match = re.search(r"ACTIVE-TESTING-APPROVAL\s*:\s*(GRANTED|SET|ENABLED)", text, re.IGNORECASE)
    return bool(table_match or key_value_match)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def check_active_approval(body_root: Path | None = None, *, use_cache: bool = True) -> bool:
    """Return ``True`` when active testing is approved."""
    global _ACTIVE_CACHE

    if use_cache and _ACTIVE_CACHE is not None:
        return _ACTIVE_CACHE

    root = _detect_body_root() if body_root is None else body_root
    approved = False

    if os.environ.get("ACTIVE_TESTING_APPROVAL") == "1":
        approved = True
    elif _approval_file(root).is_file():
        approved = True
    else:
        roe_files = [root / "layer3-engagement" / "ROE.md", root / "layer1" / "rules" / "roe.md"]
        approved = any(_has_roe_marker(_read_text(path)) for path in roe_files if path.is_file())

    if use_cache:
        _ACTIVE_CACHE = approved
    return approved


def active_reset_cache() -> None:
    """Clear the in-process approval cache."""
    global _ACTIVE_CACHE
    _ACTIVE_CACHE = None


def get_active_scope_setting(body_root: Path | None = None) -> str:
    """Get scope policy for active testing: ``YES``, ``NO``, or ``ASK``."""
    root = _detect_body_root() if body_root is None else body_root
    candidates = [root / "layer3-engagement" / "SCOPE.md", root / "layer3-engagement" / "ROE.md"]
    text = "\n".join(_read_text(path) for path in candidates if path.is_file())

    marker = re.search(r"ACTIVE[-_ ]TESTING[-_ ]APPROVAL\s*:\s*([A-Za-z_-]+)", text, re.IGNORECASE)
    raw_value = marker.group(1).upper() if marker else ""

    if raw_value in {"YES", "APPROVED", "ALLOW", "ALLOWED", "GRANTED", "TRUE", "1", "SET"}:
        return "YES"
    if raw_value in {"NO", "DENIED", "DENY", "BLOCKED", "FALSE", "0"}:
        return "NO"
    if raw_value in {"ASK", "PROMPT"}:
        return "ASK"
    return "ASK"


def _match_pattern(command: str, patterns: tuple[str, ...]) -> str | None:
    for pattern in patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return pattern
    return None


def is_localhost_target(command: str) -> bool:
    """Return ``True`` when command targets loopback/local-only endpoints."""
    return _match_pattern(command, LOCALHOST_PATTERNS) is not None


def is_static_activity(command: str) -> bool:
    """Return ``True`` for static or local analysis commands."""
    return _match_pattern(command, STATIC_ANALYSIS_PATTERNS) is not None


def is_network_activity(command: str) -> bool:
    """Return ``True`` for network-active commands against non-local targets."""
    return not is_localhost_target(command) and _match_pattern(command, NETWORK_ACTIVITY_PATTERNS) is not None


def get_network_pattern(command: str) -> str | None:
    """Return the matched network-activity regex pattern."""
    if is_localhost_target(command):
        return None
    return _match_pattern(command, NETWORK_ACTIVITY_PATTERNS)


def get_static_pattern(command: str) -> str | None:
    """Return the matched static-activity regex pattern."""
    return _match_pattern(command, STATIC_ANALYSIS_PATTERNS)


def set_active_approval(body_root: Path | None = None, *, reason: str = "Set via active_check.py") -> Path:
    """Create approval marker file and return its path."""
    root = _detect_body_root() if body_root is None else body_root
    token_file = _approval_file(root)
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(f"Token: ACTIVE-TESTING-APPROVAL\nReason: {reason}\n", encoding="utf-8")
    active_reset_cache()
    return token_file


def unset_active_approval(body_root: Path | None = None) -> None:
    """Remove approval marker file if present."""
    root = _detect_body_root() if body_root is None else body_root
    try:
        _approval_file(root).unlink()
    except FileNotFoundError:
        pass
    active_reset_cache()


def list_network_patterns() -> list[str]:
    """Return all network-activity patterns."""
    patterns = list(NETWORK_ACTIVITY_PATTERNS)
    print("Network-Based Activity Patterns (require approval):")
    print("====================================================")
    for index, pattern in enumerate(patterns, start=1):
        print(f"{index:3d}. {pattern}")
    return patterns


def list_static_patterns() -> list[str]:
    """Return all static-activity patterns."""
    patterns = list(STATIC_ANALYSIS_PATTERNS)
    print("Static Analysis Patterns (always allowed):")
    print("===========================================")
    for index, pattern in enumerate(patterns, start=1):
        print(f"{index:3d}. {pattern}")
    return patterns


def active_token_path(body_root: Path | None = None) -> Path:
    """Return the absolute path of the approval marker file."""
    root = _detect_body_root() if body_root is None else body_root
    return _approval_file(root)


def _show_help() -> None:
    print(
        "active_check.py\n\n"
        "Usage:\n"
        "  active_check.py --check\n"
        "  active_check.py --scope\n"
        "  active_check.py --classify <command...>\n"
        "  active_check.py --set [reason]\n"
        "  active_check.py --unset\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        _show_help()
        return 0

    if args[0] == "--check":
        return 0 if check_active_approval() else 1
    if args[0] == "--scope":
        print(get_active_scope_setting())
        return 0
    if args[0] == "--set":
        reason = " ".join(args[1:]).strip() or "Set via CLI"
        print(set_active_approval(reason=reason))
        return 0
    if args[0] == "--unset":
        unset_active_approval()
        return 0
    if args[0] == "--classify":
        command = " ".join(args[1:]).strip()
        if not command:
            print("Missing command to classify", file=sys.stderr)
            return 2
        if is_static_activity(command):
            print("STATIC")
            return 0
        if is_network_activity(command):
            print("NETWORK")
            return 0
        print("UNKNOWN")
        return 0

    print(f"Unknown option: {args[0]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
