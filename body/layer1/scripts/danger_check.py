#!/usr/bin/env python3
"""danger_check.py - Native command danger gate.

Exit codes:
  0 - Safe (command does not match any dangerous patterns)
  1 - Blocked (dangerous command, no approval token)
  2 - Approved-Dangerous (dangerous but token present)

Token sources (checked in order):
  1. Environment variable: DESTRUCTIVE_APPROVAL=1
  2. Approval file: .bra/approvals/DESTRUCTIVE-APPROVAL
  3. ROE.md marker: Contains "DESTRUCTIVE-APPROVAL: GRANTED"
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = PROJECT_ROOT / ".bra" / "logs"
LOG_FILE = LOG_DIR / "danger_check.log"
APPROVALS_DIR = PROJECT_ROOT / ".bra" / "approvals"

# ============== CALLER VALIDATION ==============
# Prevent direct script execution bypass - must be called via bash-guard hook
# or with DANGER_CHECK_DIRECT=1 for testing
_ALLOWED_CALLERS = {"bash-guard.py", "bash-guard.sh", "battlestations.py",
                    "battlestations.sh", "agentic-handler.py", "agentic-handler.sh"}

try:
    lib_dir = str(PROJECT_ROOT / "layer1" / "lib")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)
    from track import track_cmd, track_danger, track_warn  # type: ignore
    from watch import watch_cmd, watch_danger  # type: ignore
except Exception:  # pragma: no cover - parity fallback
    def watch_cmd(*_args: object, **_kwargs: object) -> None:
        return None

    def watch_danger(*_args: object, **_kwargs: object) -> None:
        return None

    def track_cmd(*_args: object, **_kwargs: object) -> None:
        return None

    def track_danger(*_args: object, **_kwargs: object) -> None:
        return None

    def track_warn(*_args: object, **_kwargs: object) -> None:
        return None


def _validate_caller() -> bool:
    """Check if called from an allowed caller. Returns True if allowed."""
    caller = os.environ.get("_BRA_CALLER", "")
    if caller and any(name in caller for name in _ALLOWED_CALLERS):
        return True
    if os.environ.get("DANGER_CHECK_DIRECT") == "1":
        return True
    return False

DANGEROUS_PATTERNS = [
    r"(^|;|&&|\|\||&)[\s]*rm[\s]+-[rf]",
    r"(^|;|&&|\|\||&)[\s]*rm[\s]+--recursive",
    r"(^|;|&&|\|\||&)[\s]*rm[\s]+--force",
    r"rmdir[\s]+-p",
    r"find[\s].*-delete",
    r"find[\s].*-exec[\s]+rm",
    r"xargs[\s].*rm",
    r"(^|;|&&|\|\||&)[\s]*dd[\s]+if=",
    r"(^|;|&&|\|\||&)[\s]*dd[\s]+of=/dev/",
    r"(^|;|&&|\|\||&)[\s]*mkfs",
    r"(^|;|&&|\|\||&)[\s]*format[\s]",
    r"(^|;|&&|\|\||&)[\s]*fdisk",
    r"(^|;|&&|\|\||&)[\s]*parted",
    r"(^|;|&&|\|\||&)[\s]*shred",
    r"(^|;|&&|\|\||&)[\s]*wipefs",
    r">[\s]*/dev/sd",
    r">[\s]*/dev/nvme",
    r">[\s]*/dev/hd",
    r"cat[\s]+/dev/zero[\s]*>",
    r"cat[\s]+/dev/urandom[\s]*>",
    r":\(\)[\s]*\{.*:\|:.*\}",
    r"while[\s]+(true|1|:)[\s]*(;|do)",
    r"chmod[\s]+(-R[\s]+)?[0-7]*7[0-7]*[0-7]*[\s]+-R",
    r"chmod[\s]+-R[\s]+[0-7]*7[0-7]*[0-7]*",
    r"chmod[\s]+(777|o\+w)",
    r"chown[\s]+-R[\s]+root",
    r"(^|;|&&|\|\||&)[\s]*nmap[\s]+-s[SUAFX]",
    r"(^|;|&&|\|\||&)[\s]*masscan",
    r"(^|;|&&|\|\||&)[\s]*hping3?",
    r"(^|;|&&|\|\||&)[\s]*ettercap",
    r"(^|;|&&|\|\||&)[\s]*arpspoof",
    r"(^|;|&&|\|\||&)[\s]*bettercap",
    r"sudo[\s]+su[\s]+",
    r"sudo[\s]+(bash|sh|zsh|fish)",
    r"sudo[\s]+.*[\s]+-c[\s]",
    r"(curl|wget).*\|[\s]*(sh|bash|zsh|perl|ruby)($|[\s])",
    r"(curl|wget).*\|[\s]*python([0-9.]*)?([\s]*$|[\s]+-c([\s]|$)|[\s]+-([\s]|$))",
    r"(curl|wget).*-o[\s]+[^\s]+[\s]*&&[\s]*chmod[\s]+\+x",
    r"bash[\s]+-c[\s]+.*\$(curl|wget)",
    r"nc[\s]+-[elp]",
    r"nc[\s]+.*<",
    r"curl[\s]+.*(-d|--data)[\s]+@",
    r"scp[\s]+.*:/",
    r"git[\s]+push[\s]+.*(-f|--force)",
    r"git[\s]+reset[\s]+--hard",
    r"git[\s]+clean[\s]+-[fd]",
    r"git[\s]+checkout[\s]+\.",
    r"git[\s]+restore[\s]+\.",
    r"docker[\s]+run[\s]+.*--privileged",
    r"docker[\s]+run[\s]+.*-v[\s]+/:/host",
    r"(^|;|&&|\|\||&)[\s]*nsenter",
    r"(password|passwd|secret|api.?key|token)[\s]*=[\s]*['\"][^'\"]+['\"]",
]

SYSTEM_INSTALL_PATTERNS = [
    r"sudo[\s]+(apt|apt-get)[\s]+(install|remove|purge)",
    r"sudo[\s]+(yum|dnf)[\s]+(install|remove|erase)",
    r"sudo[\s]+pacman[\s]+-S",
    r"sudo[\s]+pip3?[\s]+install",
    r"sudo[\s]+npm[\s]+install[\s]+-g",
    r"sudo[\s]+gem[\s]+install",
]

USER_INSTALL_PATTERNS = [
    r"brew[\s]+install",
    r"pip3?[\s]+install[\s]+--user",
    r"npm[\s]+install[\s]+-g",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def init_logging() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)


def log(level: str, message: str) -> None:
    try:
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"[{_utc_now()}] [{level}] {message}\n")
    except OSError:
        return


def match_pattern(command: str, patterns: Iterable[str]) -> str | None:
    for pattern in patterns:
        if re.search(pattern, command):
            return pattern
    return None


def has_marker(path: Path, pattern: str) -> bool:
    if not path.is_file():
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return re.search(pattern, content, flags=re.IGNORECASE) is not None


def has_approval_token() -> bool:
    if os.environ.get("DESTRUCTIVE_APPROVAL") == "1":
        log("INFO", "Token found: environment variable DESTRUCTIVE_APPROVAL")
        return True
    approval_file = APPROVALS_DIR / "DESTRUCTIVE-APPROVAL"
    if approval_file.is_file():
        log("INFO", f"Token found: approval file {approval_file}")
        return True
    if has_marker(PROJECT_ROOT / "layer3-engagement" / "ROE.md", r"DESTRUCTIVE-APPROVAL:\s*GRANTED"):
        log("INFO", "Token found: ROE.md marker")
        return True
    if has_marker(PROJECT_ROOT / "layer1" / "rules" / "roe.md", r"DESTRUCTIVE-APPROVAL:\s*GRANTED"):
        log("INFO", "Token found: layer1/rules/roe.md marker")
        return True
    return False


def has_push_token() -> bool:
    if os.environ.get("PUSH_APPROVAL") == "1":
        return True
    if (APPROVALS_DIR / "PUSH-APPROVAL").is_file():
        return True
    return has_marker(PROJECT_ROOT / "layer3-engagement" / "ROE.md", r"PUSH-APPROVAL:\s*GRANTED")


def has_system_install_token() -> bool:
    if os.environ.get("SYSTEM_INSTALL_APPROVAL") == "1":
        return True
    if (APPROVALS_DIR / "SYSTEM-INSTALL-APPROVAL").is_file():
        return True
    return has_marker(PROJECT_ROOT / "layer3-engagement" / "ROE.md", r"SYSTEM-INSTALL-APPROVAL:\s*GRANTED")


def is_venv_install(command: str) -> bool:
    pip_install = re.search(r"pip3?[\s]+install", command) is not None
    pip_user = "--user" in command
    pip_sudo = "sudo" in command
    if pip_install and not pip_user and not pip_sudo and os.environ.get("VIRTUAL_ENV"):
        return True
    npm_install = re.search(r"npm[\s]+install", command) is not None
    if npm_install and "-g" not in command and "--global" not in command:
        return True
    return False


def _check_killswitch() -> bool:
    """Check kill switch. Returns True if active (should halt)."""
    lib_dir = str(PROJECT_ROOT / "layer1" / "lib")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)
    try:
        import killswitch
        return killswitch.is_killswitch_active(PROJECT_ROOT)
    except (ImportError, Exception):
        return False


def check_command(command: str) -> int:
    if is_venv_install(command):
        log("INFO", "Package install in venv/project-local - ALLOWED")
        print("[INFO] Package install in venv/project-local - ALLOWED", file=sys.stderr)
        watch_cmd(command, "safe", PROJECT_ROOT)
        track_cmd(command, "Command validated as safe", "Virtualenv/project-local install", PROJECT_ROOT)
        return 0

    user_pattern = match_pattern(command, USER_INSTALL_PATTERNS)
    if user_pattern and "sudo" not in command:
        log("WARN", "User-space package installation detected")
        print("[WARN] User-space package installation detected", file=sys.stderr)
        print(f"[WARN] Pattern: {user_pattern}", file=sys.stderr)
        print(f"[WARN] Command: {command}", file=sys.stderr)
        watch_danger("WARNING", command, user_pattern, PROJECT_ROOT)
        track_warn(command, "User-space installation - allowed with warning", f"Pattern: {user_pattern}", PROJECT_ROOT)
        return 0

    system_pattern = match_pattern(command, SYSTEM_INSTALL_PATTERNS)
    if system_pattern:
        log("WARN", f"System-wide installation detected: {system_pattern}")
        if has_system_install_token():
            log("APPROVED", "System-wide install ALLOWED (SYSTEM-INSTALL-APPROVAL token present)")
            print("[APPROVED] System-wide install ALLOWED (SYSTEM-INSTALL-APPROVAL token present)", file=sys.stderr)
            watch_danger("APPROVED", command, system_pattern, PROJECT_ROOT)
            track_danger("APPROVED", command, "SYSTEM-INSTALL-APPROVAL token present", system_pattern, PROJECT_ROOT)
            return 2
        log("BLOCKED", "System-wide install BLOCKED (no SYSTEM-INSTALL-APPROVAL token)")
        print("[BLOCKED] System-wide install BLOCKED (no SYSTEM-INSTALL-APPROVAL token)", file=sys.stderr)
        print(f"[BLOCKED] Command: {command}", file=sys.stderr)
        watch_danger("BLOCKED", command, system_pattern, PROJECT_ROOT)
        track_danger("BLOCKED", command, "No SYSTEM-INSTALL-APPROVAL token", system_pattern, PROJECT_ROOT)
        print("", file=sys.stderr)
        print("System-wide installation requires SYSTEM-INSTALL-APPROVAL token.", file=sys.stderr)
        print("", file=sys.stderr)
        print("To approve, provide token via:", file=sys.stderr)
        print("  1. Environment: SYSTEM_INSTALL_APPROVAL=1", file=sys.stderr)
        print("  2. File: touch .bra/approvals/SYSTEM-INSTALL-APPROVAL", file=sys.stderr)
        print("  3. ROE.md: Add 'SYSTEM-INSTALL-APPROVAL: GRANTED'", file=sys.stderr)
        return 1

    if re.search(r"git[\s]+push", command):
        if has_push_token():
            log("APPROVED", "Git push ALLOWED (PUSH-APPROVAL token present)")
            print("[APPROVED] Git push ALLOWED (PUSH-APPROVAL token present)", file=sys.stderr)
            watch_danger("APPROVED", command, "git push", PROJECT_ROOT)
            return 2
        log("BLOCKED", "Git push BLOCKED (no PUSH-APPROVAL token)")
        print("[BLOCKED] Git push BLOCKED (no PUSH-APPROVAL token)", file=sys.stderr)
        print(f"[BLOCKED] Command: {command}", file=sys.stderr)
        watch_danger("BLOCKED", command, "git push", PROJECT_ROOT)
        print("", file=sys.stderr)
        print("Git push requires PUSH-APPROVAL token.", file=sys.stderr)
        print("", file=sys.stderr)
        print("To approve, provide token via:", file=sys.stderr)
        print("  1. Environment: PUSH_APPROVAL=1", file=sys.stderr)
        print("  2. File: touch .bra/approvals/PUSH-APPROVAL", file=sys.stderr)
        print("  3. ROE.md: Add 'PUSH-APPROVAL: GRANTED'", file=sys.stderr)
        return 1

    dangerous_pattern = match_pattern(command, DANGEROUS_PATTERNS)
    if dangerous_pattern:
        log("WARN", f"Dangerous pattern matched: {dangerous_pattern}")
        if has_approval_token():
            log("APPROVED", "Dangerous command ALLOWED (token present)")
            print("[APPROVED] Dangerous command ALLOWED (token present)", file=sys.stderr)
            print(f"[APPROVED] Pattern: {dangerous_pattern}", file=sys.stderr)
            print(f"[APPROVED] Command: {command}", file=sys.stderr)
            watch_danger("APPROVED", command, dangerous_pattern, PROJECT_ROOT)
            track_danger("APPROVED", command, "DESTRUCTIVE-APPROVAL token present - dangerous command permitted", dangerous_pattern, PROJECT_ROOT)
            return 2
        log("BLOCKED", "Dangerous command BLOCKED (no token)")
        print("[BLOCKED] Dangerous command BLOCKED (no token)", file=sys.stderr)
        print(f"[BLOCKED] Pattern: {dangerous_pattern}", file=sys.stderr)
        print(f"[BLOCKED] Command: {command}", file=sys.stderr)
        watch_danger("BLOCKED", command, dangerous_pattern, PROJECT_ROOT)
        track_danger("BLOCKED", command, "No DESTRUCTIVE-APPROVAL token - dangerous command rejected", dangerous_pattern, PROJECT_ROOT)
        print("", file=sys.stderr)
        # Hint for curl|python pattern
        if "curl|wget" in dangerous_pattern and "python" in dangerous_pattern:
            print("HINT: Piping download output to python is blocked (download-and-execute pattern).", file=sys.stderr)
            print("  Preferred alternatives (allowlisted, no approval needed):", file=sys.stderr)
            print("    1. Use jq for JSON parsing:  curl ... -o file.json && jq '.key' file.json", file=sys.stderr)
            print("    2. Save then parse:          curl ... -o file.json && python3 file.json", file=sys.stderr)
            print("    3. Use python -m json.tool:  curl ... | python3 -m json.tool", file=sys.stderr)
            print("", file=sys.stderr)
        print("To approve, provide token via:", file=sys.stderr)
        print("  1. Environment: DESTRUCTIVE_APPROVAL=1", file=sys.stderr)
        print("  2. File: touch .bra/approvals/DESTRUCTIVE-APPROVAL", file=sys.stderr)
        print("  3. ROE.md: Add 'DESTRUCTIVE-APPROVAL: GRANTED'", file=sys.stderr)
        return 1

    log("INFO", "Command OK (safe)")
    watch_cmd(command, "safe", PROJECT_ROOT)
    track_cmd(command, "Command validated as safe", "No dangerous patterns matched", PROJECT_ROOT)
    return 0


def show_help() -> None:
    print("""\
danger_check.py — Destructive Command Blocker

USAGE:
    danger_check.py <command>           Check if command is safe
    danger_check.py --help              Show this help
    danger_check.py --list-patterns     List all dangerous patterns

DESCRIPTION:
    Validates commands against a pattern library of dangerous operations.
    Commands matching dangerous patterns require DESTRUCTIVE-APPROVAL token.

EXIT CODES:
    0 - Safe: Command does not match any dangerous patterns
    1 - Blocked: Dangerous command detected, no approval token present
    2 - Approved-Dangerous: Dangerous command allowed via approval token

TOKEN SOURCES (checked in order):
    1. Environment variable: DESTRUCTIVE_APPROVAL=1
    2. Approval file: .bra/approvals/DESTRUCTIVE-APPROVAL
    3. ROE.md marker: "DESTRUCTIVE-APPROVAL: GRANTED"

EXAMPLES:
    # Check a safe command
    ./layer1/scripts/danger_check.py "ls -la /tmp"
    # Exit: 0 (Safe)

    # Check a dangerous command (blocked)
    ./layer1/scripts/danger_check.py "rm -rf /"
    # Exit: 1 (Blocked)

    # Allow dangerous command with token
    DESTRUCTIVE_APPROVAL=1 ./layer1/scripts/danger_check.py "rm -rf /tmp/test"
    # Exit: 2 (Approved-Dangerous)

REFERENCED BY:
    - CLAUDE.md (Kill-Switch Protocol)
""")


def list_patterns() -> None:
    print("Dangerous Command Patterns:")
    print("============================")
    for idx, pattern in enumerate(DANGEROUS_PATTERNS, start=1):
        print(f"{idx:3d}. {pattern}")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    init_logging()

    if _check_killswitch():
        log("BLOCKED", "Kill switch ACTIVE — halting danger check")
        print("Kill switch is ACTIVE. All operations halted.", file=sys.stderr)
        return 99

    if not args or args[0] in {"--help", "-h"}:
        show_help()
        return 0
    if args[0] == "--list-patterns":
        list_patterns()
        return 0

    # Caller validation — block direct execution bypass
    if not _validate_caller():
        log("BLOCKED", f"Direct call blocked (caller: {os.environ.get('_BRA_CALLER', 'unknown')})")
        caller = os.environ.get("_BRA_CALLER", "unknown")
        print("", file=sys.stderr)
        print("ERROR: danger_check.py must be called via bash-guard hook", file=sys.stderr)
        print("Direct script execution is blocked to prevent governance bypass.", file=sys.stderr)
        print(f"Called from: {caller}", file=sys.stderr)
        print("", file=sys.stderr)
        print("If you need to test danger_check.py directly:", file=sys.stderr)
        print('  DANGER_CHECK_DIRECT=1 python3 layer1/scripts/danger_check.py "command"', file=sys.stderr)
        return 1

    command = " ".join(args).strip()
    log("INFO", f"Checking command: {command}")
    return check_command(command)


if __name__ == "__main__":
    raise SystemExit(main())
