#!/usr/bin/env python3
"""tokens.py ── Centralized Token Checking Library

Purpose: Provide unified token checking for all governance tokens
Invariant: Token checks are consistent across all scripts

Usage:
    from layer1.lib.tokens import has_token, require_token, set_token, unset_token, list_tokens

    has_token("DESTRUCTIVE-APPROVAL")     # Check if a token is set
    require_token("PUSH-APPROVAL")        # Check and raise if not set
    set_token("WATCH")                    # Set a token
    unset_token("TRACK")                  # Unset a token
    list_tokens()                         # List all token states

Supported Tokens:
    ● DESTRUCTIVE-APPROVAL: Required for destructive file/git operations
    ● ACTIVE-TESTING-APPROVAL: Required for network-based testing (port scanning, fuzzing live targets)
    ● SYSTEM-INSTALL-APPROVAL: Required for system-wide package installations
    ● PUSH-APPROVAL: Required for git push operations
    ● WATCH: Enable human-readable audit logging
    ● TRACK: Enable comprehensive audit trail
    ● NEGATIVE-RESULTS: Document ruled-out tests
    ● IGNORE-BACKUP: Skip backup operations

Token Sources (checked in order):
    1. Environment variable (TOKEN_NAME with underscores instead of hyphens)
    2. Approval file: .bra/approvals/TOKEN-NAME
    3. ROE.md marker: "TOKEN-NAME: GRANTED" or "| TOKEN-NAME | Set |"

Referenced By:
    ● All operational scripts
    ● tokens.md (token catalog)
    ● CLAUDE.md (approval tokens section)
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

KNOWN_TOKENS: tuple[str, ...] = (
    # Governance gates
    "DESTRUCTIVE-APPROVAL",
    "TOOL-APPROVAL",
    "ACTIVE-TESTING-APPROVAL",
    "OFFENSIVE-TESTING-APPROVAL",
    "SYSTEM-INSTALL-APPROVAL",
    "PUSH-APPROVAL",
    "LAYER2-WRITE-APPROVAL",
    "FRAMEWORK-DEV-APPROVAL",
    "OVERRIDE-APPROVAL",
    "SCOPE-CONFIRMED",
    # Findings workflow
    "FINDINGS-FASTPATH",
    "SLOWPATH-FINDINGS",
    "FINDINGS-SELECTION",
    # Install scopes
    "USER-INSTALL",
    "VIRTUAL-INSTALL",
    # Observability & audit
    "WATCH",
    "TRACK",
    "BRA-DEBUG",
    "BRA_VERBOSE",
    "NO-TOKEN-TRACKING",
    "NEGATIVE-RESULTS",
    "HEALTH-BYPASS",
    "IGNORE-BACKUP",
    # 2x4 subsystem
    "2x4-ENABLED",
    "2x4-DEBUG",
    "2x4-UNRESTRICTED",
    "2x4-CONTROL",
    "2x4-TAKEOVER",
    "2x4-VOICE-CALL",
    # Anonymization layer
    "FRONTIER-SCOPE",
    "MICRO-SCOPE",
    "LOCAL-SCOPE",
    "DUMB-SCOPE",
    "NO-SCOPE",
    "MAP-SCAN",
    "ANON-SCAN",
    "LOCAL-SCAN",
    "NO-SCAN",
    "ANON-DISABLE",
)


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
        log_file = body_root / ".bra" / "logs" / "tokens.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(f"[{_utc_now()}] [TOKEN] {message}\n")
    except OSError:
        pass


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _token_to_env_var(token: str) -> str:
    """Convert token to environment variable name."""
    env_var = token.replace("-", "_").upper()
    if env_var and env_var[0].isdigit():
        env_var = f"TOKEN_{env_var}"
    return env_var


def has_token(token: str, body_root: Path | None = None) -> bool:
    """Return ``True`` if token is present in env, approval file, or ROE docs."""
    if not token:
        return False

    root = _detect_body_root() if body_root is None else body_root
    env_var = _token_to_env_var(token)

    if os.environ.get(env_var) == "1":
        _log(root, f"Token {token}: SET (env {env_var}=1)")
        return True

    token_file = root / ".bra" / "approvals" / token
    if token_file.is_file():
        _log(root, f"Token {token}: SET (approval file)")
        return True

    markers = [root / "layer3-engagement" / "ROE.md", root / "layer1" / "rules" / "roe.md"]
    for marker_file in markers:
        if not marker_file.is_file():
            continue
        text = _read_text(marker_file)
        kv_pattern = rf"{re.escape(token)}\s*:\s*(GRANTED|SET|ENABLED)"
        table_pattern = rf"^\|\s*{re.escape(token)}\s*\|\s*Set\b"
        if re.search(kv_pattern, text, re.IGNORECASE) or re.search(table_pattern, text, re.IGNORECASE | re.MULTILINE):
            _log(root, f"Token {token}: SET (ROE marker in {marker_file.name})")
            return True

    _log(root, f"Token {token}: NOT SET")
    return False


def require_token(token: str, message: str | None = None, body_root: Path | None = None) -> bool:
    """Return ``True`` when token is present, otherwise exit-style block."""
    if has_token(token, body_root=body_root):
        return True

    env_var = _token_to_env_var(token)
    reason = message or f"{token} token required for this operation"

    root = _detect_body_root() if body_root is None else body_root

    print("")
    print("╔════════════════════════════════════════════════════════════════╗")
    print(f"║                    TOKEN REQUIRED: {token}")
    print("╚════════════════════════════════════════════════════════════════╝")
    print("")
    print(reason)
    print("")
    print("To provide token, use ONE of:")
    print(f"  1. Environment: {env_var}=1 <command>")
    print(f"  2. File: touch .bra/approvals/{token}")
    print(f"  3. ROE.md: Add '{token}: GRANTED'")
    print("")

    _log(root, f"Token {token}: REQUIRED but not present - operation blocked")
    raise SystemExit(1)


def set_token(token: str, reason: str = "Set via tokens.py", body_root: Path | None = None) -> Path:
    """Create token approval file and return its path."""
    if not token:
        raise ValueError("token is required")

    root = _detect_body_root() if body_root is None else body_root
    token_file = root / ".bra" / "approvals" / token
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(
        f"Token: {token}\nSet at: {_utc_now()}\nReason: {reason}\n",
        encoding="utf-8",
    )
    _log(root, f"Token {token}: SET (reason={reason})")
    print(f"Token set: {token}")
    return token_file


def unset_token(token: str, body_root: Path | None = None) -> bool:
    """Remove token approval file if present."""
    root = _detect_body_root() if body_root is None else body_root
    token_file = root / ".bra" / "approvals" / token
    try:
        token_file.unlink()
    except FileNotFoundError:
        _log(root, f"Token {token}: UNSET requested but file missing")
        print(f"Token {token} was not set via approval file")
        return False
    _log(root, f"Token {token}: UNSET")
    print(f"Token unset: {token}")
    return True


def list_tokens(body_root: Path | None = None, *, include_extra: bool = True) -> dict[str, bool]:
    """Return known token states as ``{token: is_set}``."""
    root = _detect_body_root() if body_root is None else body_root
    token_names = set(KNOWN_TOKENS)

    if include_extra:
        approvals_dir = root / ".bra" / "approvals"
        if approvals_dir.is_dir():
            token_names.update(path.name for path in approvals_dir.iterdir() if path.is_file())

    return {token: has_token(token, body_root=root) for token in sorted(token_names)}


def token_path(token: str, body_root: Path | None = None) -> Path:
    """Return approval file path for ``token``."""
    root = _detect_body_root() if body_root is None else body_root
    return root / ".bra" / "approvals" / token


def has_destructive_approval(body_root: Path | None = None) -> bool:
    return has_token("DESTRUCTIVE-APPROVAL", body_root=body_root)


def has_active_approval(body_root: Path | None = None) -> bool:
    return has_token("ACTIVE-TESTING-APPROVAL", body_root=body_root)


def has_offensive_approval(body_root: Path | None = None) -> bool:
    return has_active_approval(body_root=body_root)


def has_push_approval(body_root: Path | None = None) -> bool:
    return has_token("PUSH-APPROVAL", body_root=body_root)


def require_push_approval(body_root: Path | None = None) -> bool:
    return require_token("PUSH-APPROVAL", "Git push operations require explicit PUSH-APPROVAL token", body_root)


def is_git_push(command: str) -> bool:
    """Return ``True`` if command resembles a git push action."""
    return bool(re.search(r"\bgit\s+push\b", command) or re.search(r"\bgh\s+pr\b.*--push\b", command))


def guard_git_push(command: str = "git push", body_root: Path | None = None) -> bool:
    """Return whether push is allowed for the given command."""
    if not is_git_push(command):
        return True
    if has_push_approval(body_root=body_root):
        root = _detect_body_root() if body_root is None else body_root
        _log(root, f"GIT PUSH ALLOWED: {command} (PUSH-APPROVAL token present)")
        return True

    root = _detect_body_root() if body_root is None else body_root

    print("")
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║                    GIT PUSH BLOCKED                            ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    print("")
    print("Git push operations require PUSH-APPROVAL token.")
    print("")
    print(f"Command blocked: {command}")
    print("")
    print("To approve, provide token via ONE of:")
    print(f"  1. Environment: PUSH_APPROVAL=1 {command}")
    print("  2. File: touch .bra/approvals/PUSH-APPROVAL")
    print("  3. ROE.md: Add 'PUSH-APPROVAL: GRANTED'")
    print("")

    _log(root, f"GIT PUSH BLOCKED: {command} (no PUSH-APPROVAL token)")
    return False


def _print_token_status(states: dict[str, bool]) -> None:
    print("")
    print("Token Status")
    print("============")
    print("")
    for token, is_set in states.items():
        if is_set:
            print(f"  [SET]     {token}")
        else:
            print(f"  [NOT SET] {token}")
    print("")


def _show_help() -> None:
    print(
        "tokens.py\n\n"
        "Usage:\n"
        "  tokens.py --list\n"
        "  tokens.py --check <TOKEN>\n"
        "  tokens.py --set <TOKEN> [reason]\n"
        "  tokens.py --unset <TOKEN>\n"
        "  tokens.py --guard-push <command...>\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        _show_help()
        return 0

    if args[0] == "--list":
        _print_token_status(list_tokens())
        return 0

    if args[0] == "--check" and len(args) >= 2:
        return 0 if has_token(args[1]) else 1

    if args[0] == "--set" and len(args) >= 2:
        reason = " ".join(args[2:]).strip() or "Set via CLI"
        set_token(args[1], reason=reason)
        return 0

    if args[0] == "--unset" and len(args) >= 2:
        unset_token(args[1])
        return 0

    if args[0] == "--guard-push":
        command = " ".join(args[1:]).strip()
        if not command:
            print("Missing command", file=sys.stderr)
            return 2
        return 0 if guard_git_push(command) else 1

    print("Invalid arguments", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
