"""Tool approval hook - MECHANICAL human-in-the-loop.

CRITICAL: This hook blocks tool executions until explicitly approved.
Low-risk built-in file/query tools are exempt because they are governed by
other BRA controls (file guard, scope checks, etc.).

ENFORCEMENT FLOW:
1. Tool execution attempt triggers PreToolUse hook
2. Hook checks for one-time approval file for this tool_use_id
3. If found: allows and consumes the approval
4. If not found: blocks with TOOL_APPROVAL_REQUIRED
5. TUI detects block, shows ToolApprovalModal
6. User approves → TUI creates approval file → agent retries
7. On retry, hook finds approval, allows, deletes file

This ensures non-exempt tools do not execute without explicit user approval.
"""

import hashlib
import json
import os
import re
import shlex
import time
from pathlib import Path
from typing import Any

from bra.hooks.types import (
    PreToolUseHookInput,
    HookContext,
    SyncHookJSONOutput,
)

from bra.config import settings
from bra.debug_log import write_debug_log


def _get_tool_approvals_dir() -> Path:
    """Dynamically resolve the one-time tool approvals directory.

    Uses settings.BRA_STATE (dynamic property) instead of a frozen
    module-level constant so that set_bra_root() changes are respected.
    """
    return settings.BRA_STATE / "one-time-approvals"

# Read/query tools are read-only and low-risk.
# Write/Edit are exempt because pre_file (file-guard) enforces all write
# governance independently — exempting here avoids a double-prompt while
# maintaining the same security posture.
# TaskOutput is read-only polling for background tasks.
# Task/TaskStop must pass normal approval flow.
_EXEMPT_TOOLS = {"Read", "Glob", "Grep", "Write", "Edit", "TaskOutput", "ToolSearch"}

# Anchored regex: only match commands that *start* with a layer1/ path,
# optionally preceded by ./ or an explicit shell interpreter.
_LAYER1_CMD_RE = re.compile(r'^(?:\./|(?:bash|sh)\s+)?layer1/')
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

# Read-only commands that can be auto-approved when invoked simply
# (no pipes, redirects, chaining, subshells).
_SAFE_BASH_COMMANDS = frozenset({
    "grep", "egrep", "fgrep", "rg", "ag", "ack",
    "cat", "head", "tail", "less", "more",
    "cut", "sort", "uniq", "wc", "tr",
    "strings", "xxd", "hexdump", "od",
    "jq", "yq", "echo", "printf",
    "file", "stat", "sha256sum", "sha1sum", "md5sum", "shasum",
    "diff", "comm", "tee", "base64",
    "rev", "nl", "expand", "unexpand", "fold", "fmt", "column",
    "paste", "join", "csplit", "split", "shuf",
    "readlink", "realpath", "basename", "dirname",
    "test", "true", "false",
    "ls", "pwd", "which", "type", "date", "df", "du", "nproc",
})

# Shell operators that indicate command chaining/piping/redirection.
_UNSAFE_SHELL_PATTERNS = frozenset({
    "|", ";", "&&", "||", ">", ">>", "<", "`", "$(", "$((", "&",
})

_FINDINGS_HANDOFF_ALLOWED_TOOLS = {"Read", "Glob", "Grep", "Write", "Edit"}
_WILDCARD_CHARS = frozenset({"*", "?", "[", "{", "]", "}"})


def _is_safe_bash_command(command: str) -> bool:
    """Check if a Bash command is a simple read-only invocation.

    Returns True only if:
    1. The command has no newlines (single statement)
    2. Contains no shell operators (pipes, redirects, chaining, subshells)
    3. The first real token (after VAR=val env prefixes) is in _SAFE_BASH_COMMANDS
    """
    if not command or not command.strip():
        return False

    # No multi-line commands
    if "\n" in command:
        return False

    # Check for unsafe shell patterns anywhere in the command string
    for pattern in _UNSAFE_SHELL_PATTERNS:
        if pattern in command:
            return False

    # Extract the first real command token (skip VAR=val env prefixes)
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    if not tokens:
        return False

    # Skip leading VAR=value environment variable assignments
    cmd_token = None
    for token in tokens:
        if "=" in token and not token.startswith("=") and not token.startswith("-"):
            continue
        cmd_token = token
        break

    if not cmd_token:
        return False

    # Strip any path prefix (e.g. /usr/bin/ls -> ls)
    cmd_name = cmd_token.rsplit("/", 1)[-1]

    return cmd_name in _SAFE_BASH_COMMANDS


def _is_under(path: Path, parent: Path) -> bool:
    """Check whether a path resolves under a parent directory."""
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except Exception:
        return False


_CURL_DATA_FLAGS = frozenset({
    "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
    "-F", "--form",
    "-H", "--header",
})

# Flags whose next token is a regex pattern, not a filesystem path.
_PATTERN_ARG_FLAGS = frozenset({
    "-e", "--regexp", "-E", "--regex",  # grep
    "-P", "--perl-regexp",              # grep
})

# Regex metacharacters that indicate a token is a pattern, not a path.
# Real filesystem paths don't contain these escape sequences.
_REGEX_METACHAR_RE = re.compile(r"\\[|(){}]|[|*+?].*[|*+?]|\.\*|\\[dswDSW]|\[[^^]")


def _looks_like_regex(value: str) -> bool:
    """Return True if a token looks like a regex pattern rather than a path."""
    return bool(_REGEX_METACHAR_RE.search(value))


def _extract_bash_path_candidates(command: str) -> list[str]:
    """Extract likely filesystem path tokens from a Bash command.

    Skips tokens that follow curl data/header flags since those are
    HTTP payloads, not local filesystem paths.  Also skips tokens that
    follow grep/sed pattern flags or look like regex patterns.
    """
    if not command:
        return []
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    candidates: list[str] = []
    skip_next = False
    for token in tokens:
        raw = token.strip().strip("\"'")

        # Previous token was a curl data/pattern flag — skip this token
        if skip_next:
            skip_next = False
            continue
        # Check if this token is a flag whose next arg should be skipped
        if raw in _CURL_DATA_FLAGS or raw in _PATTERN_ARG_FLAGS:
            skip_next = True
            continue

        if not raw or _URL_RE.match(raw):
            continue

        # Skip tokens that look like regex patterns (contain \|, .*, etc.)
        if _looks_like_regex(raw):
            continue

        values = [raw]
        if "=" in raw:
            _, rhs = raw.split("=", 1)
            values.append(rhs.strip().strip("\"'"))

        for value in values:
            if not value or _URL_RE.match(value):
                continue
            if _looks_like_regex(value):
                continue
            if value.startswith("~/"):
                candidates.append(str((Path.home() / value[2:]).resolve()))
                continue
            if value.startswith("/"):
                candidates.append(value)
                continue
            if value == ".." or value.startswith("../") or "/../" in value:
                candidates.append(value)
    return candidates


def _outside_bra_path(command: str) -> str | None:
    """Return the first path candidate that escapes configured BRA roots."""
    allowed_roots = (
        settings.BRA_ROOT.resolve(strict=False),
        settings.BODY_ROOT.resolve(strict=False),
        settings.BRA_STATE.resolve(strict=False),
    )
    body_root = settings.BODY_ROOT.resolve(strict=False)

    for candidate in _extract_bash_path_candidates(command):
        if candidate == ".." or candidate.startswith("../") or "/../" in candidate:
            return candidate
        p = Path(candidate).expanduser()
        if not p.is_absolute():
            continue
        resolved = p.resolve(strict=False)
        if _is_under(resolved, body_root):
            continue
        if any(_is_under(resolved, root) for root in allowed_roots):
            continue
        return str(resolved)
    return None


def _load_pending_findings_count() -> int:
    """Return number of pending findings from .bra/pending_findings.json."""
    pending_file = settings.BRA_STATE / "pending_findings.json"
    if not pending_file.exists():
        return 0
    try:
        data = json.loads(pending_file.read_text())
    except Exception:
        return 0
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        pending = data.get("pending", [])
        if isinstance(pending, list):
            return len(pending)
    return 0


def _is_findings_handoff_scope_active() -> bool:
    """True when findings handoff mode is active and pending findings remain."""
    flag = settings.BRA_STATE / "findings_handoff_active"
    if not flag.exists():
        return False
    return _load_pending_findings_count() > 0


def _glob_anchor_path(value: str) -> str:
    """Return stable path prefix before wildcard characters."""
    if not value:
        return ""
    wildcard_indices = [value.find(ch) for ch in _WILDCARD_CHARS if ch in value]
    if not wildcard_indices:
        return value
    first = min(idx for idx in wildcard_indices if idx >= 0)
    if first <= 0:
        return ""
    anchored = value[:first].rstrip("/\\")
    return anchored


def _resolve_scope_path(value: str) -> Path | None:
    """Resolve a potentially-relative path string to absolute path."""
    cleaned = (value or "").strip().strip("\"'")
    if not cleaned:
        return None

    p = Path(cleaned).expanduser()
    if p.is_absolute():
        return p.resolve(strict=False)

    if cleaned.startswith("body/"):
        return (settings.BODY_ROOT.parent / cleaned).resolve(strict=False)
    return (settings.BODY_ROOT / cleaned).resolve(strict=False)


def _collect_findings_scope_candidates(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
    """Collect path-like fields from tool input for findings-scope checks."""
    if tool_name in ("Read", "Write", "Edit"):
        return [str(tool_input.get("file_path", "")).strip()]
    if tool_name == "Grep":
        return [str(tool_input.get("path", "")).strip()]
    if tool_name == "Glob":
        return [
            str(tool_input.get("path", "")).strip(),
            str(tool_input.get("pattern", "")).strip(),
        ]
    return []


def _is_allowed_findings_scope_path(tool_name: str, candidate: Path) -> bool:
    """Check whether a path is in the strict findings handoff scope."""
    notes_dir = (settings.LAYER3 / "NOTES").resolve(strict=False)
    read_files = {
        (notes_dir / "FINDINGS.md").resolve(strict=False),
        (notes_dir / "INTEL.md").resolve(strict=False),
        (settings.BRA_STATE / "logs" / "captures.log").resolve(strict=False),
        (settings.BRA_STATE / "logs" / "evidence_index.jsonl").resolve(strict=False),
        (settings.BRA_STATE / "pending_findings.json").resolve(strict=False),
    }
    read_roots = {
        (notes_dir / "reqs").resolve(strict=False),
        (settings.BRA_STATE / "artifacts" / "raw").resolve(strict=False),
    }
    write_files = {
        (notes_dir / "FINDINGS.md").resolve(strict=False),
    }
    write_roots = {
        (notes_dir / "reqs").resolve(strict=False),
    }

    if tool_name in ("Write", "Edit"):
        if candidate in write_files:
            return True
        return any(_is_under(candidate, root) for root in write_roots)

    if candidate in read_files:
        return True
    return any(_is_under(candidate, root) for root in read_roots)


def _enforce_findings_handoff_scope(
    tool_name: str,
    tool_input: dict[str, Any],
    tool_use_id: str | None,
) -> dict | None:
    """Return a blocking decision when a tool escapes findings handoff scope."""
    if tool_name not in _FINDINGS_HANDOFF_ALLOWED_TOOLS:
        write_debug_log(
            "tool_approval_hook",
            "block",
            reason="findings_handoff_tool_blocked",
            tool_name=tool_name,
            tool_use_id=tool_use_id or "unknown",
        )
        return {
            "decision": "block",
            "reason": (
                "FINDINGS_HANDOFF_TOOL_BLOCKED\n"
                f"TOOL_NAME={tool_name}\n"
                f"TOOL_USE_ID={tool_use_id or 'unknown'}\n\n"
                "Findings handoff mode only permits Read, Glob, Grep, Write, and Edit."
            ),
        }

    if not isinstance(tool_input, dict):
        return None

    raw_candidates = _collect_findings_scope_candidates(tool_name, tool_input)
    resolved_any = False
    for raw in raw_candidates:
        if not raw:
            continue
        candidate_value = _glob_anchor_path(raw) if tool_name == "Glob" else raw
        if not candidate_value:
            continue
        resolved = _resolve_scope_path(candidate_value)
        if resolved is None:
            continue
        resolved_any = True
        if not _is_allowed_findings_scope_path(tool_name, resolved):
            write_debug_log(
                "tool_approval_hook",
                "block",
                reason="findings_handoff_path_blocked",
                tool_name=tool_name,
                tool_use_id=tool_use_id or "unknown",
                blocked_path=str(resolved),
            )
            return {
                "decision": "block",
                "reason": (
                    "FINDINGS_HANDOFF_PATH_BLOCKED\n"
                    f"TOOL_NAME={tool_name}\n"
                    f"TOOL_USE_ID={tool_use_id or 'unknown'}\n"
                    f"BlockedPath: {resolved}\n\n"
                    "Allowed paths are limited to NOTES/FINDINGS.md, NOTES/reqs/, "
                    ".bra/artifacts/raw/, .bra/logs/captures.log, and .bra/logs/evidence_index.jsonl."
                ),
            }

    if not resolved_any:
        write_debug_log(
            "tool_approval_hook",
            "block",
            reason="findings_handoff_unresolved_path",
            tool_name=tool_name,
            tool_use_id=tool_use_id or "unknown",
        )
        return {
            "decision": "block",
            "reason": (
                "FINDINGS_HANDOFF_PATH_REQUIRED\n"
                f"TOOL_NAME={tool_name}\n"
                f"TOOL_USE_ID={tool_use_id or 'unknown'}\n\n"
                "Findings handoff mode requires explicit in-scope file paths."
            ),
        }
    return None


def _get_approval_file(tool_use_id: str) -> Path:
    """Get path to approval file for a tool use ID."""
    return _get_tool_approvals_dir() / f"TOOL-{tool_use_id}"


def _has_tool_approval(tool_use_id: str) -> bool:
    """Check if tool use has been approved.

    Args:
        tool_use_id: Unique tool use identifier

    Returns:
        True if approved
    """
    if not tool_use_id:
        return False

    approval_file = _get_approval_file(tool_use_id)
    exists = approval_file.exists()
    write_debug_log("tool_approval_hook", "has_tool_approval", tool_use_id=tool_use_id, exists=exists)
    return exists


def _consume_tool_approval(tool_use_id: str) -> bool:
    """Consume (delete) a tool approval.

    Args:
        tool_use_id: Unique tool use identifier

    Returns:
        True if consumed
    """
    if not tool_use_id:
        return False

    approval_file = _get_approval_file(tool_use_id)
    if approval_file.exists():
        try:
            approval_file.unlink()
            write_debug_log("tool_approval_hook", "consume_tool_approval_ok", tool_use_id=tool_use_id)
            return True
        except Exception:
            write_debug_log("tool_approval_hook", "consume_tool_approval_fail", tool_use_id=tool_use_id)
            pass
    return False


def _make_retry_key(tool_name: str, tool_input: dict) -> str:
    """Deterministic hash of tool_name + essential tool_input fields.

    Only the primary identifying field is hashed so that metadata
    differences (description, timeout, etc.) between the blocked
    attempt and the SDK retry don't cause a mismatch.
    """
    if tool_name == "Bash":
        essential = {"command": tool_input.get("command", "")}
    elif tool_name in ("Read", "Write", "Edit"):
        essential = {"file_path": tool_input.get("file_path", "")}
    elif tool_name in ("Glob", "Grep"):
        essential = {"pattern": tool_input.get("pattern", "")}
    else:
        essential = tool_input

    payload = json.dumps({"tool": tool_name, "input": essential}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _get_retry_approval_file(tool_name: str, tool_input: dict) -> Path:
    """Get path to retry approval file for a tool name + input combo."""
    key = _make_retry_key(tool_name, tool_input)
    return _get_tool_approvals_dir() / f"TOOL-RETRY-{key}"


def _has_retry_approval(tool_name: str, tool_input: dict) -> bool:
    """Check if a retry approval exists for this tool name + input."""
    exists = _get_retry_approval_file(tool_name, tool_input).exists()
    write_debug_log("tool_approval_hook", "has_retry_approval", tool_name=tool_name, exists=exists)
    return exists


def _consume_retry_approval(tool_name: str, tool_input: dict) -> bool:
    """Consume (delete) a retry approval. Returns True if consumed."""
    f = _get_retry_approval_file(tool_name, tool_input)
    if f.exists():
        try:
            f.unlink()
            write_debug_log("tool_approval_hook", "consume_retry_approval_ok", tool_name=tool_name)
            return True
        except Exception:
            write_debug_log("tool_approval_hook", "consume_retry_approval_fail", tool_name=tool_name)
            pass
    return False


def grant_retry_approval(tool_name: str, tool_input: dict) -> bool:
    """Grant a retry approval for a tool name + input combo.

    Called by runner when user approves a tool execution so that
    the agent's retry (which generates a new tool_use_id) is also allowed.

    Args:
        tool_name: Name of the tool (e.g. "Bash")
        tool_input: Full tool input dict

    Returns:
        True if file was created
    """
    _get_tool_approvals_dir().mkdir(parents=True, exist_ok=True)
    f = _get_retry_approval_file(tool_name, tool_input)
    try:
        f.write_text(f"Retry approved: {tool_name}\n")
        write_debug_log("tool_approval_hook", "grant_retry_approval_ok", tool_name=tool_name, path=str(f))
        return True
    except Exception:
        write_debug_log("tool_approval_hook", "grant_retry_approval_fail", tool_name=tool_name, path=str(f))
        return False


# ── One-time retry (in-memory, TTL-based) ───────────────────────────
# For "allow_once" decisions: stored in memory with a 30-second TTL so
# they expire if the agent doesn't retry the same command promptly.
# This prevents persistent TOOL-RETRY files from acting as a permanent
# "allow" when the agent skips the retry.

_ONE_TIME_TTL = 30.0  # seconds
_one_time_retries: dict[str, float] = {}  # retry_key → grant_time
_RECENT_TOOL_APPROVAL_TTL = 10.0  # seconds
_recent_tool_approvals: dict[str, float] = {}  # tool_use_id → approval_time


def _remember_recent_tool_approval(tool_use_id: str | None) -> None:
    """Remember a just-consumed approval for follow-on hook stages."""
    if not tool_use_id:
        return
    _recent_tool_approvals[tool_use_id] = time.monotonic()
    write_debug_log("tool_approval_hook", "recent_tool_approval_remembered", tool_use_id=tool_use_id)


def consume_recent_tool_approval(tool_use_id: str | None) -> bool:
    """Consume a just-granted approval for downstream hooks in the same turn."""
    if not tool_use_id:
        return False
    granted_at = _recent_tool_approvals.pop(tool_use_id, None)
    if granted_at is None:
        return False
    elapsed = time.monotonic() - granted_at
    if elapsed > _RECENT_TOOL_APPROVAL_TTL:
        write_debug_log(
            "tool_approval_hook",
            "recent_tool_approval_expired",
            tool_use_id=tool_use_id,
            elapsed=round(elapsed, 3),
        )
        return False
    write_debug_log(
        "tool_approval_hook",
        "recent_tool_approval_consumed",
        tool_use_id=tool_use_id,
        elapsed=round(elapsed, 3),
    )
    return True


def _tool_approval_required_reason(tool_name: str, tool_use_id: str | None, command: str) -> dict[str, str]:
    """Build the canonical tool approval block payload."""
    return {
        "decision": "block",
        "reason": (
            f"TOOL_APPROVAL_REQUIRED\n"
            f"TOOL_NAME={tool_name}\n"
            f"TOOL_USE_ID={tool_use_id or 'unknown'}\n"
            f"Command: {command}\n"
            f"\n"
            f"This tool execution requires explicit user approval.\n"
            f"Approve this operation in the approval prompt to proceed."
        ),
    }


def grant_one_time_retry(tool_name: str, tool_input: dict) -> bool:
    """Grant a one-time retry that expires after TTL seconds.

    Unlike grant_retry_approval (file-based, persistent), this stores
    the approval in memory with a TTL. If the agent doesn't retry within
    the TTL window, the approval silently expires.
    """
    key = _make_retry_key(tool_name, tool_input)
    _one_time_retries[key] = time.monotonic()
    write_debug_log("tool_approval_hook", "grant_one_time_retry_ok", tool_name=tool_name, key=key)
    return True


def _check_one_time_retry(tool_name: str, tool_input: dict) -> bool:
    """Check and consume a one-time retry approval. Returns True if valid."""
    key = _make_retry_key(tool_name, tool_input)
    granted_at = _one_time_retries.pop(key, None)
    if granted_at is None:
        return False
    elapsed = time.monotonic() - granted_at
    if elapsed > _ONE_TIME_TTL:
        write_debug_log("tool_approval_hook", "one_time_retry_expired", tool_name=tool_name, elapsed=round(elapsed, 1))
        return False
    write_debug_log("tool_approval_hook", "one_time_retry_consumed", tool_name=tool_name, elapsed=round(elapsed, 1))
    return True


def preview_tool_approval_decision(
    tool_name: str,
    tool_input: dict[str, Any] | Any,
    tool_use_id: str | None,
) -> dict[str, str] | None:
    """Preview whether tool approval would still block this tool use.

    Used by downstream hooks because PreToolUse hook order is not short-circuiting.
    """
    if not _is_tool_approval_enabled():
        return None

    if tool_name in _EXEMPT_TOOLS:
        return None

    if tool_name in _session_approved_tool_types:
        return None

    if not isinstance(tool_input, dict):
        tool_input = {}

    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if cmd and cmd in _session_approved_bash_commands:
            return None
        if _LAYER1_CMD_RE.match(cmd):
            return None
        if _is_safe_bash_command(cmd):
            return None
        blocked_path = _outside_bra_path(cmd)
        if blocked_path:
            return {
                "decision": "block",
                "reason": (
                    "BASH_PATH_OUTSIDE_BRA_BLOCKED\n"
                    f"TOOL_NAME={tool_name}\n"
                    f"TOOL_USE_ID={tool_use_id or 'unknown'}\n"
                    f"BlockedPath: {blocked_path}\n"
                    f"Command: {cmd[:280]}\n\n"
                    "Bash commands may only reference files under the configured BRA directory."
                ),
            }
        if consume_recent_tool_approval(tool_use_id):
            return None
        return _tool_approval_required_reason(tool_name, tool_use_id, cmd[:200])

    return None


def _is_tool_approval_enabled() -> bool:
    """Check if tool-by-tool approval is enabled.

    ENABLED BY DEFAULT. Opt out via:
    - Environment: BRA_TOOL_APPROVAL=0
    - File: .bra/TOOL_APPROVAL_DISABLED

    Returns:
        True if enabled (default)
    """
    # Explicit disable via environment
    if os.environ.get("BRA_TOOL_APPROVAL") == "0":
        write_debug_log("tool_approval_hook", "approval_enabled_check", enabled=False, reason="env_disabled")
        return False

    # Explicit disable via file
    disabled_file = settings.BRA_STATE / "TOOL_APPROVAL_DISABLED"
    if disabled_file.exists():
        write_debug_log("tool_approval_hook", "approval_enabled_check", enabled=False, reason="marker_disabled")
        return False

    write_debug_log("tool_approval_hook", "approval_enabled_check", enabled=True)
    return True


async def check_tool_approval_hook(
    hook_input: PreToolUseHookInput,
    tool_use_id: str | None,
    context: HookContext,
) -> SyncHookJSONOutput:
    """Check tool approval before any tool use.

    MECHANICAL ENFORCEMENT:
    - If tool approval is enabled, non-exempt tools are blocked until approved
    - User must approve each tool use in the TUI
    - No way to bypass this check

    Args:
        hook_input: Hook input from SDK (contains tool_name, tool_input, etc.)
        tool_use_id: Unique tool use identifier
        context: Hook context with signal for cancellation

    Returns:
        Empty dict to allow, or dict with "decision": "block"
    """
    # Check if tool-by-tool approval is enabled
    if not _is_tool_approval_enabled():
        write_debug_log("tool_approval_hook", "allow", reason="global_disabled")
        return {}  # Disabled, allow all

    # Get tool info
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})
    write_debug_log(
        "tool_approval_hook",
        "check_start",
        tool_name=tool_name,
        tool_use_id=tool_use_id or "",
        tool_input_type=type(tool_input).__name__,
    )

    if _is_findings_handoff_scope_active():
        decision = _enforce_findings_handoff_scope(tool_name, tool_input, tool_use_id)
        if decision:
            return decision

    # Findings subagent mode is tracked for observability, but it does not
    # globally hard-block Bash in this hook. The findings subagent itself is
    # already constrained by allowed_tools in the runner.
    if tool_name == "Bash":
        subagent_flag = settings.BRA_STATE / "findings_subagent_active"
        if subagent_flag.exists():
            command = tool_input.get("command", "")[:280] if isinstance(tool_input, dict) else ""
            write_debug_log(
                "tool_approval_hook",
                "findings_subagent_active_bash_observed",
                tool_name=tool_name,
                tool_use_id=tool_use_id or "unknown",
                command=command,
            )

    # Exempt low-risk built-in tools that are governed by other layers.
    if tool_name in _EXEMPT_TOOLS:
        write_debug_log("tool_approval_hook", "allow", reason="exempt_tool", tool_name=tool_name)
        return {}

    # Session-level approval: user approved this tool type for the session.
    if tool_name in _session_approved_tool_types:
        write_debug_log("tool_approval_hook", "allow", reason="session_approved", tool_name=tool_name)
        return {}

    # Session-level Bash command approval: exact command match.
    if tool_name == "Bash" and isinstance(tool_input, dict):
        cmd = tool_input.get("command", "")
        if cmd and cmd in _session_approved_bash_commands:
            write_debug_log("tool_approval_hook", "allow", reason="session_bash_command", command=cmd[:120])
            return {}

    # Auto-approve BRA internal scripts (layer1/).
    if tool_name == "Bash" and isinstance(tool_input, dict):
        cmd = tool_input.get("command", "")
        if _LAYER1_CMD_RE.match(cmd):
            write_debug_log("tool_approval_hook", "allow", reason="layer1_internal_script", tool_name=tool_name)
            return {}
        # Auto-approve simple read-only commands (ls, pwd, grep, etc.)
        if _is_safe_bash_command(cmd):
            write_debug_log("tool_approval_hook", "allow", reason="safe_readonly_bash", tool_name=tool_name, command=cmd[:120])
            return {}
        blocked_path = _outside_bra_path(cmd)
        if blocked_path:
            write_debug_log(
                "tool_approval_hook",
                "block",
                reason="outside_bra_path",
                tool_name=tool_name,
                blocked_path=blocked_path,
                command=cmd[:240],
            )
            return {
                "decision": "block",
                "reason": (
                    "BASH_PATH_OUTSIDE_BRA_BLOCKED\n"
                    f"TOOL_NAME={tool_name}\n"
                    f"TOOL_USE_ID={tool_use_id or 'unknown'}\n"
                    f"BlockedPath: {blocked_path}\n"
                    f"Command: {cmd[:280]}\n\n"
                    "Bash commands may only reference files under the configured BRA directory."
                ),
            }

    # Check for existing approval (exact tool_use_id match)
    if tool_use_id and _has_tool_approval(tool_use_id):
        # Consume the approval and allow
        _consume_tool_approval(tool_use_id)
        _remember_recent_tool_approval(tool_use_id)
        write_debug_log("tool_approval_hook", "allow", reason="tool_use_id_approved", tool_use_id=tool_use_id)
        return {}

    # Check for retry approval (tool_name + tool_input hash match).
    # When the SDK retries with a new tool_use_id, the original id-keyed
    # file won't match.  This command-keyed file bridges the gap.
    if isinstance(tool_input, dict) and _has_retry_approval(tool_name, tool_input):
        _consume_retry_approval(tool_name, tool_input)
        _remember_recent_tool_approval(tool_use_id)
        write_debug_log("tool_approval_hook", "allow", reason="retry_approved", tool_name=tool_name)
        return {}

    # Check for one-time retry (in-memory, TTL-based).
    # Used by "allow_once" decisions — expires after 30s if not consumed.
    if isinstance(tool_input, dict) and _check_one_time_retry(tool_name, tool_input):
        _remember_recent_tool_approval(tool_use_id)
        write_debug_log("tool_approval_hook", "allow", reason="one_time_retry", tool_name=tool_name)
        return {}

    # Block with approval required message
    # Format message for TUI to parse
    command = ""
    if tool_name == "Bash":
        command = tool_input.get("command", "")[:200] if isinstance(tool_input, dict) else ""
    elif tool_name in ("Read", "Write", "Edit"):
        command = tool_input.get("file_path", "") if isinstance(tool_input, dict) else ""
    elif tool_name in ("Glob", "Grep"):
        command = tool_input.get("pattern", "") if isinstance(tool_input, dict) else ""

    write_debug_log(
        "tool_approval_hook",
        "block",
        reason="approval_required",
        tool_name=tool_name,
        tool_use_id=tool_use_id or "unknown",
        command=command,
    )
    return _tool_approval_required_reason(tool_name, tool_use_id, command)


def enable_tool_approval() -> None:
    """Enable tool-by-tool approval (remove disable marker).

    Tool approval is enabled by default. This removes any
    explicit disable marker that was previously set.
    """
    disabled_file = settings.BRA_STATE / "TOOL_APPROVAL_DISABLED"
    if disabled_file.exists():
        disabled_file.unlink()
    write_debug_log("tool_approval_hook", "enable_tool_approval")


def disable_tool_approval() -> None:
    """Disable tool-by-tool approval.

    Creates a marker file that disables the check.
    """
    settings.BRA_STATE.mkdir(parents=True, exist_ok=True)
    disabled_file = settings.BRA_STATE / "TOOL_APPROVAL_DISABLED"
    disabled_file.touch()
    write_debug_log("tool_approval_hook", "disable_tool_approval")


# Session-level approvals: tool types approved for the entire session.
# Set when user grants a persistent (one_time=False) approval.
_session_approved_tool_types: set[str] = set()

# Session-level Bash command approvals: exact commands approved for the session.
# Bash is excluded from tool-type session approval because each command is
# different.  Instead, the exact command string is approved so that only
# identical repeat invocations are auto-allowed.
_session_approved_bash_commands: set[str] = set()


def grant_session_tool_approval(tool_name: str) -> None:
    """Grant session-wide approval for a tool type.

    Once granted, all subsequent calls to this tool type pass the hook
    without requiring per-call approval.  Called when user approves a
    tool with allow_override (persistent, one_time=False).
    """
    _session_approved_tool_types.add(tool_name)
    write_debug_log("tool_approval_hook", "grant_session_tool_approval", tool_name=tool_name)


def grant_session_bash_command(command: str) -> None:
    """Grant session-wide approval for a specific Bash command.

    Only the exact command string is approved — any variation requires
    a new approval.
    """
    _session_approved_bash_commands.add(command)
    write_debug_log("tool_approval_hook", "grant_session_bash_command", command=command[:120])


def grant_tool_approval(tool_use_id: str, tool_name: str) -> bool:
    """Grant approval for a specific tool use.

    Args:
        tool_use_id: Unique tool use identifier
        tool_name: Name of the tool (for logging)

    Returns:
        True if granted
    """
    _get_tool_approvals_dir().mkdir(parents=True, exist_ok=True)

    approval_file = _get_approval_file(tool_use_id)
    try:
        approval_file.write_text(f"Approved tool: {tool_name}\n")
        write_debug_log("tool_approval_hook", "grant_tool_approval_ok", tool_use_id=tool_use_id, tool_name=tool_name)
        return True
    except Exception:
        write_debug_log("tool_approval_hook", "grant_tool_approval_fail", tool_use_id=tool_use_id, tool_name=tool_name)
        return False
