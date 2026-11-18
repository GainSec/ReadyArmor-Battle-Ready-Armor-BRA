"""Finding guard hook — defense-in-depth gate.

PreToolUse hook that blocks all tool calls when pending findings exist,
unless the tool targets NOTES/FINDINGS.md or NOTES/reqs/.

This is intentionally simple: reads pending_findings.json, gates on queue state.
No schema parsing, no validation. The FindingEnforcer handles that.
"""

import json
from pathlib import Path
from typing import Any

from bra.hooks.types import (
    PreToolUseHookInput,
    HookContext,
    SyncHookJSONOutput,
)

from bra.config.settings import BRA_STATE
from bra.debug_log import write_debug_log


def _get_bra_state_dir() -> Path:
    """Get .bra state directory (mockable for tests)."""
    return BRA_STATE


# Tools that are always allowed (read-only)
_ALWAYS_ALLOWED = {"Read", "Glob", "Grep"}


async def pre_finding_guard(
    hook_input: PreToolUseHookInput,
    tool_use_id: str | None,
    context: HookContext,
) -> SyncHookJSONOutput:
    """PreToolUse hook: block tools when findings are pending.

    Returns:
        Empty dict to allow, or dict with "decision": "block"
    """
    bra_state = _get_bra_state_dir()
    pending_file = bra_state / "pending_findings.json"
    write_debug_log(
        "finding_guard",
        "check_start",
        pending_file=str(pending_file),
        exists=pending_file.exists(),
    )

    # No pending file = no blocking
    if not pending_file.exists():
        write_debug_log("finding_guard", "allow", reason="pending_file_missing")
        return {}

    try:
        data = json.loads(pending_file.read_text())
    except (json.JSONDecodeError, IOError):
        write_debug_log("finding_guard", "allow", reason="pending_file_unreadable")
        return {}

    # Normalize dict format {"pending": [...], "completed_ids": [...]} to list
    if isinstance(data, dict):
        data = data.get("pending", [])

    # Empty queue = no blocking
    if not data:
        write_debug_log("finding_guard", "allow", reason="pending_queue_empty")
        return {}

    # Subagent is handling findings — don't block main agent
    subagent_flag = bra_state / "findings_subagent_active"
    if subagent_flag.exists():
        write_debug_log("finding_guard", "allow", reason="subagent_active")
        return {}

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})
    write_debug_log("finding_guard", "pending_queue_present", count=len(data), tool_name=tool_name)

    # Read-only tools always allowed
    if tool_name in _ALWAYS_ALLOWED:
        write_debug_log("finding_guard", "allow", reason="read_only_tool", tool_name=tool_name)
        return {}

    # Write/Edit to FINDINGS.md or reqs/ allowed
    if tool_name in ("Write", "Edit"):
        file_path = tool_input.get("file_path", "") if isinstance(tool_input, dict) else ""
        if "FINDINGS.md" in file_path or "/reqs/" in file_path:
            write_debug_log("finding_guard", "allow", reason="findings_or_reqs_write", file_path=file_path)
            return {}

    # Block everything else
    count = len(data)
    write_debug_log("finding_guard", "block", count=count, tool_name=tool_name)
    return {
        "decision": "block",
        "reason": (
            f"BLOCKED: {count} finding(s) require documentation in "
            f"NOTES/FINDINGS.md before other work can proceed."
        ),
    }
