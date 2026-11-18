"""Bash command hook.

Calls body/layer1/hooks/bash-guard.py to validate commands.

Exit codes from bash-guard.py:
- 0: Allow
- 2: Block (command halted) - user can grant token and retry
- 3: Needs approval (script execution) - treated as block
- 99: Kill switch active - no override possible

SCRIPT EXECUTION DETECTION:
    Before calling bash-guard.py, this hook checks if the command
    executes a script. If so, it blocks with SCRIPT_APPROVAL_REQUIRED
    and includes the script path and content for TUI display.

TOKEN-BASED APPROVAL FLOW:
    When a command is blocked (exit 2), bash-guard.py outputs instructions
    for how to approve. The user can then:
    1. Grant the appropriate token (env var or file)
    2. Ask the agent to retry the command
    3. Command will pass on retry

    This is NOT interactive prompting - it's a retry-after-approval model.
    The can_use_tool callback (separate from hooks) handles interactive approval.
"""

import subprocess
import os
import json
import sys
from typing import Any

from bra.hooks.types import (
    PreToolUseHookInput,
    HookContext,
    SyncHookJSONOutput,
)

from bra.config import settings
from bra.core.approval import (
    is_script_execution,
    extract_script_path,
    has_script_approval,
    read_script_content,
)
from bra.hooks.tool_approval_hook import preview_tool_approval_decision


def _log_hook(message: str) -> None:
    """Log hook activity for debugging."""
    try:
        logs_dir = settings.LOGS_DIR
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_file = logs_dir / "bash-guard.log"
        with open(log_file, "a") as f:
            from datetime import datetime, timezone
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            f.write(f"[{ts}] [PYTHON-HOOK] {message}\n")
    except Exception:
        pass  # Don't fail on log errors


async def pre_bash(
    hook_input: PreToolUseHookInput,
    tool_use_id: str | None,
    context: HookContext,
) -> SyncHookJSONOutput:
    """PreToolUse hook for Bash commands.

    Calls bash-guard.py to validate the command.

    Args:
        hook_input: Hook input from SDK (contains tool_input with "command")
        tool_use_id: Unique tool use identifier
        context: Hook context with signal for cancellation

    Returns:
        Empty dict to allow, or dict with "decision": "block" and "reason"
    """
    tool_input = hook_input.get("tool_input", {})
    command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""

    _log_hook(f"pre_bash called with command: {command[:100]}...")

    # Respect tool approval before running any bash-specific governance.
    # PreToolUse hook order is not short-circuiting, so this hook may still
    # run after tool_approval_hook has already blocked the same command.
    approval_decision = preview_tool_approval_decision("Bash", tool_input, tool_use_id)
    if approval_decision:
        _log_hook("BLOCK - pending tool approval or approval-layer block")
        return approval_decision

    # CHECK 0: Script execution detection (runs before bash-guard.py)
    # This provides script content to TUI for review
    if is_script_execution(command):
        script_path = extract_script_path(command)
        if script_path and not has_script_approval(script_path):
            _log_hook(f"BLOCK - script execution requires approval: {script_path}")
            script_content = read_script_content(script_path)
            return {
                "decision": "block",
                "reason": (
                    f"SCRIPT_APPROVAL_REQUIRED\n"
                    f"SCRIPT_PATH={script_path}\n"
                    f"Command: {command}\n"
                    f"\n"
                    f"Script execution requires approval.\n"
                    f"Review the script content before allowing execution.\n"
                    f"\n"
                    f"--- Script Content ---\n"
                    f"{script_content[:2000]}"
                ),
            }
        else:
            _log_hook(f"Script {script_path} already approved")

    hooks_dir = settings.HOOKS_DIR
    body_root = settings.BODY_ROOT
    bash_guard_py = hooks_dir / "bash-guard.py"

    # If no guard implementation exists, allow (body not set up yet)
    if not bash_guard_py.exists():
        _log_hook(f"bash-guard.py missing at {bash_guard_py}")
        return {}

    # Build JSON input in the format bash-guard.py expects
    json_input = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": command}
    })

    guard_label = "bash-guard.py"
    try:
        cmd = [(os.environ.get("BRA_PYTHON_EXECUTABLE") or sys.executable or "python3").strip(), str(bash_guard_py)]

        result = subprocess.run(
            cmd,
            input=json_input,
            capture_output=True,
            text=True,
            cwd=str(body_root),
            timeout=30,
            env={
                **os.environ,
                "BRA_HOOK_CONTEXT": "sdk",
                # Host-home signal: where default ~/.claude lives on the machine.
                "BRA_HOST_HOME": os.environ.get("BRA_HOST_HOME") or os.path.expanduser("~"),
                # Explicit allowed Claude state location under body/.bra.
                "BRA_ALLOWED_CLAUDE_DIR": str(body_root / ".bra" / ".claude"),
            },
        )
    except subprocess.TimeoutExpired:
        _log_hook(f"{guard_label} timed out")
        return {
            "decision": "block",
            "reason": "Governance check timed out",
        }
    except FileNotFoundError:
        _log_hook(f"{guard_label} not found - allowing")
        return {}

    _log_hook(f"{guard_label} returned exit code {result.returncode}")
    if result.stdout:
        _log_hook(f"stdout: {result.stdout[:200]}")
    if result.stderr:
        _log_hook(f"stderr: {result.stderr[:200]}")

    # Exit code handling
    if result.returncode == 0:
        _log_hook("ALLOW - command passed governance")
        return {}  # Allow

    if result.returncode == 99:
        _log_hook("BLOCK - kill switch active")
        return {
            "decision": "block",
            "reason": "KILL SWITCH ACTIVE - all operations halted",
        }

    if result.returncode == 2:
        # Blocked by governance
        # Prefer stderr on failures: governance scripts may emit informational
        # stdout (e.g., "Command OK") before writing the actual block reason.
        reason = result.stderr or result.stdout or "Blocked by governance"
        _log_hook(f"BLOCK (exit 2) - {reason}")
        return {
            "decision": "block",
            "reason": reason,
        }

    if result.returncode == 3:
        # Script execution needs approval - block and provide reason
        # Note: SDK only supports "block" decision, not "needs_approval"
        reason = result.stderr or result.stdout or "Script execution requires approval"
        _log_hook(f"BLOCK (needs approval) - {reason}")
        return {
            "decision": "block",
            "reason": f"APPROVAL REQUIRED: {reason}",
        }

    # Any other non-zero exit code = block
    reason = result.stderr or result.stdout or "Blocked by governance"
    _log_hook(f"BLOCK (exit {result.returncode}) - {reason}")
    return {
        "decision": "block",
        "reason": reason,
    }
