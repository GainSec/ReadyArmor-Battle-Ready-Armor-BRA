"""SDK adapter for file-related governance hooks.

This hook remains in the SDK path for Read, Grep, Glob, Write, and Edit,
but delegates shared file/path policy decisions to body/layer1/hooks/file-guard.py.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

from bra.config import settings
from bra.debug_log import write_debug_log
from bra.hooks.types import HookContext, PreToolUseHookInput, SyncHookJSONOutput


def _transport_block(reason: str) -> SyncHookJSONOutput:
    return {
        "decision": "block",
        "reason": reason,
        "policy": "FILE_GUARD_TRANSPORT_ERROR",
    }


def _build_request(tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"tool_name": tool_name, "tool_input": {}}
    normalized = payload["tool_input"]
    for key in ("file_path", "content", "path", "pattern"):
        value = tool_input.get(key)
        if isinstance(value, str):
            normalized[key] = value
    return payload


def _translate_response(raw: dict[str, Any]) -> SyncHookJSONOutput:
    decision = raw.get("decision")
    if decision == "allow":
        return {}
    if decision == "block":
        reason = raw.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            return _transport_block("File governance check failed: missing block reason")
        result: SyncHookJSONOutput = {"decision": "block", "reason": reason}
        policy = raw.get("policy")
        if isinstance(policy, str) and policy.strip():
            result["policy"] = policy
        meta = raw.get("meta")
        if isinstance(meta, dict):
            result["meta"] = meta
        return result
    return _transport_block("File governance check failed: invalid decision payload")


def _run_file_guard(tool_name: str, tool_input: dict[str, Any]) -> SyncHookJSONOutput:
    file_guard_py = settings.HOOKS_DIR / "file-guard.py"
    if not file_guard_py.exists():
        write_debug_log("file_hook", "guard_missing", tool_name=tool_name, path=str(file_guard_py))
        return _transport_block("File governance check failed: file-guard.py is missing")

    payload = _build_request(tool_name, tool_input)
    try:
        result = subprocess.run(
            [(os.environ.get("BRA_PYTHON_EXECUTABLE") or sys.executable or "python3").strip(), str(file_guard_py)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            cwd=str(settings.BODY_ROOT),
            timeout=30,
            env={
                **os.environ,
                "BRA_HOOK_CONTEXT": "sdk",
            },
        )
    except subprocess.TimeoutExpired:
        write_debug_log("file_hook", "guard_timeout", tool_name=tool_name)
        return _transport_block("File governance check failed: file-guard.py timed out")
    except FileNotFoundError:
        write_debug_log("file_hook", "guard_exec_missing", tool_name=tool_name)
        return _transport_block("File governance check failed: python executable missing")

    if result.returncode != 0:
        write_debug_log("file_hook", "guard_nonzero_exit", tool_name=tool_name, exit_code=result.returncode)
        return _transport_block(
            f"File governance check failed: file-guard.py exited with code {result.returncode}"
        )

    stdout = (result.stdout or "").strip()
    if not stdout:
        write_debug_log("file_hook", "guard_empty_stdout", tool_name=tool_name, exit_code=result.returncode)
        return _transport_block("File governance check failed: empty guard response")

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        write_debug_log("file_hook", "guard_invalid_json", tool_name=tool_name, stdout=stdout[:200])
        return _transport_block("File governance check failed: invalid guard JSON")

    if not isinstance(parsed, dict):
        write_debug_log("file_hook", "guard_non_dict_json", tool_name=tool_name)
        return _transport_block("File governance check failed: invalid guard payload type")

    translated = _translate_response(parsed)
    write_debug_log(
        "file_hook",
        "guard_result",
        tool_name=tool_name,
        decision=translated.get("decision", "allow"),
        policy=translated.get("policy", ""),
    )
    return translated


async def pre_read(
    hook_input: PreToolUseHookInput,
    tool_use_id: str | None,
    context: HookContext,
) -> SyncHookJSONOutput:
    tool_input = hook_input.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return {}
    return _run_file_guard("Read", tool_input)


async def pre_grep(
    hook_input: PreToolUseHookInput,
    tool_use_id: str | None,
    context: HookContext,
) -> SyncHookJSONOutput:
    tool_input = hook_input.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return {}
    return _run_file_guard("Grep", tool_input)


async def pre_glob(
    hook_input: PreToolUseHookInput,
    tool_use_id: str | None,
    context: HookContext,
) -> SyncHookJSONOutput:
    tool_input = hook_input.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return {}
    return _run_file_guard("Glob", tool_input)


async def pre_file(
    hook_input: PreToolUseHookInput,
    tool_use_id: str | None,
    context: HookContext,
) -> SyncHookJSONOutput:
    tool_input = hook_input.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return {}
    tool_name = "Edit" if "old_string" in tool_input or "new_string" in tool_input else "Write"
    return _run_file_guard(tool_name, tool_input)
