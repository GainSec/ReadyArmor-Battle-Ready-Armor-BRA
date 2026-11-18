"""Provider-agnostic hook type aliases.

These aliases allow hooks to be imported and executed even when the
Claude SDK is not installed. When Claude SDK is available, we use its
native types. Otherwise, we fall back to permissive runtime aliases.
"""

from dataclasses import dataclass
from typing import Any, Callable

try:
    from claude_agent_sdk.types import (  # type: ignore
        PreToolUseHookInput,
        PostToolUseHookInput,
        HookContext,
        SyncHookJSONOutput,
        HookMatcher,
        HookEvent,
    )
except Exception:
    PreToolUseHookInput = dict[str, Any]
    PostToolUseHookInput = dict[str, Any]
    HookContext = dict[str, Any]
    SyncHookJSONOutput = dict[str, Any]
    HookEvent = str

    @dataclass
    class HookMatcher:
        """Fallback matcher shape when SDK types are unavailable."""

        matcher: str
        hooks: list[Callable[..., Any]]

