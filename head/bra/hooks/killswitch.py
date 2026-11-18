"""Kill switch hook.

Checks kill switch status before every tool use.
Kill switch can be activated via:
- Environment: BRA_STOP=1
- File: .bra/STOP
- CLAUDE.md: STOP marker in Kill Switch section

CRITICAL: The kill switch has NO TOKEN OVERRIDE.
    When active, ALL operations are blocked until deactivated.
    This is the ultimate emergency stop for the system.

    To deactivate:
    - Remove .bra/STOP file
    - Unset BRA_STOP environment variable
    - Change CLAUDE.md Kill Switch section from STOP to CLEAR
"""

import os
import re
from typing import Any

from bra.hooks.types import (
    PreToolUseHookInput,
    HookContext,
    SyncHookJSONOutput,
)

from bra.config.settings import BRA_STATE, LAYER1


def is_killswitch_active() -> bool:
    """Check if kill switch is active.

    Returns:
        True if kill switch is active
    """
    # Check environment variable
    if os.environ.get("BRA_STOP") == "1":
        return True

    # Check .bra/STOP file
    stop_file = BRA_STATE / "STOP"
    if stop_file.exists():
        return True

    # Check CLAUDE.md for STOP marker
    agents_file = LAYER1.parent / "CLAUDE.md"
    if agents_file.exists():
        try:
            content = agents_file.read_text()
            # Look for STOP in the Kill Switch code block (between ```)
            # Pattern: ## Kill Switch followed by code block containing STOP
            # Must be in the actual status block, not documentation
            match = re.search(r"##\s*Kill\s*Switch\s*\n+```\s*\n\s*(STOP|CLEAR)\s*\n```", content, re.IGNORECASE)
            if match and match.group(1).upper() == "STOP":
                return True
        except Exception:
            pass

    return False


async def check_killswitch_hook(
    hook_input: PreToolUseHookInput,
    tool_use_id: str | None,
    context: HookContext,
) -> SyncHookJSONOutput:
    """Check kill switch before any tool use.

    Args:
        hook_input: Hook input from SDK (contains tool_name, tool_input, etc.)
        tool_use_id: Unique tool use identifier
        context: Hook context with signal for cancellation

    Returns:
        Empty dict to allow, or dict with "decision": "block"
    """
    if is_killswitch_active():
        return {
            "decision": "block",
            "reason": "KILL SWITCH ACTIVE - all operations halted. Check CLAUDE.md or .bra/STOP",
        }

    return {}
