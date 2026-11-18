"""PreCompact hook — re-injects CLAUDE.md governance on context compaction.

CLAUDE.md is injected into the first turn's prompt. When the SDK compacts
context (to free token space), the original governance text may be
summarized away. This hook catches the PreCompact event and writes the
full CLAUDE.md into ``custom_instructions`` so it survives compaction.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from bra.config import settings


async def pre_compact(
    hook_input: dict[str, Any],
    context: Any,
    tool_input: dict[str, Any],
) -> dict[str, Any]:
    """Inject CLAUDE.md into custom_instructions before compaction."""
    claude_md = settings.BODY_ROOT / "CLAUDE.md"
    if claude_md.exists():
        governance = claude_md.read_text(encoding="utf-8", errors="ignore")
        hook_input["custom_instructions"] = governance
    return {}
