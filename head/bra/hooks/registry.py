"""SDK hooks registry.

Builds the hooks configuration for the Claude Agent SDK.
Hooks delegate to body's existing bash scripts for governance.

HOOK ORDER (PreToolUse):
1. Kill switch - absolute stop, no override
2. Tool approval - mechanical human-in-the-loop (if enabled)
3. Finding guard - block all tools when findings pending
4. Bash guard - dangerous command detection
5. File guard - filesystem protection

PreCompact:
- Governance persistence — re-injects CLAUDE.md into custom_instructions
  so governance survives context compaction on long sessions.

MECHANICAL ENFORCEMENT:
When tool approval is enabled, non-exempt tools require explicit user approval.
This is in addition to other governance checks.
"""

from typing import Any

from bra.hooks.types import HookMatcher, HookEvent


def build_documentation_hooks() -> dict[HookEvent, list[HookMatcher]]:
    """Hooks for the findings documentation subagent.

    Drops finding guard only — subagent IS the one clearing findings so
    blocking it on pending findings is a deadlock. Keeps everything else
    including file guard (subagent output uses a safe filename + numbered
    format that passes all content checks).
    """
    from bra.hooks.killswitch import check_killswitch_hook
    from bra.hooks.bash_hook import pre_bash
    from bra.hooks.file_hook import pre_file, pre_read, pre_grep, pre_glob
    from bra.hooks.post_hook import post_tool
    from bra.hooks.tool_approval_hook import check_tool_approval_hook

    return {
        "PreToolUse": [
            HookMatcher(matcher="*", hooks=[check_killswitch_hook]),
            HookMatcher(matcher="*", hooks=[check_tool_approval_hook]),
            HookMatcher(matcher="Bash", hooks=[pre_bash]),
            HookMatcher(matcher="Read", hooks=[pre_read]),
            HookMatcher(matcher="Grep", hooks=[pre_grep]),
            HookMatcher(matcher="Glob", hooks=[pre_glob]),
            HookMatcher(matcher="Write|Edit", hooks=[pre_file]),
        ],
        "PostToolUse": [
            HookMatcher(matcher="*", hooks=[post_tool]),
        ],
    }


def build_hooks() -> dict[HookEvent, list[HookMatcher]]:
    """Build SDK hooks configuration.

    Returns:
        Dict with PreToolUse and PostToolUse hook lists
    """
    from bra.hooks.killswitch import check_killswitch_hook
    from bra.hooks.bash_hook import pre_bash
    from bra.hooks.file_hook import pre_file, pre_read, pre_grep, pre_glob
    from bra.hooks.finding_guard import pre_finding_guard
    from bra.hooks.post_hook import post_tool
    from bra.hooks.tool_approval_hook import check_tool_approval_hook
    from bra.hooks.compact_hook import pre_compact

    return {
        "PreToolUse": [
            # Kill switch - checked on EVERY tool use (highest priority)
            HookMatcher(matcher="*", hooks=[check_killswitch_hook]),
            # Tool approval - mechanical human-in-the-loop (if enabled)
            # Runs BEFORE other checks so user sees approval before governance
            HookMatcher(matcher="*", hooks=[check_tool_approval_hook]),
            # Finding guard - block all tools when findings pending
            HookMatcher(matcher="*", hooks=[pre_finding_guard]),
            # Bash commands: full bash-guard.py chain
            HookMatcher(matcher="Bash", hooks=[pre_bash]),
            # File reads/searches: delegate to file-guard.py through file_hook.py
            HookMatcher(matcher="Read", hooks=[pre_read]),
            HookMatcher(matcher="Grep", hooks=[pre_grep]),
            HookMatcher(matcher="Glob", hooks=[pre_glob]),
            # File writes/edits: delegate to file-guard.py through file_hook.py
            HookMatcher(matcher="Write|Edit", hooks=[pre_file]),
        ],
        "PostToolUse": [
            # Audit trail - all tools
            HookMatcher(matcher="*", hooks=[post_tool]),
        ],
        "PreCompact": [
            # Re-inject CLAUDE.md governance before compaction
            HookMatcher(matcher="*", hooks=[pre_compact]),
        ],
    }
