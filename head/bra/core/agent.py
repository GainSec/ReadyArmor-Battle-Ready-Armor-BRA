"""Claude Agent SDK runtime wrapper."""

import os
from pathlib import Path
from typing import Any, AsyncIterator, Optional, Union

from bra.config import settings
from bra.config.settings import get_proxy_config, get_runtime_config
from bra.hooks.registry import build_hooks, build_documentation_hooks

MessageOrError = Union[dict[str, Any], Any]

try:
    from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions  # type: ignore
    from claude_agent_sdk.types import (  # type: ignore
        PermissionResultAllow,
        ToolPermissionContext,
    )

    SDK_AVAILABLE = True
except Exception:
    ClaudeSDKClient = None  # type: ignore
    ClaudeAgentOptions = None  # type: ignore
    PermissionResultAllow = None  # type: ignore
    ToolPermissionContext = None  # type: ignore
    SDK_AVAILABLE = False


DEFAULT_TOOLS = [
    "Bash", "Read", "Write", "Edit",
    "Glob", "Grep", "WebSearch", "WebFetch",
]


def _build_claude_runtime_env(body_root: Path) -> dict[str, str]:
    """Pin Claude CLI state/config/temp under body/.bra for this process."""
    bra_state = body_root / ".bra"
    claude_config_dir = bra_state / ".claude"
    projects_dir = claude_config_dir / "projects"
    tmp_dir = bra_state / "tmp"
    xdg_config_home = bra_state / ".config"
    xdg_cache_home = bra_state / ".cache"
    xdg_data_home = bra_state / ".local" / "share"

    for path in (
        bra_state,
        claude_config_dir,
        projects_dir,
        tmp_dir,
        xdg_config_home,
        xdg_cache_home,
        xdg_data_home,
    ):
        path.mkdir(parents=True, exist_ok=True)

    env = {
        "HOME": str(bra_state),
        "CLAUDE_CONFIG_DIR": str(claude_config_dir),
        "CLAUDE_CODE_TMPDIR": str(tmp_dir),
        "CLAUDE_PROJECTS_DIR": str(projects_dir),
        "BRA_HOST_HOME": str(Path.home()),
        "BRA_ALLOWED_CLAUDE_DIR": str(claude_config_dir),
        "TMPDIR": str(tmp_dir),
        "TMP": str(tmp_dir),
        "TEMP": str(tmp_dir),
        "XDG_CONFIG_HOME": str(xdg_config_home),
        "XDG_CACHE_HOME": str(xdg_cache_home),
        "XDG_DATA_HOME": str(xdg_data_home),
    }
    api_key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if api_key:
        # Keep key source explicit for downstream subprocesses.
        env["ANTHROPIC_API_KEY"] = api_key
    proxy_cfg = get_proxy_config()
    if proxy_cfg["proxy_enabled"]:
        env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{proxy_cfg['proxy_port']}"
    return env


async def run_agent(
    prompt: str,
    allowed_tools: Optional[list[str]] = None,
    resume_session: Optional[str] = None,
    model: Optional[str] = None,
    system_prompt: Optional[str] = None,
    cwd: Optional[str] = None,
    body_root_override: Optional[str | Path] = None,
) -> AsyncIterator[MessageOrError]:
    """Run a Claude agent turn.

    Args:
        prompt: The prompt to send to the agent.
        allowed_tools: List of tool names the agent can use.
        resume_session: Session ID to resume.
        model: Optional Claude model override (e.g. "claude-sonnet-4-6").

    Yields:
        Agent messages and events.
    """
    if not SDK_AVAILABLE:
        yield {
            "type": "error",
            "content": "Claude Agent SDK not installed. Run: pip install claude-agent-sdk",
        }
        return

    if model is None:
        runtime = get_runtime_config()
        model = runtime.get("model")

    if allowed_tools is None:
        allowed_tools = DEFAULT_TOOLS

    hooks = build_documentation_hooks() if system_prompt is not None else build_hooks()

    async def can_use_tool_func(
        tool_name: str,
        tool_input: dict[str, Any],
        context: "ToolPermissionContext",
    ) -> "PermissionResultAllow":
        return PermissionResultAllow()

    effective_body_root = (
        Path(body_root_override).expanduser().resolve()
        if body_root_override is not None
        else Path(settings.BODY_ROOT)
    )
    effective_cwd = cwd if cwd is not None else str(effective_body_root)

    # Inject CLAUDE.md governance on the first turn only. The PreCompact
    # hook in compact_hook.py re-injects it into custom_instructions when
    # the SDK compacts context, so governance survives long sessions.
    if system_prompt is None and resume_session is None:
        claude_md = Path(effective_cwd) / "CLAUDE.md"
        if claude_md.exists():
            governance = claude_md.read_text(encoding="utf-8", errors="ignore")
            prompt = f"{governance}\n\n---\n\n{prompt}"

    option_args: dict[str, Any] = {
        "allowed_tools": allowed_tools,
        "hooks": hooks,
        "permission_mode": "default",
        "can_use_tool": can_use_tool_func,
        "cwd": effective_cwd,
        "env": _build_claude_runtime_env(effective_body_root),
        "resume": resume_session,
    }
    if model:
        option_args["model"] = model
    if system_prompt is not None:
        option_args["system_prompt"] = system_prompt
        option_args["setting_sources"] = []  # don't load CLAUDE.md or project settings

    options = ClaudeAgentOptions(**option_args)
    client = ClaudeSDKClient(options=options)
    try:
        await client.__aenter__()
        await client.query(prompt)
        session_id_yielded = False

        async for message in client.receive_messages():
            if not session_id_yielded:
                session_id = None
                if hasattr(message, "session_id") and message.session_id:
                    session_id = message.session_id
                elif (
                    hasattr(message, "subtype")
                    and getattr(message, "subtype", "") == "init"
                    and hasattr(message, "data")
                ):
                    session_id = getattr(message, "data", {}).get("session_id")

                if session_id:
                    yield {"type": "session_init", "session_id": session_id}
                    session_id_yielded = True
            yield message

            # ResultMessage marks the end of an agent turn. The SDK keeps
            # the session alive for multi-turn use (waiting for another
            # query()), so receive_messages() won't terminate on its own.
            # Break here so the runner can process turn completion, show
            # options, and await user input before calling run_agent again.
            if type(message).__name__ == "ResultMessage":
                try:
                    from bra.core.token_usage import log_sdk_token_usage

                    log_sdk_token_usage(
                        message,
                        body_root=effective_body_root,
                        source="agent_sdk",
                    )
                except Exception:
                    pass
                break
    finally:
        try:
            await client.__aexit__(None, None, None)
        except RuntimeError:
            # anyio cancel scope exited from a different task during
            # application shutdown — safe to suppress.
            pass
