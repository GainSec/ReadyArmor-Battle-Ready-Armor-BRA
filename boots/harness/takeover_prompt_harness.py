"""TakeoverPrompt harness — preview the hidden 2x4 takeover prompt payload."""

from __future__ import annotations

import json
from pathlib import Path
from typing import AsyncIterator

from boots.harness.base import BaseHarness, HarnessResult, ParamSpec
from boots.takeover import TakeoverController


class TakeoverPromptHarness(BaseHarness):
    name = "takeover_prompt"
    label = "2x4 Takeover Prompt"
    description = "Preview the hidden backend prompt/context used for Engage takeover decisions"
    executable = False

    def parameters(self) -> list[ParamSpec]:
        return [
            ParamSpec(
                name="event_type",
                type="select",
                required=False,
                default="awaiting_input",
                help="Engage event type to build preview context for",
                options=[
                    "awaiting_input",
                    "approval_token",
                    "approval_scope_add",
                    "approval_scope_upgrade",
                    "approval_script",
                    "approval_tool",
                ],
            ),
            ParamSpec(
                name="recent_chat",
                type="textarea",
                required=False,
                default="",
                help="Optional recent user chat message to include in context preview",
            ),
        ]

    def build_prompt(self, params: dict, bra_root: Path) -> HarnessResult:
        event_type = str(params.get("event_type") or "awaiting_input").strip() or "awaiting_input"
        recent_chat = str(params.get("recent_chat") or "").strip()

        context: dict[str, object] = {"event": {"type": event_type}}
        if recent_chat:
            context["recent_chat"] = [{"role": "user", "content": recent_chat}]

        config_file = Path(__file__).resolve().parents[1] / ".bra-gui-config.json"
        config: dict[str, object] = {}
        if config_file.exists():
            try:
                parsed = json.loads(config_file.read_text(encoding="utf-8"))
                if isinstance(parsed, dict):
                    config = parsed
            except Exception:
                config = {}

        controller = TakeoverController()
        controller.configure_relay_settings(config)
        payload = controller.build_query_payload(context)
        prompt = json.dumps(payload, indent=2)

        return HarnessResult(
            prompt=prompt,
            allowed_tools=[],
            metadata={"source": "boots/takeover.py:TakeoverController.build_query_payload"},
        )

    async def execute(self, params: dict, bra_root: Path) -> AsyncIterator[str]:
        raise NotImplementedError("takeover_prompt harness is preview-only")
        yield  # pragma: no cover


harness = TakeoverPromptHarness()
