"""AgentPrompt harness — send an arbitrary prompt to the agent with host context."""

from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator

from boots.harness.base import BaseHarness, HarnessResult, ParamSpec
from bra.core.host_context import build_host_context_block

ALL_TOOLS = ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch"]


class AgentPromptHarness(BaseHarness):
    name = "agent_prompt"
    label = "Custom Agent Prompt"
    description = "Send an arbitrary prompt to the agent with host context"

    def parameters(self) -> list[ParamSpec]:
        return [
            ParamSpec(
                name="prompt",
                type="textarea",
                required=True,
                default="",
                help="The prompt to send to the agent",
            ),
            ParamSpec(
                name="model",
                type="select",
                required=False,
                default="default",
                help="Model to use for the agent",
                options=["default", "sonnet", "opus", "haiku"],
            ),
        ]

    def build_prompt(self, params: dict, bra_root: Path) -> HarnessResult:
        prompt = (params.get("prompt") or "").strip()
        if not prompt:
            raise ValueError("prompt is required and must not be empty")

        model_choice = params.get("model", "default")
        model = None if model_choice == "default" else model_choice

        if "## Host Environment" not in prompt:
            host_block = build_host_context_block()
            prompt = f"{prompt}\n\n{host_block}"

        return HarnessResult(
            prompt=prompt,
            allowed_tools=ALL_TOOLS,
            metadata={
                "model": model,
                "source": "head/bra/core/agent.py:run_agent",
            },
        )

    async def execute(self, params: dict, bra_root: Path) -> AsyncIterator[str]:
        from bra.core.agent import run_agent

        result = self.build_prompt(params, bra_root)
        model = result.metadata.get("model")
        async for message in run_agent(
            result.prompt, allowed_tools=ALL_TOOLS, model=model
        ):
            yield message


harness = AgentPromptHarness()
