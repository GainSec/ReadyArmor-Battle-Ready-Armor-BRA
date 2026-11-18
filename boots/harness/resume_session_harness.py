"""ResumeSession harness — preview the prompt sent when resuming an existing agent session."""

from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator

from boots.harness.base import BaseHarness, HarnessResult, ParamSpec
from bra.core.host_context import build_host_context_block

ALL_TOOLS = ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch"]


class ResumeSessionHarness(BaseHarness):
    name = "resume_session"
    label = "Resume Session"
    description = "Preview the prompt sent when resuming an existing agent session"

    def parameters(self) -> list[ParamSpec]:
        return [
            ParamSpec(
                name="session_id",
                type="text",
                required=False,
                default="",
                help="Session ID to resume (blank for auto-detect)",
            ),
            ParamSpec(
                name="prompt",
                type="textarea",
                required=False,
                default="Continue.",
                help="Resume prompt to send",
            ),
        ]

    def build_prompt(self, params: dict, bra_root: Path) -> HarnessResult:
        prompt = (params.get("prompt") or "").strip() or "Continue."
        session_id = (params.get("session_id") or "").strip()

        if "## Host Environment" not in prompt:
            host_block = build_host_context_block()
            prompt = f"{prompt}\n\n{host_block}"

        return HarnessResult(
            prompt=prompt,
            allowed_tools=ALL_TOOLS,
            metadata={
                "session_id": session_id or "(auto-detect at runtime)",
                "source": "head/bra/core/agent.py:run_agent(resume_session=...)",
            },
        )

    async def execute(self, params: dict, bra_root: Path) -> AsyncIterator[str]:
        from bra.core.agent import run_agent

        result = self.build_prompt(params, bra_root)
        session_id = (params.get("session_id") or "").strip() or None
        async for message in run_agent(
            result.prompt,
            allowed_tools=ALL_TOOLS,
            resume_session=session_id,
        ):
            yield message


harness = ResumeSessionHarness()
