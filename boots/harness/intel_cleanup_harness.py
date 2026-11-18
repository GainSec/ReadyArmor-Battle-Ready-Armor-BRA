"""IntelCleanup harness — consolidate and clean up INTEL.md entries."""

from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator

from boots.harness.base import BaseHarness, HarnessResult, ParamSpec
from bra.core.intel_cleanup import _build_cleanup_prompt


class IntelCleanupHarness(BaseHarness):
    name = "intel_cleanup"
    label = "INTEL Cleanup"
    description = "Consolidate and clean up INTEL.md entries"

    def parameters(self) -> list[ParamSpec]:
        return []

    def build_prompt(self, params: dict, bra_root: Path) -> HarnessResult:
        notes_dir = bra_root / "layer3-engagement" / "NOTES"
        prompt = _build_cleanup_prompt(notes_dir)

        return HarnessResult(
            prompt=prompt,
            allowed_tools=["Read", "Write"],
            metadata={
                "source": "head/bra/core/intel_cleanup.py:31-54",
            },
        )

    async def execute(self, params: dict, bra_root: Path) -> AsyncIterator[str]:
        from bra.core.agent import run_agent

        result = self.build_prompt(params, bra_root)
        async for message in run_agent(
            result.prompt, allowed_tools=["Read", "Write"]
        ):
            yield message


harness = IntelCleanupHarness()
