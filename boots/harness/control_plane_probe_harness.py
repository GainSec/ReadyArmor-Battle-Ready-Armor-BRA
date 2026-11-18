"""ControlPlaneProbe harness — preview a deterministic 2x4 control-plane probe plan."""

from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator

from boots.harness.base import BaseHarness, HarnessResult


class ControlPlaneProbeHarness(BaseHarness):
    name = "control_plane_probe"
    label = "2x4 Control Plane Probe"
    description = "Preview read-only 2x4 control-plane probe steps used for takeover readiness checks"
    executable = False

    def build_prompt(self, params: dict, bra_root: Path) -> HarnessResult:
        prompt = "\n".join(
            [
                "2x4 control-plane probe (read-only):",
                "1. bra2x4.summary()",
                "2. bra2x4.file('scope')",
                "3. bra2x4.log('engage', tail=200)",
                "4. bra2x4.engage_status()",
                "5. bra2x4.engage_action('review_pending')",
                "Rules: deny scope-add requests, do not mutate files, and ask operator when uncertain.",
                f"BRA root: {bra_root}",
            ]
        )
        return HarnessResult(
            prompt=prompt,
            allowed_tools=[],
            metadata={"source": "boots/harness/control_plane_probe_harness.py"},
        )

    async def execute(self, params: dict, bra_root: Path) -> AsyncIterator[str]:
        raise NotImplementedError("control_plane_probe harness is preview-only")
        yield  # pragma: no cover


harness = ControlPlaneProbeHarness()
