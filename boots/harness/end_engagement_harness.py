"""EndEngagement harness — preview the end-engagement script sequence (INACTIVE)."""

from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator

from boots.harness.base import BaseHarness, HarnessResult, ParamSpec


class EndEngagementHarness(BaseHarness):
    name = "end_engagement"
    label = "End Engagement"
    description = "Preview the end-engagement script sequence (execution not yet available)"
    executable = False

    def parameters(self) -> list[ParamSpec]:
        return [
            ParamSpec(
                name="vendor",
                type="checkbox",
                required=False,
                default="true",
                help="Generate vendor submission package",
            ),
            ParamSpec(
                name="cna",
                type="checkbox",
                required=False,
                default="false",
                help="Generate CNA submission package",
            ),
            ParamSpec(
                name="generic",
                type="checkbox",
                required=False,
                default="true",
                help="Generate generic disclosure package",
            ),
        ]

    def build_prompt(self, params: dict, bra_root: Path) -> HarnessResult:
        types: list[str] = []
        if params.get("vendor", "true").lower() in ("true", "1", "yes"):
            types.append("vendor")
        if params.get("cna", "false").lower() in ("true", "1", "yes"):
            types.append("cna")
        if params.get("generic", "true").lower() in ("true", "1", "yes"):
            types.append("generic")

        disclosure_types = ", ".join(types) if types else "(none selected)"

        sequence = [
            "1. stats.sh          — Collect engagement statistics",
            "2. report-ready.sh   — Generate final report",
            f"3. disclose.sh       — Build disclosure packages ({disclosure_types})",
            "4. lessons-learned.sh — Generate retrospective",
        ]

        prompt = (
            "End-Engagement Script Sequence Preview\n"
            "======================================\n\n"
            "The following scripts would be executed in order:\n\n"
            + "\n".join(sequence)
            + "\n\n"
            "This harness is currently INACTIVE. Execution is not yet available.\n"
            "Use this preview to verify the sequence before manual execution."
        )

        return HarnessResult(
            prompt=prompt,
            allowed_tools=[],
            metadata={
                "disclosure_types": types,
                "note": "INACTIVE — execution not yet available",
                "source": "body/layer1/scripts/{stats,report-ready,disclose,lessons-learned}.sh",
            },
        )

    async def execute(self, params: dict, bra_root: Path) -> AsyncIterator[str]:
        raise NotImplementedError(
            "end_engagement harness is inactive — execution not yet available"
        )
        yield  # pragma: no cover — makes this an async generator


harness = EndEngagementHarness()
