"""FindingProbe harness — investigate, validate, or extend a documented finding."""

from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator

from boots.harness.base import BaseHarness, HarnessResult, ParamSpec
from bra.core.finding_probe import (
    DEFAULT_ALLOWED_TOOLS,
    ProbeConfig,
    _extract_finding_identity_from_intel,
    _normalize_finding_id,
    build_probe_prompt,
)


class FindingProbeHarness(BaseHarness):
    name = "finding_probe"
    label = "Finding Probe"
    description = "Investigate, validate, or extend a documented finding"

    def parameters(self) -> list[ParamSpec]:
        return [
            ParamSpec(
                name="finding_id",
                type="text",
                required=True,
                default="001",
                help="Finding ID to probe (e.g. 001, 002)",
            ),
            ParamSpec(
                name="action",
                type="select",
                required=False,
                default="validate",
                help="Probe action to perform",
                options=["validate", "extend", "investigate", "generate_poc"],
            ),
        ]

    def build_prompt(self, params: dict, bra_root: Path) -> HarnessResult:
        finding_id = params.get("finding_id", "").strip()
        if not finding_id:
            raise ValueError("finding_id is required and must not be empty")

        action = params.get("action", "validate")
        finding_id = _normalize_finding_id(finding_id)

        notes_dir = bra_root / "layer3-engagement" / "NOTES"
        bra_state_dir = bra_root / ".bra"
        schema_path = (
            bra_root / "layer2-templates" / "reference" / "evidence" / "findings-schema.md"
        )

        intel_path = notes_dir / "INTEL.md"
        intel_text = intel_path.read_text(errors="replace") if intel_path.exists() else ""

        severity, title, source_marker = _extract_finding_identity_from_intel(
            intel_text, finding_id
        )

        profile = str(action or "validate").strip().lower()
        if profile not in {"validate", "extend", "investigate", "generate_poc"}:
            profile = "validate"

        max_file_chars = 8000
        max_context_chars = 26000
        include_tools = False
        extra_instructions: list[str] = []
        if profile == "validate":
            extra_instructions = [
                "Optimize for first-pass schema-valid completion.",
                "Keep it concise and prefer Unknown (pending capture) over speculation.",
                "Do not spend output budget on optional enrichment.",
            ]
        elif profile == "extend":
            max_file_chars = 20000
            max_context_chars = 70000
            include_tools = True
            extra_instructions = [
                "Enrich the existing finding with higher-fidelity impact, attack vector, and remediation detail.",
                "Refine CVSS to match concrete observed evidence.",
            ]
        elif profile == "investigate":
            max_file_chars = 10000
            max_context_chars = 40000
            include_tools = True
            extra_instructions = [
                "Prioritize evidence gap analysis and concrete follow-up capture commands.",
                "If required facts are missing, keep Unknown (pending capture) and avoid fabrication.",
            ]
        elif profile == "generate_poc":
            max_file_chars = 12000
            max_context_chars = 45000
            include_tools = True
            extra_instructions = [
                "Prioritize a robust, executable PoC artifact and evidence artifact.",
                "Keep the markdown finding body minimal and consistent with known facts.",
            ]

        cfg = ProbeConfig(
            finding_id=finding_id,
            severity=severity,
            title=title,
            source_marker=source_marker,
            notes_dir=notes_dir,
            bra_state_dir=bra_state_dir,
            schema_path=schema_path,
            model=None,
            max_file_chars=max_file_chars,
            max_context_chars=max_context_chars,
            context_files=[],
            extra_context=[],
            extra_instructions=extra_instructions,
            include_tools=include_tools,
        )

        prompt = build_probe_prompt(cfg)

        return HarnessResult(
            prompt=prompt,
            allowed_tools=list(DEFAULT_ALLOWED_TOOLS) if include_tools else [],
            metadata={
                "finding_id": finding_id,
                "severity": severity,
                "title": title,
                "action": profile,
                "source": "head/bra/core/finding_probe.py",
            },
        )

    async def execute(self, params: dict, bra_root: Path) -> AsyncIterator[str]:
        from bra.core.agent import run_agent

        result = self.build_prompt(params, bra_root)
        async for message in run_agent(
            result.prompt, allowed_tools=result.allowed_tools
        ):
            yield message


harness = FindingProbeHarness()
