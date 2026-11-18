"""FindingsWebHarness — wraps findings_flow.py prompt logic in the BaseHarness interface.

This module does NOT modify findings_flow.py. It imports the existing
prompt-building functions and exposes them through the standard harness API
so the web GUI can drive the same logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator

from boots.harness.base import BaseHarness, HarnessResult, ParamSpec
from boots.harness.findings_flow import (
    ALLOWED_TOOLS,
    DEFAULT_USER_PROMPT,
    _resolve_api_key,
    build_effective_prompt,
    extract_finding_entry,
    resolve_finding,
    run_finding_flow,
)
from bra.config.settings import set_bra_root
from bra.core.finding_enforcer import FindingEnforcer


class FindingsWebHarness(BaseHarness):
    name = "findings_flow"
    label = "Finding Documentation"
    description = "Build the exact prompt boots sends when findings are pending"

    def parameters(self) -> list[ParamSpec]:
        return [
            ParamSpec(
                name="finding_id",
                type="text",
                required=True,
                default="001",
                help="Finding ID to document (e.g. 001, 002)",
            ),
            ParamSpec(
                name="user_prompt",
                type="textarea",
                required=False,
                default=DEFAULT_USER_PROMPT,
                help="Deferred user prompt appended after the documentation instructions",
            ),
            ParamSpec(
                name="timeout_seconds",
                type="text",
                required=False,
                default="300",
                help="Hard timeout in seconds for model execution",
            ),
            ParamSpec(
                name="print_finding_entry",
                type="checkbox",
                required=False,
                default="false",
                help="After execution, print full FINDINGS.md entry for this finding",
            ),
        ]

    def build_prompt(self, params: dict, bra_root: Path) -> HarnessResult:
        finding_id = params.get("finding_id", "").strip()
        if not finding_id:
            raise ValueError("finding_id is required and must not be empty")

        set_bra_root(bra_root)

        notes_dir = bra_root / "layer3-engagement" / "NOTES"
        bra_state_dir = bra_root / ".bra"

        enforcer = FindingEnforcer(notes_dir, bra_state_dir)

        target, pending = resolve_finding(enforcer, finding_id)

        user_prompt = params.get("user_prompt") or DEFAULT_USER_PROMPT
        prompt = build_effective_prompt(enforcer, target, pending, user_prompt)

        print_entry = str(params.get("print_finding_entry", "false")).strip().lower() not in (
            "0",
            "false",
            "no",
            "off",
        )

        return HarnessResult(
            prompt=prompt,
            allowed_tools=ALLOWED_TOOLS,
            metadata={
                "finding_id": target.id,
                "severity": target.severity,
                "title": target.title,
                "pending_count": len(pending),
                "print_finding_entry": print_entry,
            },
        )

    async def execute(self, params: dict, bra_root: Path) -> AsyncIterator[str]:
        finding_id = params.get("finding_id", "").strip()
        if not finding_id:
            raise ValueError("finding_id is required and must not be empty")

        set_bra_root(bra_root)
        notes_dir = bra_root / "layer3-engagement" / "NOTES"
        bra_state_dir = bra_root / ".bra"
        enforcer = FindingEnforcer(notes_dir, bra_state_dir)
        target, pending = resolve_finding(enforcer, finding_id)

        # Mirror findings_flow.py: avoid model call when fastpath can dequeue now.
        if enforcer.is_fastpath_enabled():
            preflight_dequeued = enforcer.check_and_dequeue_completed()
            if target.id in preflight_dequeued:
                yield f"[info] Fastpath preflight validated FINDING-{target.id}; skipping model run\n"
                return

        user_prompt = params.get("user_prompt") or DEFAULT_USER_PROMPT
        prompt = build_effective_prompt(enforcer, target, pending, user_prompt)
        try:
            timeout_seconds = max(30, int(str(params.get("timeout_seconds", "300")).strip() or "300"))
        except ValueError:
            timeout_seconds = 300
        if not _resolve_api_key():
            raise ValueError(
                "No API key found (set ANTHROPIC_API_KEY or place apikey.txt in boots/harness/)"
            )
        output = await run_finding_flow(prompt, show_events=True, timeout_seconds=timeout_seconds)
        yield output

        print_entry = str(params.get("print_finding_entry", "false")).strip().lower() not in (
            "0",
            "false",
            "no",
            "off",
        )
        if print_entry:
            entry = extract_finding_entry(enforcer.findings_path, target.id)
            if entry:
                yield f"\n\n--- FINDINGS.md entry (FINDING-{target.id}) ---\n\n{entry}"
            else:
                yield (
                    f"\n\n[warn] FINDING-{target.id} entry not found in "
                    f"{enforcer.findings_path}\n"
                )


harness = FindingsWebHarness()
