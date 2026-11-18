"""PromptAB harness — preview and run prompt variants through the debug harness tab."""

from __future__ import annotations

import importlib.util
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, AsyncIterator

from boots.harness.base import BaseHarness, HarnessResult, ParamSpec
from bra.config.settings import set_bra_root
from bra.core.agent import run_agent
from bra.core.bridge import run_script
from bra.core.host_context import build_host_context_block

ALL_TOOLS = ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch"]
REPO_ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def _prompt_ab_module():
    path = REPO_ROOT / "tools" / "prompt_ab_harness.py"
    spec = importlib.util.spec_from_file_location("bra_prompt_ab_tool", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load prompt A/B module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("bra_prompt_ab_tool", module)
    spec.loader.exec_module(module)
    return module


def _resolve_base_prompt(source: str, raw_prompt: str, bra_root: Path) -> tuple[str, str]:
    source_kind = str(source or "engagement_handoff").strip().lower()
    if source_kind == "custom":
        prompt = str(raw_prompt or "").strip()
        if not prompt:
            raise ValueError("prompt is required when source=custom")
    else:
        set_bra_root(bra_root)
        result = run_script("agentic-handler.py", timeout=30)
        if result.returncode != 0:
            raise RuntimeError(f"agentic-handler.py failed: {result.stderr}")
        prompt = result.stdout.strip()
        source_kind = "engagement_handoff"

    if "## Host Environment" not in prompt:
        prompt = f"{prompt}\n\n{build_host_context_block()}"
    return prompt, source_kind


def _apply_variant(prompt: str, variant: str) -> str:
    module = _prompt_ab_module()
    selected = str(variant or "baseline").strip().lower()
    if selected == "baseline":
        return prompt
    if selected == "compact":
        return module.compact_prompt(prompt)
    if selected == "aggressive":
        return module.aggressive_compact_prompt(prompt)
    if selected == "fixed":
        return module.fixed_first_turn_prompt(prompt)
    raise ValueError(f"Unknown variant: {variant}")


def _timeout_seconds(params: dict[str, Any]) -> float:
    raw = str(params.get("timeout_seconds", "60") or "60").strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError("timeout_seconds must be a number") from exc
    if value <= 0:
        raise ValueError("timeout_seconds must be greater than 0")
    return value


class PromptAbHarness(BaseHarness):
    name = "prompt_ab"
    label = "Prompt A/B"
    description = "Preview or run prompt variants for engagement-start prompt experiments"

    def parameters(self) -> list[ParamSpec]:
        return [
            ParamSpec(
                name="source",
                type="select",
                required=False,
                default="engagement_handoff",
                help="Base prompt source",
                options=["engagement_handoff", "custom"],
            ),
            ParamSpec(
                name="prompt",
                type="textarea",
                required=False,
                default="",
                help="Custom prompt text when source=custom",
            ),
            ParamSpec(
                name="variant",
                type="select",
                required=False,
                default="fixed",
                help="Prompt variant to preview or run",
                options=["baseline", "compact", "aggressive", "fixed"],
            ),
            ParamSpec(
                name="transport",
                type="select",
                required=False,
                default="sdk",
                help="Execution transport used by Run",
                options=["sdk", "messages", "backend"],
            ),
            ParamSpec(
                name="model",
                type="text",
                required=False,
                default="",
                help="Optional model override",
            ),
            ParamSpec(
                name="timeout_seconds",
                type="text",
                required=False,
                default="60",
                help="Per-run timeout in seconds",
            ),
        ]

    def build_prompt(self, params: dict, bra_root: Path) -> HarnessResult:
        source_prompt, source_kind = _resolve_base_prompt(
            str(params.get("source", "engagement_handoff")),
            str(params.get("prompt", "")),
            bra_root,
        )
        variant = str(params.get("variant", "fixed") or "fixed").strip().lower()
        final_prompt = _apply_variant(source_prompt, variant)
        return HarnessResult(
            prompt=final_prompt,
            allowed_tools=ALL_TOOLS,
            metadata={
                "source_kind": source_kind,
                "variant": variant,
                "transport": str(params.get("transport", "sdk") or "sdk").strip().lower(),
                "model": str(params.get("model", "") or "").strip(),
                "source": "boots/harness/prompt_ab_harness.py + tools/prompt_ab_harness.py",
            },
        )

    async def execute(self, params: dict, bra_root: Path) -> AsyncIterator[str]:
        result = self.build_prompt(params, bra_root)
        transport = str(params.get("transport", "sdk") or "sdk").strip().lower()
        model = str(params.get("model", "") or "").strip() or None
        timeout_seconds = _timeout_seconds(params)
        module = _prompt_ab_module()

        if transport == "sdk":
            async for message in run_agent(result.prompt, allowed_tools=result.allowed_tools, model=model):
                chunks = module._message_text_chunks(message)
                for chunk in chunks:
                    if chunk:
                        yield chunk
            return

        runners = {
            "messages": module.run_case_messages,
            "backend": module.run_case_backend,
        }
        if transport not in runners:
            raise ValueError(f"Unknown transport: {transport}")

        case = await runners[transport](
            str(params.get("variant", "fixed") or "fixed").strip().lower(),
            result.prompt,
            model=model,
            timeout_seconds=timeout_seconds,
        )
        response = str(case.get("response", "") or "").strip()
        if response:
            yield response


harness = PromptAbHarness()
