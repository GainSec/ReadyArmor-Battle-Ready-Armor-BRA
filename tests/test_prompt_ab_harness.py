from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, relative_path: str) -> types.ModuleType:
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class PromptAbHarnessTests(unittest.IsolatedAsyncioTestCase):
    def test_compact_prompt_removes_formatting_only_blank_lines(self) -> None:
        module = _load_module("prompt_ab_harness_compact", "tools/prompt_ab_harness.py")
        prompt = "\n".join(
            [
                "## Header",
                "",
                "Line one",
                "",
                "",
                "- a",
                "- b",
                "",
                "1. first",
                "2. second",
                "",
                "| A | B |",
                "|---|---|",
                "| x | y |",
                "",
                "Paragraph two",
                "",
            ]
        )

        compacted = module.compact_prompt(prompt)

        self.assertIn("## Header\nLine one", compacted)
        self.assertNotIn("\n\n\n", compacted)
        self.assertIn("- a\n- b", compacted)
        self.assertIn("1. first\n2. second", compacted)
        self.assertIn("| A | B |\n|---|---|\n| x | y |", compacted)
        self.assertTrue(compacted.endswith("Paragraph two"))

    def test_aggressive_compact_prompt_collapses_sections_but_keeps_option_numbers(self) -> None:
        module = _load_module("prompt_ab_harness_aggressive", "tools/prompt_ab_harness.py")
        prompt = "\n".join(
            [
                "▶ PREFLIGHT CHECK",
                "",
                "  Kill switch (CLAUDE.md)... CLEAR",
                "  Governance files (layer1/rules/)... OK",
                "",
                "## Tool Resolution",
                "",
                "### Available (2)",
                "- adb",
                "- apktool",
                "",
                "### Missing (1)",
                "- ffuf",
                "",
                "## Engagement Summary",
                "",
                "Target: Android Auto Dongle",
                "Phase: Intelligence",
                "Time: now",
                "",
                "## FIRST ACTION: Validate Scope",
                "",
                "Before proceeding:",
                "  1. Read layer3-engagement/SCOPE.md completely",
                "  2. Validate scope",
                "     1. Confirm scope and proceed",
                "     2. Revise scope",
                "     3. Ask a clarifying question",
                "     4. Cancel engagement",
            ]
        )

        compacted = module.aggressive_compact_prompt(prompt)

        self.assertLess(len(compacted.splitlines()), len(prompt.splitlines()))
        self.assertIn("▶ PREFLIGHT CHECK: Kill switch (CLAUDE.md)... CLEAR; Governance files (layer1/rules/)... OK", compacted)
        self.assertIn("Available tools: adb, apktool", compacted)
        self.assertIn("Missing tools: ffuf", compacted)
        self.assertIn("Target: Android Auto Dongle | Phase: Intelligence | Time: now", compacted)
        self.assertIn("1. Confirm scope and proceed", compacted)
        self.assertIn("4. Cancel engagement", compacted)

    def test_fixed_first_turn_prompt_removes_skip_path_and_preserves_required_scope_flow(self) -> None:
        module = _load_module("prompt_ab_harness_fixed", "tools/prompt_ab_harness.py")
        prompt = "\n".join(
            [
                "## FIRST ACTION: Validate Scope",
                "",
                "Before proceeding with any methodology work, you MUST:",
                "",
                "  1. Read layer3-engagement/SCOPE.md completely",
                "  2. Validate and normalize the scope data",
                "  3. Present a BRIEF summary of the validated scope",
                "  4. End with 'What would you like to do?' followed by these exact options:",
                "",
                "     1. Confirm scope and proceed",
                "     2. Revise scope (tell me what to change)",
                "     3. Ask a clarifying question",
                "     4. Cancel engagement",
                "",
                "## CRITICAL: Human-in-the-Loop Requirement",
                "",
                "Step 1: Describe what you WANT to do (do not do it yet)",
                "Step 2: Present options including the proposed action",
                "Step 3: STOP and WAIT for user to select",
            ]
        )

        fixed = module.fixed_first_turn_prompt(prompt)

        self.assertIn("scope validation is required", fixed)
        self.assertIn("1. Read and validate scope", fixed)
        self.assertIn("2. Revise scope before validation", fixed)
        self.assertIn("3. Ask a clarifying question", fixed)
        self.assertIn("4. Cancel engagement", fixed)
        self.assertIn("1. Confirm scope and proceed", fixed)
        self.assertNotIn("Skip scope validation", fixed)

    async def test_run_case_collects_assistant_and_result_text(self) -> None:
        module = _load_module("prompt_ab_harness_run_case", "tools/prompt_ab_harness.py")

        assistant = types.SimpleNamespace(
            content=[types.SimpleNamespace(text="First line"), types.SimpleNamespace(text="Second line")]
        )
        result = types.SimpleNamespace(result="Final line", is_error=False)

        async def fake_run_agent(prompt: str, *, allowed_tools: list[str], model: str | None = None):
            self.assertEqual(prompt, "PROMPT")
            self.assertEqual(allowed_tools, module.DEFAULT_ALLOWED_TOOLS)
            self.assertEqual(model, "test-model")
            yield assistant
            yield result

        with mock.patch.object(module, "run_agent", side_effect=fake_run_agent):
            case = await module.run_case("baseline", "PROMPT", model="test-model")

        self.assertEqual(case["name"], "baseline")
        self.assertEqual(case["response"], "First line\nSecond line\nFinal line")
        self.assertEqual(case["prompt_stats"]["lines"], 1)

    async def test_run_case_falls_back_to_dict_messages(self) -> None:
        module = _load_module("prompt_ab_harness_dict_case", "tools/prompt_ab_harness.py")

        async def fake_run_agent(prompt: str, *, allowed_tools: list[str], model: str | None = None):
            yield {"type": "assistant_text", "content": "Alpha"}
            yield {"type": "text", "content": "Beta"}

        with mock.patch.object(module, "run_agent", side_effect=fake_run_agent):
            case = await module.run_case("baseline", "PROMPT", model=None)

        self.assertEqual(case["response"], "Alpha\nBeta")

    async def test_run_case_returns_partial_output_on_timeout(self) -> None:
        module = _load_module("prompt_ab_harness_timeout_case", "tools/prompt_ab_harness.py")

        async def fake_run_agent(prompt: str, *, allowed_tools: list[str], model: str | None = None):
            yield {"type": "assistant_text", "content": "Alpha"}
            await module.asyncio.sleep(0.02)
            while True:
                await module.asyncio.sleep(1)

        with mock.patch.object(module, "run_agent", side_effect=fake_run_agent):
            case = await module.run_case("baseline", "PROMPT", timeout_seconds=0.01)

        self.assertIn("Timed out", case["response"])

    def test_extract_anthropic_response_text_collects_text_blocks(self) -> None:
        module = _load_module("prompt_ab_harness_anthropic_extract", "tools/prompt_ab_harness.py")
        payload = {
            "content": [
                {"type": "text", "text": "Alpha"},
                {"type": "tool_use", "name": "Read"},
                {"type": "text", "text": "Beta"},
            ]
        }
        self.assertEqual(module.extract_anthropic_response_text(payload), "Alpha\nBeta")

    def test_extract_openai_response_text_collects_message_content(self) -> None:
        module = _load_module("prompt_ab_harness_openai_extract", "tools/prompt_ab_harness.py")
        payload = {
            "choices": [
                {
                    "message": {
                        "content": [
                            {"type": "text", "text": "Alpha"},
                            {"type": "text", "text": "Beta"},
                        ]
                    }
                }
            ]
        }
        self.assertEqual(module.extract_openai_response_text(payload), "Alpha\nBeta")

    def test_write_report_persists_cases_and_summary(self) -> None:
        module = _load_module("prompt_ab_harness_report", "tools/prompt_ab_harness.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir)
            cases = [
                {
                    "name": "baseline",
                    "prompt": "A",
                    "response": "B",
                    "prompt_stats": {"chars": 1, "lines": 1, "non_empty_lines": 1},
                    "response_stats": {"chars": 1, "lines": 1, "non_empty_lines": 1},
                },
                {
                    "name": "compact",
                    "prompt": "AA",
                    "response": "BB",
                    "prompt_stats": {"chars": 2, "lines": 1, "non_empty_lines": 1},
                    "response_stats": {"chars": 2, "lines": 1, "non_empty_lines": 1},
                },
            ]

            summary_path = module.write_report(outdir, cases)

            self.assertTrue(summary_path.exists())
            summary = summary_path.read_text(encoding="utf-8")
            self.assertIn("baseline", summary)
            self.assertIn("compact", summary)
            manifest = json.loads((outdir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(len(manifest["cases"]), 2)

    def test_ensure_proxy_api_key_sets_placeholder_when_proxy_enabled(self) -> None:
        module = _load_module("prompt_ab_harness_proxy_key", "tools/prompt_ab_harness.py")
        with mock.patch.object(module, "get_proxy_config", return_value={"proxy_enabled": True}):
            with mock.patch.dict(module.os.environ, {}, clear=True):
                module.ensure_proxy_api_key()
                self.assertEqual(module.os.environ["ANTHROPIC_API_KEY"], "proxy-routed")


if __name__ == "__main__":
    unittest.main()
