from __future__ import annotations

import importlib.util
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


class WebPromptAbHarnessTests(unittest.IsolatedAsyncioTestCase):
    def test_build_prompt_with_custom_fixed_variant(self) -> None:
        module = _load_module("web_prompt_ab_harness_custom", "boots/harness/prompt_ab_harness.py")
        harness = module.harness

        with tempfile.TemporaryDirectory() as tmpdir:
            bra_root = Path(tmpdir)
            result = harness.build_prompt(
                {
                    "source": "custom",
                    "prompt": "## FIRST ACTION: Validate Scope\n1. Read layer3-engagement/SCOPE.md completely",
                    "variant": "fixed",
                },
                bra_root,
            )

        self.assertIn("scope validation is required", result.prompt)
        self.assertIn("1. Read and validate scope", result.prompt)
        self.assertEqual(result.metadata["variant"], "fixed")
        self.assertEqual(result.metadata["source_kind"], "custom")

    def test_build_prompt_with_live_engagement_source_uses_handler_output(self) -> None:
        module = _load_module("web_prompt_ab_harness_live", "boots/harness/prompt_ab_harness.py")
        harness = module.harness

        fake_result = types.SimpleNamespace(returncode=0, stdout="LIVE PROMPT", stderr="")
        with tempfile.TemporaryDirectory() as tmpdir:
            bra_root = Path(tmpdir)
            with mock.patch.object(module, "run_script", return_value=fake_result):
                with mock.patch.object(module, "build_host_context_block", return_value="## Host Environment\nHost: test"):
                    result = harness.build_prompt({"source": "engagement_handoff", "variant": "baseline"}, bra_root)

        self.assertIn("LIVE PROMPT", result.prompt)
        self.assertIn("## Host Environment", result.prompt)
        self.assertEqual(result.metadata["source_kind"], "engagement_handoff")

    async def test_execute_backend_yields_response_text(self) -> None:
        module = _load_module("web_prompt_ab_harness_exec", "boots/harness/prompt_ab_harness.py")
        harness = module.harness

        async def fake_backend(name: str, prompt: str, *, model: str | None = None, timeout_seconds: float = 120.0):
            self.assertEqual(name, "fixed")
            self.assertIn("scope validation is required", prompt)
            self.assertEqual(model, "qwen3")
            self.assertEqual(timeout_seconds, 30.0)
            return {
                "name": name,
                "prompt": prompt,
                "response": "OK",
                "prompt_stats": {"chars": len(prompt), "lines": len(prompt.splitlines()), "non_empty_lines": 1},
                "response_stats": {"chars": 2, "lines": 1, "non_empty_lines": 1},
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            bra_root = Path(tmpdir)
            fake_tool_module = types.SimpleNamespace(
                run_case_backend=fake_backend,
                run_case_messages=None,
                _message_text_chunks=lambda message: [],
                compact_prompt=lambda prompt: prompt,
                aggressive_compact_prompt=lambda prompt: prompt,
                fixed_first_turn_prompt=lambda prompt: "scope validation is required\n1. Read and validate scope",
            )
            with mock.patch.object(module, "_prompt_ab_module", return_value=fake_tool_module):
                chunks = []
                async for chunk in harness.execute(
                    {
                        "source": "custom",
                        "prompt": "## FIRST ACTION: Validate Scope\n1. Read layer3-engagement/SCOPE.md completely",
                        "variant": "fixed",
                        "transport": "backend",
                        "model": "qwen3",
                        "timeout_seconds": "30",
                    },
                    bra_root,
                ):
                    chunks.append(chunk)

        self.assertEqual(chunks, ["OK"])


if __name__ == "__main__":
    unittest.main()
