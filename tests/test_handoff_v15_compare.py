from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path


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


class HandoffV15CompareTests(unittest.TestCase):
    def test_generate_handoff_prompt_preserves_v15_marker_contract(self) -> None:
        module = _load_module("handoff_v15_compare_markers", "body/layer1/lib/handoff.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            scope_file = body_root / "layer3-engagement" / "SCOPE.md"
            scope_file.parent.mkdir(parents=True)
            scope_file.write_text(
                "\n".join(
                    [
                        "# Engagement Scope",
                        "",
                        "## Target Definition",
                        "",
                        "**Name:** Android Auto Dongle",
                        "**Target Type:** iot",
                        "**Version:** Unknown",
                        "",
                        "### Targets",
                        "",
                        "- 192.168.18.9",
                        "",
                        "---",
                    ]
                ),
                encoding="utf-8",
            )
            prompt = module.generate_handoff_prompt("Intelligence", "", body_root=body_root)
        self.assertIn("Intel Capture Format", prompt)
        self.assertIn("[SERVICE]", prompt)
        self.assertIn("[ENDPOINT]", prompt)
        self.assertIn("[LEAD]", prompt)
        self.assertIn("a port, an endpoint, a target property, a lead, or other security-relevant", prompt)
        self.assertIn("The framework captures markers automatically into the intel record.", prompt)
        self.assertIn("If valuable intel does not fit one", prompt)
        self.assertIn("you may create a concise uppercase marker [CATEGORY].", prompt)
        self.assertIn("markers accumulate automatically", prompt)
        self.assertNotIn("Format reference: layer2-templates/reference/evidence/intel-schema.md", prompt)
        self.assertNotIn("write to INTEL.md directly", prompt)
        self.assertNotIn("markers accumulate in INTEL.md automatically", prompt)
        self.assertIn("## Existing Artifacts", prompt)
        self.assertIn("## Questions for You", prompt)
        self.assertIn("## CRITICAL: Human-in-the-Loop Requirement", prompt)
        self.assertIn("## Targets (From Layer 3)", prompt)
        self.assertNotIn("## Targets (Layer 3: SCOPE.md)", prompt)

    def test_generate_handoff_prompt_restores_v15_human_loop_language(self) -> None:
        module = _load_module("handoff_v15_compare_transition", "body/layer1/lib/handoff.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            scope_file = body_root / "layer3-engagement" / "SCOPE.md"
            scope_file.parent.mkdir(parents=True)
            scope_file.write_text("# Engagement Scope\n", encoding="utf-8")
            prompt = module.generate_handoff_prompt("Intelligence", "", body_root=body_root)
        self.assertIn("WARNING: You MUST stop and wait for human approval before EVERY action.", prompt)
        self.assertIn("DO NOT execute commands without explicit user approval", prompt)
        self.assertIn("STOP after EVERY response and wait for user input", prompt)
        self.assertIn("Step 1: Describe what you WANT to do (do not do it yet)", prompt)
        self.assertIn("Step 2: Present options including the proposed action", prompt)
        self.assertIn("Step 3: STOP and WAIT for user to select", prompt)
        self.assertIn("Step 4: Only execute AFTER user explicitly approves", prompt)
        self.assertNotIn("Operator-facing output contract:", prompt)
        self.assertNotIn("First response after scope intake:", prompt)
        self.assertNotIn("Subsequent turns:", prompt)
        self.assertNotIn("Preferred operator loop example:", prompt)

    def test_generate_handoff_prompt_forbids_operator_facing_file_leakage_and_first_person_options(self) -> None:
        module = _load_module("handoff_v15_compare_output_style", "body/layer1/lib/handoff.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            scope_file = body_root / "layer3-engagement" / "SCOPE.md"
            scope_file.parent.mkdir(parents=True)
            scope_file.write_text("# Engagement Scope\n", encoding="utf-8")
            prompt = module.generate_handoff_prompt("Intelligence", "", body_root=body_root)
        self.assertIn("Do not mention internal document names, file paths, markdown filenames, or repository structure in operator-facing chat output.", prompt)
        self.assertIn("Selectable options must be plain action labels only.", prompt)
        self.assertIn("Do not use first-person phrasing in options such as \"I'll\", \"I will\", or parenthetical planning text.", prompt)
        self.assertIn("After the initial scope-validation turn, do not restate unchanged target, authorization, interface, scope, hotspot, or other engagement-context facts in later replies.", prompt)
        self.assertIn("On later turns, summarize only what changed, what was learned, or why the next step is being proposed.", prompt)
        self.assertIn("Do not repeat \"Scope confirmed\" or re-issue the scope summary after the initial scope-validation turn unless the scope actually changed.", prompt)

    def test_generate_brief_handoff_matches_expected_v17_or_intentional_v15_drift(self) -> None:
        module = _load_module("handoff_v15_compare_brief", "body/layer1/lib/handoff.py")
        text = module.generate_brief_handoff("ping", "ok")
        self.assertIn("Action Complete", text)
