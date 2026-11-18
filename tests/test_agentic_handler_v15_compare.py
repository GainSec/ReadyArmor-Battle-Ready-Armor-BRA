from __future__ import annotations

import contextlib
import importlib.util
import io
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


class AgenticHandlerV15CompareTests(unittest.TestCase):
    def test_generate_handoff_prefers_handoff_library_when_available(self) -> None:
        module = _load_module("agentic_handler_v15_compare_library", "body/layer1/scripts/agentic-handler.py")
        handoff = types.SimpleNamespace(generate_handoff_prompt=lambda phase, meth, body_root: f"LIB:{phase}:{meth}:{body_root.name}")
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpdir, contextlib.redirect_stdout(stdout):
            body_root = Path(tmpdir)
            module._generate_handoff(body_root, {"handoff": handoff}, "iot", "layer2-templates/method.md", "Intelligence")
        output = stdout.getvalue()
        self.assertIn("LIB:Intelligence:layer2-templates/method.md", output)
        self.assertNotIn("Subsequent turns:", output)

    def test_fallback_handoff_includes_v15_marker_and_human_loop_contract(self) -> None:
        module = _load_module("agentic_handler_v15_compare_fallback", "body/layer1/scripts/agentic-handler.py")
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
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                module._generate_layer_aware_handoff(body_root, {}, "iot", "", "Intelligence")
            output = stdout.getvalue()

        self.assertIn("Intel Capture Format", output)
        self.assertIn("[SERVICE]", output)
        self.assertIn("[ENDPOINT]", output)
        self.assertIn("[LEAD]", output)
        self.assertIn("[FINDING]", output)
        self.assertIn("a port, an endpoint, a target property, a lead, or other security-relevant", output)
        self.assertIn("The framework captures markers automatically into the intel record.", output)
        self.assertIn("If valuable intel does not fit one", output)
        self.assertIn("you may create a concise uppercase marker [CATEGORY].", output)
        self.assertIn("markers accumulate automatically", output)
        self.assertNotIn("Format reference: layer2-templates/reference/evidence/intel-schema.md", output)
        self.assertNotIn("write to INTEL.md directly", output)
        self.assertNotIn("markers accumulate in INTEL.md automatically", output)
        self.assertIn("If an observation is both useful intel and a reportable security issue, emit both the intel marker and the FINDING marker.", output)
        self.assertIn("Do not re-emit SERVICE markers during web or app-layer analysis unless the service fact itself changed.", output)
        self.assertIn("When saving a response body to an artifact file, do not append shell status text such as ; echo \"EXIT:$?\" into the same redirected artifact.", output)
        self.assertIn("## Existing Artifacts", output)
        self.assertIn("## Questions for You", output)
        self.assertIn("## CRITICAL: Human-in-the-Loop Requirement", output)
        self.assertIn("WARNING: You MUST stop and wait for human approval before EVERY action.", output)
        self.assertIn("Step 1: Describe what you WANT to do (do not do it yet)", output)
        self.assertIn("Step 4: Only execute AFTER user explicitly approves", output)
        self.assertIn("## Targets (From Layer 3)", output)
        self.assertNotIn("## Targets (Layer 3: SCOPE.md)", output)
        self.assertNotIn("Operator-facing output contract:", output)
        self.assertNotIn("First response after scope intake:", output)
        self.assertNotIn("Subsequent turns:", output)
        self.assertNotIn("Preferred operator loop example:", output)
        self.assertIn("Do not mention internal document names, file paths, markdown filenames, or repository structure in operator-facing chat output.", output)
        self.assertIn("Selectable options must be plain action labels only.", output)
        self.assertIn("Do not use first-person phrasing in options such as \"I'll\", \"I will\", or parenthetical planning text.", output)
        self.assertIn("After the initial scope-validation turn, do not restate unchanged target, authorization, interface, scope, hotspot, or other engagement-context facts in later replies.", output)
        self.assertIn("On later turns, summarize only what changed, what was learned, or why the next step is being proposed.", output)
        self.assertIn("Do not repeat \"Scope confirmed\" or re-issue the scope summary after the initial scope-validation turn unless the scope actually changed.", output)

    def test_fallback_handoff_explains_anonymized_scope_values_are_intentional(self) -> None:
        module = _load_module("agentic_handler_v15_compare_anon_scope", "body/layer1/scripts/agentic-handler.py")
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
                        "**Version:** Unknown",
                        "",
                        "### Targets",
                        "",
                        "- IP is pinwheel",
                        "",
                        "---",
                    ]
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                module._generate_layer_aware_handoff(body_root, {}, "iot", "", "Phase 1")
            output = stdout.getvalue()

        self.assertIn("Governed files may contain anonymized values.", output)
        self.assertIn("Do not treat anonymized nouns in SCOPE.md as placeholders, dummy data, or bad scope.", output)
        self.assertIn("Do not ask for the real value solely because a governed file contains anonymized nouns.", output)
        self.assertIn("An anonymized IP/hostname placeholder is a valid scope entry during initial scope review.", output)
        self.assertIn("Do not ask for the real IP/hostname during the initial scope-validation turn.", output)
        self.assertIn("If a later approved network action needs a concrete address, ask then.", output)
        self.assertIn("Anonymized values are stable within a single engagement.", output)
        self.assertIn("If one value is anonymized as one noun, that noun refers to the same underlying value throughout the engagement.", output)
        self.assertIn("Different anonymized nouns refer to different underlying values.", output)
        self.assertIn("Do not describe anonymized values as hostname aliases, unresolved names, placeholders that need fixing, or non-routable addresses during initial scope review.", output)
        self.assertIn("Do not ask the operator to provide the actual IP, hostname, CIDR, or subnet during the initial scope-validation turn merely because the governed scope uses anonymized values.", output)

    def test_frontier_scope_adds_mask_note_only_for_frontier_scope(self) -> None:
        module = _load_module("agentic_handler_frontier_scope_note", "body/layer1/scripts/agentic-handler.py")
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
            approvals_dir = body_root / ".bra" / "approvals"
            approvals_dir.mkdir(parents=True)

            frontier_stdout = io.StringIO()
            (approvals_dir / "FRONTIER-SCOPE").touch()
            with contextlib.redirect_stdout(frontier_stdout):
                module._generate_layer_aware_handoff(body_root, {}, "iot", "", "Phase 1")
            frontier_output = frontier_stdout.getvalue()

            (approvals_dir / "FRONTIER-SCOPE").unlink()
            dumb_stdout = io.StringIO()
            with contextlib.redirect_stdout(dumb_stdout):
                module._generate_layer_aware_handoff(body_root, {}, "iot", "", "Phase 1")
            dumb_output = dumb_stdout.getvalue()

        self.assertIn("Note any values I should apply a privacy mask to.", frontier_output)
        self.assertNotIn("Note any values I should apply a privacy mask to.", dumb_output)
