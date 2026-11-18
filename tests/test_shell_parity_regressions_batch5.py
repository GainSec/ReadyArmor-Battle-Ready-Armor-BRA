from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
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


class _TtyInput(io.StringIO):
    def isatty(self) -> bool:
        return True


class ShellParityRegressionBatch5Tests(unittest.TestCase):
    def test_agentic_handler_phase_context_path_is_not_printed_twice(self) -> None:
        module = _load_module("agentic_handler_phase_context_regression_batch5", "body/layer1/scripts/agentic-handler.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            context_file = body_root / ".bra" / "phase_context.md"
            methodology_file = body_root / "layer2-templates" / "methodologies" / "iot-embedded-security.md"
            methodology_file.parent.mkdir(parents=True, exist_ok=True)
            methodology_file.write_text("# Methodology\n", encoding="utf-8")

            def _emit_once(_phase: str, _methodology: str, _root: Path) -> Path:
                context_file.parent.mkdir(parents=True, exist_ok=True)
                context_file.write_text("# Phase Execution Context\n", encoding="utf-8")
                print(f"Phase context written to: {context_file}")
                return context_file

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                module._generate_phase_context(
                    body_root,
                    {"phase_invoker": types.SimpleNamespace(output_phase_context=_emit_once)},
                    "iot",
                    str(methodology_file),
                    "APK-First Analysis",
                )

            output = stdout.getvalue()
            self.assertEqual(output.count("Phase context written to:"), 1)

    def test_metadata_keeps_shell_frame_defaults(self) -> None:
        module = _load_module("metadata_regression_batch5", "body/layer1/lib/banner/metadata.py")
        metadata = module.load_metadata()
        self.assertEqual(metadata.frame_delay, 0.05)
        self.assertGreater(metadata.frame_count, 0)

    def test_handoff_summarize_artifacts_limits_to_txt_md_xml(self) -> None:
        module = _load_module("handoff_regression_batch5", "body/layer1/lib/handoff.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            artifacts = body_root / ".bra" / "artifacts" / "intel"
            artifacts.mkdir(parents=True)
            (artifacts / "keep.md").write_text("Interesting line\n", encoding="utf-8")
            (artifacts / "skip.json").write_text('{"a":1}\n', encoding="utf-8")
            (artifacts / "skip.log").write_text("log\n", encoding="utf-8")
            lines = module.summarize_artifacts("intel", body_root=body_root)
            text = "\n".join(lines)
            self.assertIn("keep.md", text)
            self.assertNotIn("skip.json", text)
            self.assertNotIn("skip.log", text)
            self.assertIn("Total: 1 files", text)

    def test_handoff_prompt_uses_current_targets_section_and_restores_v15_loop_contract(self) -> None:
        module = _load_module("handoff_prompt_regression_batch5", "body/layer1/lib/handoff.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            scope_file = body_root / "layer3-engagement" / "SCOPE.md"
            approvals_dir = body_root / ".bra" / "approvals"
            scope_file.parent.mkdir(parents=True)
            approvals_dir.mkdir(parents=True)
            (approvals_dir / "ACTIVE-TESTING-APPROVAL").touch()
            scope_file.write_text(
                "\n".join(
                    [
                        "# Engagement Scope",
                        "",
                        "## Target Definition",
                        "",
                        "**Name:** Android Auto Dongle",
                        "**Target Type:** iot",
                        "**Methodology:** iot-embedded-security",
                        "**Version:** Unknown",
                        "",
                        "### Targets",
                        "",
                        "- 192.168.18.9",
                        "- USB device access",
                        "",
                        "---",
                        "",
                        "## Active Testing",
                        "",
                        "ACTIVE-TESTING-APPROVAL: YES",
                    ]
                ),
                encoding="utf-8",
            )

            prompt = module.generate_handoff_prompt("Intelligence", "", body_root=body_root)

            self.assertIn("192.168.18.9", prompt)
            self.assertNotIn("No targets defined", prompt)
            self.assertIn("## Existing Artifacts", prompt)
            self.assertIn("## Questions for You", prompt)
            self.assertIn("## CRITICAL: Human-in-the-Loop Requirement", prompt)
            self.assertIn("## Targets (From Layer 3)", prompt)
            self.assertIn("What would you like to do?", prompt)
            self.assertIn("1. Confirm scope and proceed", prompt)
            self.assertIn("4. Cancel engagement", prompt)
            self.assertIn("Intel Capture Format", prompt)
            self.assertIn("[SERVICE]", prompt)
            self.assertIn("[ENDPOINT]", prompt)
            self.assertIn("[LEAD]", prompt)
            self.assertIn("Emit them inline, as they happen, on their own line.", prompt)
            self.assertIn("Step 1: Describe what you WANT to do (do not do it yet)", prompt)
            self.assertIn("Step 2: Present options including the proposed action", prompt)
            self.assertIn("Step 3: STOP and WAIT for user to select", prompt)
            self.assertIn("Step 4: Only execute AFTER user explicitly approves", prompt)
            self.assertIn("Do not mention internal document names, file paths, markdown filenames, or repository structure in operator-facing chat output.", prompt)
            self.assertIn("Selectable options must be plain action labels only.", prompt)
            self.assertIn("Do not use first-person phrasing in options such as \"I'll\", \"I will\", or parenthetical planning text.", prompt)
            self.assertIn("After the initial scope-validation turn, do not restate unchanged target, authorization, interface, scope, hotspot, or other engagement-context facts in later replies.", prompt)
            self.assertIn("On later turns, summarize only what changed, what was learned, or why the next step is being proposed.", prompt)
            self.assertIn("Do not repeat \"Scope confirmed\" or re-issue the scope summary after the initial scope-validation turn unless the scope actually changed.", prompt)
            self.assertNotIn("Operator-facing output contract:", prompt)
            self.assertNotIn("First response after scope intake:", prompt)
            self.assertNotIn("Subsequent turns:", prompt)
            self.assertNotIn("Preferred operator loop example:", prompt)

    def test_handoff_brief_handoff_keeps_shell_header_shape_when_action_missing(self) -> None:
        module = _load_module("handoff_brief_regression_batch5", "body/layer1/lib/handoff.py")
        text = module.generate_brief_handoff("", "ok")
        self.assertIn("  Action Complete: ", text)
        self.assertNotIn("  Action Complete\n", text)

    def test_overrides_has_override_is_case_sensitive(self) -> None:
        module = _load_module("overrides_regression_batch5", "body/layer1/lib/overrides.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            path = body_root / ".bra" / "overrides.json"
            path.parent.mkdir(parents=True)
            path.write_text('{"rules": [{"id": "Case-Sensitive"}]}\n', encoding="utf-8")
            self.assertTrue(module.has_override("Case-Sensitive", body_root))
            self.assertFalse(module.has_override("case-sensitive", body_root))

    def test_approve_target_killswitch_applies_to_list_and_check_uses_cidr_scope(self) -> None:
        module = _load_module("approve_target_regression_batch5", "body/layer1/scripts/approve-target.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            module.PROJECT_ROOT = body_root
            module.APPROVED_TARGETS_PATH = body_root / ".bra" / "approved_targets.json"
            module.APPROVAL_TOKEN_DIR = body_root / ".bra" / "one-time-approvals"
            module.SCOPE_MD_PATH = body_root / "layer3-engagement" / "SCOPE.md"
            module.TARGET_SCOPE_LOG_PATH = body_root / ".bra" / "logs" / "target-scope.log"

            stderr = io.StringIO()
            with mock.patch.object(module, "_check_killswitch", return_value=True), contextlib.redirect_stderr(stderr):
                rc = module.main(["--list"])
            self.assertEqual(rc, 99)
            self.assertIn("Kill switch", stderr.getvalue())

            module.APPROVED_TARGETS_PATH.parent.mkdir(parents=True)
            module.APPROVED_TARGETS_PATH.write_text(
                json.dumps({
                    "original": [],
                    "discovered": [{"target": "192.168.1.0/24", "level": "LIMITED", "source": "runtime"}],
                }),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = module.cmd_check("192.168.1.42")
            self.assertEqual(rc, 0)
            self.assertIn("STATUS: Approved", stdout.getvalue())
            self.assertIn("LEVEL:  LIMITED", stdout.getvalue())

    def test_agentic_handler_help_and_killswitch_exit_match_shell(self) -> None:
        module = _load_module("agentic_handler_regression_batch5", "body/layer1/scripts/agentic-handler.py")
        help_stdout = io.StringIO()
        with contextlib.redirect_stdout(help_stdout):
            rc = module.main(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("Three-Layer Architecture", help_stdout.getvalue())

        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            with mock.patch.object(module, "_detect_body_root", return_value=body_root), mock.patch.object(
                module, "_import_libs", return_value={"killswitch": types.SimpleNamespace(is_killswitch_active=lambda *_: True)}
            ), contextlib.redirect_stdout(io.StringIO()):
                rc = module.main([])
        self.assertEqual(rc, 99)

    def test_agentic_handler_fallback_parses_current_targets_and_restores_v15_loop_contract(self) -> None:
        module = _load_module("agentic_handler_fallback_regression_batch5", "body/layer1/scripts/agentic-handler.py")
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

            self.assertIn("192.168.18.9", output)
            self.assertNotIn("No targets defined", output)
            self.assertNotIn("Suggest something else", output)
            self.assertIn("1. Confirm scope and proceed", output)
            self.assertIn("4. Cancel engagement", output)
            self.assertIn("Intel Capture Format", output)
            self.assertIn("[SERVICE]", output)
            self.assertIn("[ENDPOINT]", output)
            self.assertIn("[LEAD]", output)
            self.assertIn("Emit them inline, as they happen, on their own line.", output)
            self.assertIn("a port, an endpoint, a target property, a lead, or other security-relevant", output)
            self.assertIn("The framework captures markers automatically into the intel record.", output)
            self.assertIn("If valuable intel does not fit one", output)
            self.assertIn("you may create a concise uppercase marker [CATEGORY].", output)
            self.assertIn("markers accumulate automatically", output)
            self.assertNotIn("Format reference: layer2-templates/reference/evidence/intel-schema.md", output)
            self.assertNotIn("write to INTEL.md directly", output)
            self.assertNotIn("markers accumulate in INTEL.md automatically", output)
            self.assertIn("## Existing Artifacts", output)
            self.assertIn("## Questions for You", output)
            self.assertIn("## CRITICAL: Human-in-the-Loop Requirement", output)
            self.assertIn("Step 1: Describe what you WANT to do (do not do it yet)", output)
            self.assertIn("Step 4: Only execute AFTER user explicitly approves", output)
            self.assertIn("## Targets (From Layer 3)", output)
            self.assertIn("Do not mention internal document names, file paths, markdown filenames, or repository structure in operator-facing chat output.", output)
            self.assertIn("Selectable options must be plain action labels only.", output)
            self.assertIn("Do not use first-person phrasing in options such as \"I'll\", \"I will\", or parenthetical planning text.", output)
            self.assertIn("After the initial scope-validation turn, do not restate unchanged target, authorization, interface, scope, hotspot, or other engagement-context facts in later replies.", output)
            self.assertIn("On later turns, summarize only what changed, what was learned, or why the next step is being proposed.", output)
            self.assertIn("Do not repeat \"Scope confirmed\" or re-issue the scope summary after the initial scope-validation turn unless the scope actually changed.", output)
            self.assertNotIn("Operator-facing output contract:", output)
            self.assertNotIn("First response after scope intake:", output)
            self.assertNotIn("Subsequent turns:", output)
            self.assertNotIn("Preferred operator loop example:", output)

    def test_battlestations_unknown_args_fall_through_and_scope_intake_always_runs(self) -> None:
        module = _load_module("battlestations_regression_batch5", "body/layer1/scripts/battlestations.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            with mock.patch.object(module, "_body_root", return_value=body_root), mock.patch.object(
                module, "_run_setup", return_value=7
            ) as run_setup:
                rc = module.main(["--unexpected"])
            self.assertEqual(rc, 7)
            run_setup.assert_called_once_with(body_root)

            with mock.patch.object(module, "_print_banner"), mock.patch.object(module, "_run_precheck", return_value=0), \
                 mock.patch.object(module, "_preflight_check", return_value=True), mock.patch.object(module, "_ensure_structure"), \
                 mock.patch.object(module, "_reset_overrides"), mock.patch.object(module, "_run_dry_run", return_value=0), \
                 mock.patch.object(module, "_scope_configured", return_value=True), mock.patch.object(
                     module, "_run_scope_intake", return_value=0
                 ) as intake, mock.patch.object(module, "_show_launch_instructions"):
                rc = module._run_setup(body_root)
            self.assertEqual(rc, 0)
            intake.assert_called_once_with(body_root)

    def test_danger_check_checks_killswitch_before_help_and_emits_watch_track_events(self) -> None:
        module = _load_module("danger_check_regression_batch5", "body/layer1/scripts/danger_check.py")
        stderr = io.StringIO()
        with mock.patch.object(module, "_check_killswitch", return_value=True), contextlib.redirect_stderr(stderr):
            rc = module.main(["--help"])
        self.assertEqual(rc, 99)
        self.assertIn("Kill switch is ACTIVE", stderr.getvalue())

        with mock.patch.object(module, "_validate_caller", return_value=True), mock.patch.object(
            module, "_check_killswitch", return_value=False
        ), mock.patch.object(module, "watch_cmd", create=True) as watch_cmd, mock.patch.object(
            module, "track_cmd", create=True
        ) as track_cmd:
            rc = module.main(["echo", "safe"])
        self.assertEqual(rc, 0)
        watch_cmd.assert_called_once()
        track_cmd.assert_called_once()

    def test_disclose_last_mode_flag_wins(self) -> None:
        module = _load_module("disclose_regression_batch5", "body/layer1/scripts/disclose.py")
        args = module._parse_args(["--package", "--vendor"])
        self.assertEqual(module._selected_types(args), ("vendor",))

    def test_generate_docs_unknown_option_is_exit_one_and_output_matches_shell_shape(self) -> None:
        module = _load_module("generate_docs_regression_batch5", "body/layer1/scripts/generate-docs.py")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = module.main(["--bogus"])
        self.assertEqual(rc, 1)
        self.assertIn("Usage:", stdout.getvalue() + stderr.getvalue())

        content = module._markdown(
            [{
                "name": "demo",
                "category": "lib",
                "purpose": "Demo purpose",
                "args": "None",
                "exit": "0",
                "depends": "None",
                "live-test": "python3 demo.py",
                "file": str(REPO_ROOT / "tests" / "demo.bats"),
            }],
            REPO_ROOT,
        )
        self.assertIn("This reference documents all components tested in the BattleReadyDev framework.", content)
        self.assertIn("**Test File:** [`tests/demo.bats`](tests/demo.bats)", content)

    def test_scope_intake_default_selection_maps_to_pending_intel(self) -> None:
        module = _load_module("scope_intake_regression_batch5", "body/layer1/scripts/scope-intake.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            (body_root / ".bra").mkdir(parents=True)
            (body_root / "layer3-engagement").mkdir(parents=True)
            stdin = _TtyInput("\n" * 20)
            with mock.patch.object(module, "_find_body_root", return_value=body_root), mock.patch.object(sys, "stdin", stdin):
                rc = module.main([])
            self.assertEqual(rc, 0)
            scope_text = (body_root / "layer3-engagement" / "SCOPE.md").read_text(encoding="utf-8")
            self.assertIn("**Target Type:** pending-intel", scope_text)
            self.assertIn("**Methodology:** auto-detect", scope_text)

    def test_status_matches_shell_killswitch_json_shape_and_arg_errors(self) -> None:
        module = _load_module("status_regression_batch5", "body/layer1/scripts/status.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            module.PROJECT_ROOT = body_root
            module.BRA_STATE = body_root / ".bra"
            module.LOG_DIR = module.BRA_STATE / "logs"
            module.ARTIFACTS_DIR = module.BRA_STATE / "artifacts"
            module.NOTES_DIR = body_root / "layer3-engagement" / "NOTES"
            module.STATE_FILE = module.BRA_STATE / "pipeline_state.json"
            module.LOG_DIR.mkdir(parents=True)
            module.ARTIFACTS_DIR.mkdir(parents=True)
            module.NOTES_DIR.mkdir(parents=True)

            with mock.patch.dict(os.environ, {"BRA_STOP": "1"}, clear=False):
                self.assertFalse(module.kill_switch_active())

            (module.BRA_STATE / "STOP").write_text("STOP\n", encoding="utf-8")
            self.assertFalse(module.kill_switch_active())

            (body_root / "CLAUDE.md").write_text("## Kill Switch\nSTOP\n## Next\n", encoding="utf-8")
            self.assertTrue(module.kill_switch_active())
            (body_root / "CLAUDE.md").write_text("## Kill Switch\n```\nSTOP\n```\n## Next\n", encoding="utf-8")
            self.assertFalse(module.kill_switch_active())

            payload = module.build_status_payload()
            self.assertIn("intel", payload["pipeline"])
            self.assertIn("count", payload["findings"])
            self.assertIsInstance(payload["tokens"], str)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = module.main(["--bogus"])
            self.assertEqual(rc, 1)
            self.assertIn("USAGE:", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
