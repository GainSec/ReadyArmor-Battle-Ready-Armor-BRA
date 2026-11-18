from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
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


class _NoTtyStdin(io.StringIO):
    def isatty(self) -> bool:
        return False


class ShellParityRegressionBatch4Tests(unittest.TestCase):
    def test_killswitch_deactivate_noop_is_success(self) -> None:
        module = _load_module("killswitch_regression_batch4", "body/layer1/lib/killswitch.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                ok = module.deactivate_killswitch(body_root)
                rc = module.main(["--deactivate"])
            output = stdout.getvalue()
            self.assertTrue(ok)
            self.assertEqual(rc, 0)
            self.assertIn("No stop file to remove", output)

    def test_ollama_preserves_governance_exit_codes_and_order(self) -> None:
        module = _load_module("ollama_regression_batch4", "body/layer1/lib/ollama.py")
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.dict(os.environ, {"BRA_STOP": "1"}, clear=False):
            body_root = Path(tmpdir)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = module.main(["--generate", "hello"])
            self.assertEqual(rc, 99)
            self.assertIn("Kill switch active", stderr.getvalue())
            with self.assertRaises(module.OllamaGovernanceError):
                module.ollama_generate_with_context("", body_root=body_root)

    def test_phase_invoker_restores_project_root_phase_dir_and_metadata(self) -> None:
        module = _load_module("phase_invoker_regression_batch4", "body/layer1/lib/phase_invoker.py")
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.dict(os.environ, {"PROJECT_ROOT": tmpdir}, clear=False):
            body_root = Path(tmpdir)
            (body_root / ".bra" / "artifacts" / "phase2_work").mkdir(parents=True)
            (body_root / "layer3-engagement" / "pitches").mkdir(parents=True)
            methodology = body_root / "sample-methodology.md"
            methodology.write_text(
                "# Demo\n\n## Phase 2: Static\n\n- Objective\n\n```bash\necho hi\n```\n\nDeliverable\n",
                encoding="utf-8",
            )

            self.assertEqual(module.get_context_file(), (body_root / ".bra" / "phase_context.md").resolve())
            context_path = module.output_phase_context("Phase 2: Static", str(methodology))
            context_text = context_path.read_text(encoding="utf-8")
            self.assertIn("`.bra/artifacts/phase2_work/`", context_text)

            pitch = module.propose_methodology_update("desc", "echo hi", methodology="demo-method")
            self.assertIn("> **Methodology:** demo-method", pitch.read_text(encoding="utf-8"))

            improvements = body_root / ".bra" / "improvements"
            improvements.mkdir(parents=True)
            (improvements / "techniques.log").write_text("2026-01-01 | intel | thing | discovered\n", encoding="utf-8")
            summary_path = module.consolidate_improvements(body_root)
            self.assertIsInstance(summary_path, Path)
            self.assertTrue(summary_path.is_file())

            context_path.touch()
            old_ts = time.time() - 7200
            os.utime(context_path, (old_ts, old_ts))
            self.assertFalse(module.has_valid_context(body_root=body_root))
            os.utime(context_path, None)
            self.assertTrue(module.has_valid_context(body_root=body_root))

    def test_promotion_uses_temporary_layer2_write_token(self) -> None:
        module = _load_module("promotion_regression_batch4", "body/layer1/lib/promotion.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            pitch_dir = body_root / "layer3-engagement" / "pitches"
            pitch_dir.mkdir(parents=True)
            pitch = pitch_dir / "demo.md"
            pitch.write_text(
                "## 1. Skills\n\n- [x] **Demo Skill**: Description\n",
                encoding="utf-8",
            )
            seen: dict[str, bool] = {}

            def fake_add_skill(name: str, desc: str, body_root: Path | None = None) -> int:
                token_file = Path(tmpdir) / ".bra" / "approvals" / "LAYER2-WRITE-APPROVAL"
                seen["during"] = token_file.is_file()
                return 0

            with mock.patch.object(module, "add_skill", side_effect=fake_add_skill):
                result = module.promote_from_pitch(pitch, body_root=body_root)
            token_file = body_root / ".bra" / "approvals" / "LAYER2-WRITE-APPROVAL"
            self.assertEqual(result["promoted"], 1)
            self.assertTrue(seen.get("during"))
            self.assertFalse(token_file.exists())

    def test_scope_validate_restores_minimal_ready_gate_and_target_fallback(self) -> None:
        module = _load_module("scope_validate_regression_batch4", "body/layer1/lib/scope_validate.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            scope_dir = body_root / "layer3-engagement"
            scope_dir.mkdir(parents=True)
            (scope_dir / "SCOPE.md").write_text(
                "# Scope\n\n**Authorization:** Yes\n\n## Target\n- camera.local\n\n## Out-of-Scope\n- none\n\nnotes\nmore\nmore\nmore\nmore\n",
                encoding="utf-8",
            )
            self.assertTrue(module.check_target_defined(body_root))
            self.assertTrue(module.scope_is_ready(body_root))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                ok = module.require_scope(body_root)
            self.assertTrue(ok)

            (scope_dir / "SCOPE.md").write_text("# Scope\n\n_TBD_\n", encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                ok = module.require_scope(body_root)
            self.assertFalse(ok)
            self.assertIn("ERROR: Scope not defined", stdout.getvalue())

    def test_service_state_does_not_use_dns_only_fallback_or_create_file_on_clear(self) -> None:
        module = _load_module("service_state_regression_batch4", "body/layer1/lib/service_state.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            with mock.patch.object(module.request, "urlopen", side_effect=OSError("down")), mock.patch.object(
                module.socket, "gethostbyname", return_value="1.2.3.4"
            ):
                responding, code = module.check_service_responding("example.com")
            self.assertFalse(responding)
            self.assertIsNone(code)
            self.assertTrue(module.clear_service("example.com", body_root=body_root))
            self.assertFalse((body_root / ".bra" / "service_state.json").exists())

    def test_target_scope_restores_level_validation_approved_at_and_custom_allow(self) -> None:
        module = _load_module("target_scope_regression_batch4", "body/layer1/lib/target_scope.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            entry = module.add_approved_target("example.com", level="CUSTOM", source="runtime", allowed=["^echo"], body_root=body_root)
            self.assertEqual(entry["level"], "CUSTOM")
            self.assertIn("approved_at", entry)
            self.assertTrue(module.is_operation_allowed("rm -rf /tmp/demo", "CUSTOM", []))
            with self.assertRaises(ValueError):
                module.add_approved_target("example.org", level="INVALID", body_root=body_root)

    def test_tokens_require_token_exits_like_shell(self) -> None:
        module = _load_module("tokens_regression_batch4", "body/layer1/lib/tokens.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            stdout = io.StringIO()
            with self.assertRaises(SystemExit) as cm:
                with contextlib.redirect_stdout(stdout):
                    module.require_token("PUSH-APPROVAL", body_root=body_root)
            self.assertEqual(cm.exception.code, 1)
            self.assertIn("TOKEN REQUIRED: PUSH-APPROVAL", stdout.getvalue())

    def test_bra_restores_menu_default_and_legacy_flags(self) -> None:
        module = _load_module("bra_regression_batch4", "body/layer1/scripts/bra.py")
        events: list[object] = []
        with mock.patch.object(module, "show_banner", side_effect=lambda: events.append("banner")), mock.patch.object(
            module, "show_main_menu", side_effect=lambda state: events.append(("menu", state)) or 0
        ), mock.patch.object(module, "_session_state", return_value="READY"), mock.patch.object(
            sys, "stdin", _NoTtyStdin()
        ):
            rc = module.main([])
        self.assertEqual(rc, 0)
        self.assertEqual(events, ["banner", ("menu", "READY")])

        events = []
        with mock.patch.object(module, "show_banner", side_effect=lambda: events.append("banner")), mock.patch.object(
            module, "cmd_phase", side_effect=lambda args: events.append(("phase", args.name)) or 7
        ):
            rc = module.main(["--phase", "static"])
        self.assertEqual(rc, 7)
        self.assertEqual(events, ["banner", ("phase", "static")])

    def test_dedupe_integrated_noop_returns_success(self) -> None:
        module = _load_module("dedupe_regression_batch4", "body/layer1/scripts/dedupe-integrated.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            integrated = body_root / "layer2-templates" / "reference" / "integrated"
            integrated.mkdir(parents=True)
            for name in (
                "tools-integrated.md",
                "skills-integrated.md",
                "methodologies-integrated.md",
                "workflows-integrated.md",
            ):
                (integrated / name).write_text("# Empty\n", encoding="utf-8")
            (body_root / "layer2-templates").mkdir(exist_ok=True)
            with mock.patch.object(module, "_body_root", return_value=body_root):
                rc = module.main([])
            self.assertEqual(rc, 0)

    def test_growth_keeps_help_and_review_banner(self) -> None:
        module = _load_module("growth_regression_batch4", "body/layer1/scripts/growth.py")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            module._show_help()
        help_output = stdout.getvalue()
        self.assertIn("DATA SOURCES ANALYZED:", help_output)
        self.assertIn("layer3-engagement/REVIEW.md", help_output)

        notify = io.StringIO()
        with contextlib.redirect_stdout(notify):
            module._notify_user(Path("demo.md"))
        self.assertIn("GROWTH PROPOSALS REQUIRE YOUR REVIEW", notify.getvalue())

    def test_hunt_keeps_help_sections_status_alias_and_accept_instructions(self) -> None:
        module = _load_module("hunt_regression_batch4", "body/layer1/scripts/hunt.py")
        args = module._parse_args(["-s"])
        self.assertTrue(args.status)

        help_result = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(help_result):
                module._parse_args(["--help"])
        help_text = help_result.getvalue()
        self.assertIn("LEAD FORMAT:", help_text)
        self.assertIn("EXAMPLES:", help_text)

        with tempfile.TemporaryDirectory() as tmpdir:
            pitch = Path(tmpdir) / "pitch.md"
            module._write_pitch(
                pitch,
                [{
                    "priority": "HIGH",
                    "title": "Demo Lead",
                    "hypothesis": "Something is exposed",
                    "evidence": "Artifact",
                    "effort": "Quick check",
                    "phase": "intel",
                    "next_steps": "Check it",
                }],
            )
            text = pitch.read_text(encoding="utf-8")
            self.assertIn("### To Accept a Lead", text)
            self.assertIn("notes_guard.py append", text)

    def test_leads_restores_interactive_default_and_short_alias(self) -> None:
        module = _load_module("leads_regression_batch4", "body/layer1/scripts/leads.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            notes_dir = body_root / "layer3-engagement" / "NOTES"
            notes_dir.mkdir(parents=True)
            (notes_dir / "LEADS.md").write_text(
                "### [OPEN] Demo Lead\n- **Hypothesis:** Test it\n- **Evidence:** Artifact\n- **Priority:** HIGH\n- **Effort:** Quick check\n- **Next Steps:** Check it\n",
                encoding="utf-8",
            )
            with mock.patch.object(module, "_find_body_root", return_value=body_root), mock.patch.object(sys, "stdin", _NoTtyStdin()):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    rc = module.main([])
                self.assertEqual(rc, 0)
                self.assertIn("Interactive selection requires a TTY", stdout.getvalue())

                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    rc = module.main(["-s"])
                self.assertEqual(rc, 0)
                self.assertIn("Lead Statistics", stdout.getvalue())

    def test_notes_guard_checks_killswitch_before_operations(self) -> None:
        module = _load_module("notes_guard_regression_batch4", "body/layer1/scripts/notes_guard.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            (body_root / ".bra").mkdir(parents=True)
            (body_root / ".bra" / "STOP").write_text("stop\n", encoding="utf-8")
            with mock.patch.object(module, "_detect_body_root", return_value=body_root):
                rc = module.main(["check"])
            self.assertEqual(rc, 99)

    def test_self_improvement_restores_help_aliases_and_dry_run_paths(self) -> None:
        module = _load_module("self_improvement_regression_batch4", "body/layer1/scripts/self-improvement.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            (body_root / "layer3-engagement" / "NOTES").mkdir(parents=True)
            help_stdout = io.StringIO()
            with mock.patch.object(module, "_find_body_root", return_value=body_root):
                with contextlib.redirect_stdout(help_stdout):
                    rc = module.main([])
                self.assertEqual(rc, 0)
            self.assertIn("PROMOTION WORKFLOW", help_stdout.getvalue())
            self.assertIn("AUTO-INVOCATION", help_stdout.getvalue())

            with mock.patch.object(module, "_find_body_root", return_value=body_root):
                status_stdout = io.StringIO()
                with contextlib.redirect_stdout(status_stdout):
                    rc = module.main(["-s"])
                self.assertEqual(rc, 0)
                self.assertIn("Self-Improvement Status", status_stdout.getvalue())

            with mock.patch.object(module, "_find_body_root", return_value=body_root), mock.patch.object(
                module, "_promote", return_value=0
            ) as promote_mock:
                rc = module.main(["--dry-run"])
                self.assertEqual(rc, 0)
                self.assertTrue(promote_mock.called)
                self.assertTrue(promote_mock.call_args.args[-1])

            with mock.patch.object(module, "_find_body_root", return_value=body_root), mock.patch.object(
                module, "_promote_overrides", return_value=0
            ) as promote_overrides_mock:
                rc = module.main(["--ingest-overrides"])
                self.assertEqual(rc, 0)
                self.assertTrue(promote_overrides_mock.called)

            with mock.patch.object(module, "_find_body_root", return_value=body_root), mock.patch.object(
                module, "_promote", return_value=0
            ) as promote_mock:
                rc = module.main(["-p"])
                self.assertEqual(rc, 0)
                self.assertTrue(promote_mock.called)


if __name__ == "__main__":
    unittest.main()
