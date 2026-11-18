from __future__ import annotations

import contextlib
import importlib.util
import io
import os
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


class ShellParityRegressionBatch3Tests(unittest.TestCase):
    def test_lock_restores_failure_and_display_messages(self) -> None:
        module = _load_module("lock_regression", "body/layer1/lib/lock.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            lock_dir = body_root / ".bra" / "locks"
            lock_dir.mkdir(parents=True)
            lock_file = lock_dir / "demo.lock"
            lock_file.write_text(f"{os.getpid()}\nScript: other\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                ok = module.acquire_lock("demo", body_root=body_root)
                module.list_locks(body_root)
                module.force_release_lock("demo", body_root)

            output = stdout.getvalue()
            self.assertFalse(ok)
            self.assertIn("Cannot acquire lock: demo", output)
            self.assertIn("Lock held by:", output)
            self.assertIn("Current locks:", output)
            self.assertIn("Force releasing lock: demo", output)

    def test_offensive_check_keeps_list_header_and_numbering(self) -> None:
        module = _load_module("offensive_check_regression", "body/layer1/lib/offensive_check.py")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            patterns = module.list_offensive_patterns()
        self.assertIsInstance(patterns, list)
        output = stdout.getvalue()
        self.assertIn("Offensive Activity Patterns:", output)
        self.assertIn("============================", output)
        self.assertRegex(output, r"(?m)^\s*1\.\s+")

    def test_pipeline_state_restores_workdir_readme_and_scope_target_extraction(self) -> None:
        module = _load_module("pipeline_state_regression", "body/layer1/lib/pipeline_state.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            (body_root / "layer3-engagement").mkdir(parents=True)
            (body_root / "layer3-engagement" / "SCOPE.md").write_text(
                "# Scope\n\n## Target\nExample Camera 3000\n",
                encoding="utf-8",
            )

            work_dir = module.init_phase_work_dir("INTEL", body_root)
            readme = (work_dir / "README.md").read_text(encoding="utf-8")
            self.assertIn("## Contents", readme)
            self.assertIn("## Notes", readme)

            session = module.init_session(body_root).read_text(encoding="utf-8")
            self.assertIn("# Session Log", session)
            self.assertIn("## Session Timeline", session)
            self.assertIn("> **Target:** Example Camera 3000", session)

    def test_target_type_detector_keeps_display_and_remediation(self) -> None:
        module = _load_module("target_type_regression", "body/layer1/lib/target_type_detector.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            (body_root / "layer2-templates" / "methodologies").mkdir(parents=True)
            (body_root / "layer2-templates" / "methodologies" / "android-mobile-security.md").write_text(
                "## Phase 1: Recon\n",
                encoding="utf-8",
            )

            meth_stdout = io.StringIO()
            with contextlib.redirect_stdout(meth_stdout):
                module.list_methodologies(body_root)
            meth_output = meth_stdout.getvalue()
            self.assertIn("Available Methodologies", meth_output)
            self.assertIn("Set target type in SCOPE.md: 'Target Type: <type>'", meth_output)

            target_types = module.list_target_types()
            self.assertIn("1. android      - Android mobile apps (APK/AAB)", target_types)

            missing_scope_stdout = io.StringIO()
            with contextlib.redirect_stdout(missing_scope_stdout):
                with self.assertRaises(FileNotFoundError):
                    module.require_methodology(body_root)
            self.assertIn("No target type detected in scope.", missing_scope_stdout.getvalue())
            self.assertIn("Target Type: android", missing_scope_stdout.getvalue())

    def test_tool_resolver_keeps_display_functions(self) -> None:
        module = _load_module("tool_resolver_regression", "body/layer1/lib/tool_resolver.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            (body_root / "layer2-templates").mkdir(parents=True)
            (body_root / "layer2-templates" / "toolset.md").write_text(
                "### Recon\n\n| Tool | Purpose | Notes |\n|------|---------|-------|\n| `nmap` | Port scan | ACTIVE-TESTING-APPROVAL |\n",
                encoding="utf-8",
            )
            methodology = body_root / "methodology.md"
            methodology.write_text("```bash\nnmap -Pn example.com\n```", encoding="utf-8")

            resolve_stdout = io.StringIO()
            with contextlib.redirect_stdout(resolve_stdout):
                module.resolve_tools_for_methodology(methodology, body_root=body_root)
            self.assertIn("## Tool Resolution", resolve_stdout.getvalue())

            install_stdout = io.StringIO()
            with contextlib.redirect_stdout(install_stdout):
                module.show_install_suggestions(methodology)
            self.assertTrue(
                "Missing Tools - Install Suggestions:" in install_stdout.getvalue()
                or "All methodology tools available!" in install_stdout.getvalue()
            )

            status_text = module.show_tool_status(methodology, body_root=body_root)
            self.assertIn("Tool Availability", status_text)

    def test_tool_resolver_ignores_ports_headings_and_diagram_junk(self) -> None:
        module = _load_module("tool_resolver_filter_regression", "body/layer1/lib/tool_resolver.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            methodology = Path(tmpdir) / "methodology.md"
            methodology.write_text(
                "\n".join(
                    [
                        "## Phase",
                        "",
                        "```bash",
                        "adb shell pm list packages",
                        "apktool d app.apk",
                        "```",
                        "",
                        "## Tools Reference",
                        "",
                        "| Category | Tools |",
                        "|----------|-------|",
                        "| Scanning | nmap, masscan, httpx |",
                        "| BLE | gatttool, bleah |",
                        "",
                        "## Port Map",
                        "",
                        "| Port | Protocol | Service |",
                        "|------|----------|---------|",
                        "| 80/443 | HTTP/S | Admin web interface |",
                        "| 1883/8883 | MQTT | Message queue |",
                        "",
                        "```",
                        "[Mobile App] → [Cloud API] → [Device Tunnel]",
                        "     ↓              ↓             ↓",
                        "[Auth: OAuth]  [Auth: Token]  [Auth: ???]",
                        "```",
                    ]
                ),
                encoding="utf-8",
            )

            tools = module.extract_methodology_tools(methodology)

        self.assertIn("adb", tools)
        self.assertIn("apktool", tools)
        self.assertIn("nmap", tools)
        self.assertIn("masscan", tools)
        self.assertIn("httpx", tools)
        self.assertIn("gatttool", tools)
        self.assertIn("bleah", tools)
        self.assertNotIn("80/443", tools)
        self.assertNotIn("1883/8883", tools)
        self.assertNotIn("Scanning", tools)
        self.assertNotIn("BLE", tools)
        self.assertNotIn("[Mobile", tools)
        self.assertNotIn("[Auth:", tools)
        self.assertNotIn("↓", tools)

    def test_approval_gate_keeps_help_and_summary_messages(self) -> None:
        module = _load_module("approval_gate_regression", "body/layer1/scripts/approval-gate.py")
        help_stdout = io.StringIO()
        with contextlib.redirect_stdout(help_stdout):
            module.show_help()
        help_output = help_stdout.getvalue()
        self.assertIn("EXIT CODES:", help_output)
        self.assertIn("EXAMPLES:", help_output)

        with tempfile.TemporaryDirectory() as tmpdir:
            pitches_dir = Path(tmpdir) / "layer3-engagement" / "pitches"
            pitches_dir.mkdir(parents=True)
            module.PITCHES_DIR = pitches_dir
            list_stdout = io.StringIO()
            with contextlib.redirect_stdout(list_stdout):
                rc = module.list_pitches()
            self.assertEqual(rc, 2)
            self.assertIn("No pitches found", list_stdout.getvalue())

            check_stdout = io.StringIO()
            with contextlib.redirect_stdout(check_stdout):
                rc = module.check_specific_pitch("missing-pitch")
            self.assertEqual(rc, 1)
            self.assertIn("Pitch not found", check_stdout.getvalue())

    def test_audit_keeps_help_headers_and_unicode_quick_markers(self) -> None:
        module = _load_module("audit_regression", "body/layer1/scripts/audit.py")
        help_result = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(help_result):
                module._parse_args(["--help"])
        help_output = help_result.getvalue()
        self.assertIn("DESCRIPTION:", help_output)
        self.assertIn("AUDIT CHECKS:", help_output)
        self.assertIn("OUTPUT:", help_output)
        self.assertIn("EXAMPLES:", help_output)

        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            (body_root / ".bra" / "artifacts").mkdir(parents=True)
            (body_root / ".bra" / "artifacts" / ".intel_complete").write_text("", encoding="utf-8")
            quick_stdout = io.StringIO()
            with contextlib.redirect_stdout(quick_stdout):
                rc = module._audit_quick(body_root)
            self.assertEqual(rc, 0)
            self.assertIn("✓I", quick_stdout.getvalue())
            self.assertIn("○S", quick_stdout.getvalue())

            args = module._parse_args(["-p", "intel"])
            self.assertEqual(args.phase, "INTEL")
            self.assertEqual(module._select_checks(args), ["artifacts"])

            (body_root / "CLAUDE.md").write_text(
                "# Test\n\n## Kill Switch\n```\nSTOP\n```\n",
                encoding="utf-8",
            )
            governance = module._audit_governance(body_root)
            self.assertTrue(
                any(
                    result.name == "Kill Switch"
                    and result.status == "PASS"
                    and "documented but not active" in result.message
                    for result in governance
                )
            )

            original_root = module._body_root
            try:
                module._body_root = lambda: body_root
                json_stdout = io.StringIO()
                with contextlib.redirect_stdout(json_stdout):
                    rc = module.main(["--json", "--phase", "intel"])
            finally:
                module._body_root = original_root
            self.assertEqual(rc, 1)
            self.assertIn('"exit_code": 1', json_stdout.getvalue())
            self.assertIn('"pipeline"', json_stdout.getvalue())
            self.assertIn('"log_file"', json_stdout.getvalue())

    def test_backup_keeps_help_banners_and_human_sizes(self) -> None:
        module = _load_module("backup_regression", "body/layer1/scripts/backup.py")
        help_result = io.StringIO()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(help_result):
                module._parse_args(["--help"])
        help_output = help_result.getvalue()
        self.assertIn("BACKUP TARGETS:", help_output)
        self.assertIn("ROTATION:", help_output)
        self.assertIn("EXAMPLES:", help_output)

        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            (body_root / ".bra").mkdir(parents=True)
            (body_root / "layer3-engagement" / "NOTES").mkdir(parents=True)
            (body_root / "layer3-engagement" / "OVERRIDES.md").write_text("override\n", encoding="utf-8")
            backups_dir = body_root / "BACKUPS"
            backups_dir.mkdir()

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = module._create_backup(body_root, backups_dir, name="test_backup", dry_run=False)
            self.assertEqual(rc, 0)
            output = stdout.getvalue()
            self.assertIn("BACKUP COMPLETE", output)
            self.assertRegex(output, r"Size:\s+.+(?:bytes|KiB|MiB|GiB)")

            parsed = module._parse_args(["-l"])
            self.assertTrue(parsed.list)
            parsed = module._parse_args(["-v", "BACKUPS/test_backup"])
            self.assertEqual(parsed.verify, "BACKUPS/test_backup")
            parsed = module._parse_args(["-r", "BACKUPS/test_backup"])
            self.assertEqual(parsed.restore, "BACKUPS/test_backup")

            missing_manifest = backups_dir / "missing_manifest"
            missing_manifest.mkdir()
            self.assertEqual(module._verify_backup(backups_dir, "BACKUPS/missing_manifest"), 1)

            backup_dir = backups_dir / "restore_case"
            (backup_dir / ".bra").mkdir(parents=True)
            (backup_dir / "layer3-engagement" / "NOTES").mkdir(parents=True)
            (backup_dir / ".bra" / "restored.txt").write_text("new\n", encoding="utf-8")
            (backup_dir / "layer3-engagement" / "NOTES" / "note.md").write_text("note\n", encoding="utf-8")
            (backup_dir / "layer3-engagement" / "OVERRIDES.md").write_text("override\n", encoding="utf-8")
            module._write_manifest(backup_dir, body_root)

            stale_file = body_root / ".bra" / "stale.txt"
            stale_file.write_text("stale\n", encoding="utf-8")
            rc = module._restore_backup(body_root, backups_dir, "BACKUPS/restore_case", dry_run=False)
            self.assertEqual(rc, 0)
            self.assertFalse(stale_file.exists())


if __name__ == "__main__":
    unittest.main()
