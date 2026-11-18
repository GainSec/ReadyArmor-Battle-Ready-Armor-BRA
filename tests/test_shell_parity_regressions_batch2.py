from __future__ import annotations

import builtins
import contextlib
import importlib.util
import io
import subprocess
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


def _write_py_stub(path: Path, body: str = "import sys\nraise SystemExit(0)\n") -> None:
    path.write_text(body, encoding="utf-8")


class ShellParityRegressionBatch2Tests(unittest.TestCase):
    def test_deploy_help_and_runtime_banners_match_shell_parity(self) -> None:
        help_result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/scripts/deploy.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("DESCRIPTION:", help_result.stdout)
        self.assertIn("8. Running full precheck", help_result.stdout)
        self.assertIn("NEXT STEPS:", help_result.stdout)

        module = _load_module("deploy_regression", "body/layer1/scripts/deploy.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            (body_root / "layer1/rules").mkdir(parents=True)
            (body_root / "layer2-templates").mkdir(parents=True)
            (body_root / "layer3-engagement").mkdir(parents=True)
            (body_root / "CLAUDE.md").write_text("# Test\n\n## Kill Switch\n\n```\nCLEAR\n```\n", encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = module._run_checks(body_root, fix=False, quick=True)
        self.assertEqual(rc, 1)
        output = stdout.getvalue()
        self.assertIn("B.R.A. DEPLOY", output)
        self.assertIn("━━━ DIRECTORY STRUCTURE ━━━", output)
        self.assertIn("DEPLOYMENT SUMMARY", output)

    def test_dry_run_restores_unicode_markers_and_danger_check(self) -> None:
        help_result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/scripts/dry-run.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("SIMULATED TARGET:", help_result.stdout)
        self.assertIn("PHASES EXERCISED:", help_result.stdout)
        self.assertIn("EXIT CODES:", help_result.stdout)
        self.assertIn("EXAMPLES:", help_result.stdout)
        self.assertIn("INTEL → STATIC → DYNAMIC → REPORT", help_result.stdout)

        module = _load_module("dry_run_regression", "body/layer1/scripts/dry-run.py")
        counts = module.Counts()
        phase_stdout = io.StringIO()
        with contextlib.redirect_stdout(phase_stdout):
            module._phase("Verifying support scripts")
            module._pass("status.py", counts)
            module._skip("notes_guard.py", counts)
        phase_output = phase_stdout.getvalue()
        self.assertIn("▶", phase_output)
        self.assertIn("✓", phase_output)
        self.assertIn("○", phase_output)

        with tempfile.TemporaryDirectory() as tmpdir:
            scripts_dir = Path(tmpdir)
            _write_py_stub(scripts_dir / "status.py")
            _write_py_stub(scripts_dir / "notes_guard.py")
            _write_py_stub(scripts_dir / "danger_check.py")
            counts = module.Counts()
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                module._check_support_scripts(scripts_dir, counts)
        self.assertIn("danger_check.py", stdout.getvalue())

        with tempfile.TemporaryDirectory() as tmpdir:
            scripts_dir = Path(tmpdir)
            _write_py_stub(scripts_dir / "audit.py", "import sys\nraise SystemExit(1)\n")
            counts = module.Counts()
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                module._run_script_check(
                    scripts_dir,
                    "audit.py",
                    [],
                    "audit.py (verification)",
                    counts,
                    accepted_exit_codes={0, 1},
                )
        self.assertIn("✓ audit.py (verification)", stdout.getvalue())

    def test_integrate_ingest_restores_headers_and_summary_detail(self) -> None:
        help_result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/scripts/integrate-ingest.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("Usage: integrate-ingest.py [OPTIONS]", help_result.stdout)

        module = _load_module("integrate_ingest_regression", "body/layer1/scripts/integrate-ingest.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            project = root / "engagement-one"
            project.mkdir()
            (project / "tools.md").write_text("nmap\n", encoding="utf-8")
            output_file = root / "tools-integrated.md"
            module._integrate_file(
                [project],
                ["tools.md"],
                output_file,
                "Integrated Tools Reference",
                ["engagement-one"],
                verbose=False,
                dry_run=False,
            )
            content = output_file.read_text(encoding="utf-8")
            self.assertIn("## Tool Categories", content)

            module._write_summary(root, 1, {"tools-integrated.md": 1}, dry_run=False)
            summary = (root / "INTEGRATION-SUMMARY.md").read_text(encoding="utf-8")
            self.assertIn("| Company names | [TARGET] |", summary)
            self.assertIn("- `tools-integrated.md` - Combined tool references", summary)

    def test_lessons_learned_restores_status_grouping_and_generation_banners(self) -> None:
        help_result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/scripts/lessons-learned.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("OUTPUT DOCUMENT STRUCTURE:", help_result.stdout)
        self.assertIn("POST-LESSONS AUTOMATION:", help_result.stdout)

        module = _load_module("lessons_regression", "body/layer1/scripts/lessons-learned.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            (body_root / "layer1/rules").mkdir(parents=True)
            notes_dir = body_root / "layer3-engagement" / "NOTES"
            notes_dir.mkdir(parents=True)
            (body_root / ".bra" / "artifacts").mkdir(parents=True)
            files = [
                ("scope.md", body_root / "layer1/rules/scope.md"),
                ("roe.md", body_root / "layer1/rules/roe.md"),
                ("tokens.md", body_root / "layer1/rules/tokens.md"),
                ("FINDINGS.md", notes_dir / "FINDINGS.md"),
                ("LEADS.md", notes_dir / "LEADS.md"),
                ("REVIEW.md", body_root / "layer3-engagement/REVIEW.md"),
                ("SESSION.md", notes_dir / "SESSION.md"),
                ("manifest.json", body_root / ".bra/artifacts/manifest.json"),
                ("pipeline_state.json", body_root / ".bra/pipeline_state.json"),
            ]
            (notes_dir / "FINDINGS.md").write_text("## [FINDING-001]\n| **Severity** | HIGH |\n", encoding="utf-8")
            (notes_dir / "SESSION.md").write_text("- session note\n", encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                module._check_data_availability(files)
            status_output = stdout.getvalue()
            self.assertIn("=== Data Availability Check ===", status_output)
            self.assertIn("Core Documents:", status_output)
            self.assertIn("NOTES Directory:", status_output)

            original_find = module._find_body_root
            original_generate = module._generate_document
            original_post = module._run_post_lessons_automation
            try:
                module._find_body_root = lambda _path: body_root
                module._generate_document = lambda **kwargs: None
                module._run_post_lessons_automation = lambda *args, **kwargs: None
                main_stdout = io.StringIO()
                with contextlib.redirect_stdout(main_stdout):
                    rc = module.main([])
            finally:
                module._find_body_root = original_find
                module._generate_document = original_generate
                module._run_post_lessons_automation = original_post
            self.assertEqual(rc, 0)
            self.assertIn("GENERATING LESSONS LEARNED", main_stdout.getvalue())
            self.assertIn("LESSONS LEARNED COMPLETE", main_stdout.getvalue())

    def test_packup_restores_dry_run_box_and_claude_temp_options(self) -> None:
        help_result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/scripts/packup.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("ARCHIVE CONTENTS:", help_result.stdout)

        module = _load_module("packup_regression", "body/layer1/scripts/packup.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir) / "body"
            (body_root / ".bra" / "artifacts").mkdir(parents=True)
            (body_root / "layer3-engagement" / "NOTES").mkdir(parents=True)
            original_detect = module._detect_body_root
            try:
                module._detect_body_root = lambda _path: body_root
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    rc = module.main(["--dry-run"])
            finally:
                module._detect_body_root = original_detect
        self.assertEqual(rc, 0)
        self.assertIn("═══ PACKUP DRY RUN ═══", stdout.getvalue())

        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir) / "body"
            body_root.mkdir(parents=True)
            claude_temp = Path(tmpdir) / "claude-temp"
            claude_temp.mkdir()
            (claude_temp / "task.txt").write_text("secret\n", encoding="utf-8")
            module = _load_module("packup_regression_prompt", "body/layer1/scripts/packup.py")
            original_get = module._get_claude_temp_dir
            original_input = builtins.input
            try:
                module._get_claude_temp_dir = lambda _body_root: claude_temp
                builtins.input = lambda _prompt="": "3"
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    module._check_claude_temp(body_root)
            finally:
                module._get_claude_temp_dir = original_get
                builtins.input = original_input
        self.assertIn("Options:", stdout.getvalue())
        self.assertIn("Include in archive", stdout.getvalue())

    def test_prep_deploy_restores_list_formatting(self) -> None:
        help_result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/scripts/prep-deploy.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("DEPLOYMENT:", help_result.stdout)

        module = _load_module("prep_deploy_regression", "body/layer1/scripts/prep-deploy.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir)
            (body_root / "CLAUDE.md").write_text("# test\n", encoding="utf-8")
            (body_root / "layer1/rules").mkdir(parents=True)
            (body_root / "layer2-templates").mkdir(parents=True)
            (body_root / "scripts").mkdir()
            (body_root / ".claude").mkdir()
            includes = module._iter_includes(body_root)
            files = module._collect_files(body_root, includes)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                module._list_includes(body_root, includes, files)
        output = stdout.getvalue()
        self.assertIn("=== Deployment Package Contents ===", output)
        self.assertIn("Layer 1 (Root Guides):", output)
        self.assertIn("Framework Components:", output)

    def test_ref_harvest_restores_detailed_harvest_and_verify_output(self) -> None:
        help_result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/scripts/ref_harvest.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("MANIFEST FORMAT:", help_result.stdout)

        module = _load_module("ref_harvest_regression", "body/layer1/scripts/ref_harvest.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = root / "evidence.bin"
            source.write_text("abc123\n", encoding="utf-8")
            destination = root / "artifacts"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = module._harvest(source, destination, root / "ref_harvest.log")
            self.assertEqual(rc, 0)
            self.assertIn("Harvesting file:", stdout.getvalue())
            self.assertIn("Collected:", stdout.getvalue())

            manifest = destination / "manifest.json"
            manifest.write_text(
                '{"version":"1.0","artifacts":[{"path":"evidence.bin","sha256":"deadbeef"}]}\n',
                encoding="utf-8",
            )
            verify_stdout = io.StringIO()
            with contextlib.redirect_stdout(verify_stdout):
                rc = module._verify_manifest(manifest, root / "ref_harvest.log")
            self.assertEqual(rc, 2)
            self.assertIn("Expected:", verify_stdout.getvalue())
            self.assertIn("Actual:", verify_stdout.getvalue())

    def test_reset_restores_boxed_dry_run_and_warning_banner(self) -> None:
        help_result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/scripts/reset.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("WHAT GETS RESET:", help_result.stdout)

        module = _load_module("reset_regression", "body/layer1/scripts/reset.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir) / "body"
            body_root.mkdir(parents=True)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = module._dry_run(body_root, [])
            self.assertEqual(rc, 2)
            self.assertIn("═══ RESET DRY RUN ═══", stdout.getvalue())

        with tempfile.TemporaryDirectory() as tmpdir:
            body_root = Path(tmpdir) / "body"
            (body_root / ".bra" / "approvals").mkdir(parents=True)
            (body_root / ".bra" / "approvals" / "DESTRUCTIVE-APPROVAL").write_text("", encoding="utf-8")
            (body_root / "BACKUPS").mkdir()
            fake_archive = body_root / "BACKUPS" / "reset_backup_test.tar.gz"
            fake_archive.write_text("archive\n", encoding="utf-8")
            module = _load_module("reset_regression_warning", "body/layer1/scripts/reset.py")
            original_detect = module._detect_body_root
            original_archive = module._create_archive
            original_reset_bra = module._reset_bra
            original_reset_notes = module._reset_notes
            original_reset_layer3 = module._reset_layer3_engagement
            original_reset_dirs = module._reset_custom_dirs
            original_reset_scripts = module._reset_custom_scripts
            original_reset_temp = module._reset_claude_temp
            original_input = builtins.input
            try:
                module._detect_body_root = lambda _path: body_root
                module._create_archive = lambda _body_root, _items: fake_archive
                module._reset_bra = lambda _body_root: None
                module._reset_notes = lambda _body_root: None
                module._reset_layer3_engagement = lambda _body_root: None
                module._reset_custom_dirs = lambda _body_root: None
                module._reset_custom_scripts = lambda _body_root: None
                module._reset_claude_temp = lambda _body_root: None
                builtins.input = lambda _prompt="": "RESET"
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    rc = module.main([])
            finally:
                module._detect_body_root = original_detect
                module._create_archive = original_archive
                module._reset_bra = original_reset_bra
                module._reset_notes = original_reset_notes
                module._reset_layer3_engagement = original_reset_layer3
                module._reset_custom_dirs = original_reset_dirs
                module._reset_custom_scripts = original_reset_scripts
                module._reset_claude_temp = original_reset_temp
                builtins.input = original_input
            self.assertEqual(rc, 0)
            self.assertIn("╔", stdout.getvalue())
            self.assertIn("WARNING: DESTRUCTIVE ACTION", stdout.getvalue())
            self.assertIn("To restore from backup:", stdout.getvalue())

    def test_restore_and_validate_mappings_already_keep_shell_parity(self) -> None:
        restore_help = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/scripts/restore.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(restore_help.returncode, 0, restore_help.stderr)
        self.assertIn("SUPPORTED ARCHIVES:", restore_help.stdout)
        self.assertIn("RESTORE BEHAVIOR:", restore_help.stdout)

        validate_help = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/scripts/validate-mappings.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(validate_help.returncode, 0, validate_help.stderr)
        self.assertIn("CHECKS PERFORMED:", validate_help.stdout)
        self.assertIn("EXIT CODES:", validate_help.stdout)


if __name__ == "__main__":
    unittest.main()
