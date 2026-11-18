from __future__ import annotations

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
    spec.loader.exec_module(module)
    return module


class ShellParityRegressionTests(unittest.TestCase):
    def test_active_check_lists_keep_headers_and_numbering(self) -> None:
        module = _load_module("active_check_regression", "body/layer1/lib/active_check.py")

        network_stdout = io.StringIO()
        with contextlib.redirect_stdout(network_stdout):
            network_patterns = module.list_network_patterns()

        static_stdout = io.StringIO()
        with contextlib.redirect_stdout(static_stdout):
            static_patterns = module.list_static_patterns()

        self.assertIsInstance(network_patterns, list)
        self.assertIsInstance(static_patterns, list)
        self.assertIn("Network-Based Activity Patterns (require approval):", network_stdout.getvalue())
        self.assertIn("====================================================", network_stdout.getvalue())
        self.assertRegex(network_stdout.getvalue(), r"(?m)^\s*1\.\s+")
        self.assertIn("Static Analysis Patterns (always allowed):", static_stdout.getvalue())
        self.assertIn("===========================================", static_stdout.getvalue())
        self.assertRegex(static_stdout.getvalue(), r"(?m)^\s*1\.\s+")

    def test_methodology_loader_restores_color_emphasis(self) -> None:
        module = _load_module("methodology_loader_regression", "body/layer1/lib/methodology_loader.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            methodology = Path(tmpdir) / "methodology.md"
            methodology.write_text(
                "# Mobile Assessment\n\n"
                "> **Template Version:** 1.0\n\n"
                "## Phase 1: Recon\n"
                "### Objectives\n"
                "- Enumerate targets\n"
                "### Techniques\n"
                "```bash\n"
                "nmap -Pn example.com\n"
                "```\n"
                "### Deliverables\n"
                "- [ ] Recon notes\n",
                encoding="utf-8",
            )

            summary = module.show_methodology_summary(methodology)
            detail = module.show_phase_detail(methodology, "Phase 1")

        self.assertIn("\033[0;36m", summary)
        self.assertIn("\033[2m", summary)
        self.assertIn("\033[0;36m", detail)
        self.assertIn("\033[0;32m", detail)

    def test_methodology_loader_reports_missing_file(self) -> None:
        missing = REPO_ROOT / "tests" / "does-not-exist-methodology.md"
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/lib/methodology_loader.py"), "--summary", str(missing)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )

        combined = (result.stdout or "") + (result.stderr or "")
        self.assertEqual(result.returncode, 1, combined)
        self.assertIn("Methodology file not found", combined)

    def test_run_tests_help_and_header_match_shell_parity(self) -> None:
        help_result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/scripts/run-tests.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("Examples:", help_result.stdout)
        self.assertIn("Requirements:", help_result.stdout)
        self.assertIn("brew install bats-core", help_result.stdout)

        module = _load_module("run_tests_regression", "body/layer1/scripts/run-tests.py")
        header_stdout = io.StringIO()
        with contextlib.redirect_stdout(header_stdout):
            module._print_header()
        self.assertIn("════════════════════════════════════════════════════════════════", header_stdout.getvalue())

    def test_stats_help_restores_examples_metrics_and_exit_codes(self) -> None:
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "body/layer1/scripts/stats.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("METRICS COLLECTED:", result.stdout)
        self.assertIn("EXIT CODES:", result.stdout)
        self.assertIn("EXAMPLES:", result.stdout)

    def test_gui_help_restores_environment_variables_section(self) -> None:
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "boots/gui.py"), "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Environment variables:", result.stdout)
        self.assertIn("BRA_GUI_PORT", result.stdout)
        self.assertIn("BRA_GUI_HOST", result.stdout)
        self.assertIn("BRA_GUI_DIR", result.stdout)


if __name__ == "__main__":
    unittest.main()
