from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class BootsPythonLaunchersTests(unittest.TestCase):
    def test_shell_launchers_removed(self) -> None:
        boots_dir = Path(__file__).resolve().parents[1] / "boots"
        self.assertFalse((boots_dir / "gui.sh").exists())
        self.assertFalse((boots_dir / "gui-debug.sh").exists())
        self.assertFalse((boots_dir / "logview.sh").exists())

    def test_python_launchers_exist_and_help(self) -> None:
        root = Path(__file__).resolve().parents[1]
        boots_dir = root / "boots"
        launchers = [
            boots_dir / "gui.py",
            boots_dir / "gui-debug.py",
            boots_dir / "logview-launch.py",
        ]
        for launcher in launchers:
            self.assertTrue(launcher.exists(), f"Missing launcher: {launcher}")
            proc = subprocess.run(
                [sys.executable, str(launcher), "--help"],
                cwd=str(root),
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, f"{launcher} --help failed: {proc.stderr}")

    def test_verbose_module_enables_from_approval_file(self) -> None:
        root = Path(__file__).resolve().parents[1]
        verbose_py = root / "boots" / "verbose.py"
        spec = importlib.util.spec_from_file_location("boots_verbose_test_mod", verbose_py)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)

        with tempfile.TemporaryDirectory() as td:
            project_root = Path(td)
            body_root = project_root / "body"
            (body_root / ".bra" / "approvals").mkdir(parents=True)
            (body_root / ".bra" / "approvals" / "BRA_VERBOSE").write_text("")

            old_bra_dir = os.environ.get("BRA_DIR")
            old_verbose = os.environ.get("BRA_VERBOSE")
            try:
                os.environ.pop("BRA_VERBOSE", None)
                os.environ["BRA_DIR"] = str(project_root)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.assertTrue(module.ENABLED)
            finally:
                if old_bra_dir is None:
                    os.environ.pop("BRA_DIR", None)
                else:
                    os.environ["BRA_DIR"] = old_bra_dir
                if old_verbose is None:
                    os.environ.pop("BRA_VERBOSE", None)
                else:
                    os.environ["BRA_VERBOSE"] = old_verbose


if __name__ == "__main__":
    unittest.main()
