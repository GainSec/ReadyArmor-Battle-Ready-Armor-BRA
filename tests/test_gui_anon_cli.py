from __future__ import annotations

import importlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


gui = importlib.import_module("boots.gui")


class _Completed:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode


class GuiAnonCliTests(unittest.TestCase):
    def test_parse_args_accepts_ner_flag(self) -> None:
        args = gui._parse_args(["--ner"])

        self.assertTrue(args.ner)

    def test_main_forwards_ner_flag_to_boots_main(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            project_root = Path(td)
            boots_dir = project_root / "boots"
            bra_dir = project_root / "body"
            (bra_dir / ".bra").mkdir(parents=True)

            run_calls: list[list[str]] = []

            def _fake_run(cmd, **kwargs):
                run_calls.append(list(cmd))
                return _Completed(0)

            with (
                patch.object(gui.Path, "resolve", return_value=boots_dir / "gui.py"),
                patch.object(gui, "_ensure_venv", return_value=Path("/tmp/fake-python")),
                patch.object(gui, "_deps_installed", return_value=True),
                patch.object(gui.subprocess, "run", side_effect=_fake_run),
            ):
                result = gui.main(["--ner", "--bra-dir", str(bra_dir)])

        self.assertEqual(result, 0)
        self.assertIn("--ner", run_calls[-1])

    def test_main_exports_virtualenv_context_to_boots_main(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            project_root = Path(td)
            boots_dir = project_root / "boots"
            bra_dir = project_root / "body"
            (bra_dir / ".bra").mkdir(parents=True)

            venv_python = project_root / "boots" / ".venv" / "bin" / "python3"
            venv_bin = str(venv_python.parent)
            captured: dict[str, object] = {}

            def _fake_run(cmd, **kwargs):
                captured["cmd"] = list(cmd)
                captured["env"] = dict(kwargs.get("env", {}))
                return _Completed(0)

            with (
                patch.object(gui.Path, "resolve", return_value=boots_dir / "gui.py"),
                patch.object(gui, "_ensure_venv", return_value=venv_python),
                patch.object(gui, "_deps_installed", return_value=True),
                patch.object(gui.subprocess, "run", side_effect=_fake_run),
            ):
                result = gui.main(["--bra-dir", str(project_root)])

        self.assertEqual(result, 0)
        env = captured["env"]
        self.assertEqual(env["VIRTUAL_ENV"], str(venv_python.parent.parent))
        self.assertEqual(env["PATH"].split(":")[0], venv_bin)


if __name__ == "__main__":
    unittest.main()
