from __future__ import annotations

import os
import tempfile
import textwrap
import unittest
from pathlib import Path

from bra.config import settings as settings_module
from bra.core.bridge import run_script


class BridgePythonPortDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._old_bra_root = getattr(settings_module, "_bra_root", None)
        self._old_env = dict(os.environ)

    def tearDown(self) -> None:
        settings_module._bra_root = self._old_bra_root
        os.environ.clear()
        os.environ.update(self._old_env)

    def _make_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        scripts_dir = root / "body" / "layer1" / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        settings_module._bra_root = root
        return td, root, scripts_dir

    def test_runs_python_script(self) -> None:
        td, _, scripts = self._make_root()
        with td:
            (scripts / "hello.py").write_text(
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import os
                    print(f"python:{os.environ.get('BRA_LAYER1_PORT','missing')}")
                    """
                ).strip()
                + "\n"
            )
            (scripts / "hello.py").chmod(0o755)

            result = run_script("hello.py")

            self.assertEqual(result.returncode, 0)
            self.assertIn("python:python", result.stdout.strip())

    def test_rejects_legacy_sh_name(self) -> None:
        """Hard Python-only bridge: .sh entrypoints are no longer accepted."""
        td, _, scripts = self._make_root()
        with td:
            (scripts / "hello.py").write_text(
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    print("python-path-ran")
                    """
                ).strip()
                + "\n"
            )
            (scripts / "hello.py").chmod(0o755)

            with self.assertRaises(FileNotFoundError):
                run_script("hello.sh")

    def test_raises_for_missing_script(self) -> None:
        td, _, _ = self._make_root()
        with td:
            with self.assertRaises(FileNotFoundError):
                run_script("missing.py")

    def test_raises_for_missing_py_even_if_sh_exists(self) -> None:
        """Shell fallback is removed — missing .py raises even if .sh exists."""
        td, _, scripts = self._make_root()
        with td:
            sh_path = scripts / "hello.sh"
            sh_path.write_text("#!/usr/bin/env bash\necho shell\n")
            sh_path.chmod(0o755)

            with self.assertRaises(FileNotFoundError):
                run_script("hello.sh")

    def test_passes_args_to_script(self) -> None:
        td, _, scripts = self._make_root()
        with td:
            (scripts / "echo_args.py").write_text(
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import sys
                    print(" ".join(sys.argv[1:]))
                    """
                ).strip()
                + "\n"
            )
            (scripts / "echo_args.py").chmod(0o755)

            result = run_script("echo_args.py", "--foo", "bar")

            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "--foo bar")


if __name__ == "__main__":
    unittest.main()
