import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "body" / "layer1" / "scripts"


class RuntimeScriptNativePortTests(unittest.TestCase):
    def _setup_body(self) -> tuple[Path, Path]:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        body = root / "body"
        (body / "layer1" / "scripts").mkdir(parents=True)
        (body / ".bra" / "artifacts").mkdir(parents=True)
        (body / "layer3-engagement").mkdir(parents=True)
        return root, body

    def test_precheck_runs_without_shell_sibling(self) -> None:
        _, body = self._setup_body()
        dst = body / "layer1" / "scripts" / "precheck.py"
        shutil.copy2(SRC / "precheck.py", dst)

        result = subprocess.run(["python3", str(dst), "--fix"], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_dry_run_runs_without_shell_sibling(self) -> None:
        _, body = self._setup_body()
        dst = body / "layer1" / "scripts" / "dry-run.py"
        shutil.copy2(SRC / "dry-run.py", dst)

        result = subprocess.run(["python3", str(dst), "--help"], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Lifecycle Health Check", result.stdout)

    def test_agentic_handler_runs_without_shell_sibling(self) -> None:
        _, body = self._setup_body()
        dst = body / "layer1" / "scripts" / "agentic-handler.py"
        shutil.copy2(SRC / "agentic-handler.py", dst)

        result = subprocess.run(["python3", str(dst), "--status"], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue(result.stdout.strip())


if __name__ == "__main__":
    unittest.main()
