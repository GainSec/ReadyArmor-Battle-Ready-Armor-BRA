import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "body" / "layer1" / "scripts"

REMAINING = [
    "audit",
    "backup",
    "battlestations",
    "bra",
    "dedupe-integrated",
    "deploy",
    "generate-docs",
    "hunt",
    "integrate-ingest",
    "leads",
    "prep-deploy",
    "ref_harvest",
    "remote-ingest",
    "restore",
    "run-tests",
    "scope-intake",
    "self-improvement",
    "validate-mappings",
]


class RemainingScriptNativePortTests(unittest.TestCase):
    def _setup_body(self) -> tuple[Path, Path, Path]:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        body = root / "body"
        scripts = body / "layer1" / "scripts"
        scripts.mkdir(parents=True)
        (body / ".bra" / "artifacts").mkdir(parents=True)
        (body / ".bra" / "logs").mkdir(parents=True)
        (body / "layer3-engagement" / "NOTES").mkdir(parents=True)
        (body / "layer3-engagement" / "pitches").mkdir(parents=True)
        return root, body, scripts

    def test_remaining_scripts_do_not_require_shell_siblings(self) -> None:
        _, body, scripts = self._setup_body()

        for stem in REMAINING:
            with self.subTest(script=stem):
                dst = scripts / f"{stem}.py"
                shutil.copy2(SRC / f"{stem}.py", dst)
                result = subprocess.run(
                    ["python3", str(dst), "--help"],
                    cwd=str(body),
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(
                    result.returncode,
                    127,
                    msg=f"{stem}.py still depends on .sh: {result.stderr}",
                )
                self.assertNotIn("Missing shell script", (result.stderr or "") + (result.stdout or ""))


if __name__ == "__main__":
    unittest.main()
