import shutil
import subprocess
import tempfile
import unittest
import os
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "body" / "layer1" / "scripts"


class EndPipelineNativePortTests(unittest.TestCase):
    _MINIMAL_FINDING = """## [FINDING-001] Default credentials
| **Severity** | HIGH |
| **CVSS** | 8.8 |
| **CWE** | CWE-798 |
| **Status** | Open |
"""

    def _setup_body(self) -> tuple[Path, Path, Path]:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        body = root / "body"
        scripts = body / "layer1" / "scripts"
        scripts.mkdir(parents=True)

        (body / ".bra" / "artifacts").mkdir(parents=True)
        (body / ".bra" / "logs").mkdir(parents=True)
        (body / "layer3-engagement" / "disclosure").mkdir(parents=True)
        (body / "layer3-engagement" / "NOTES").mkdir(parents=True)
        (body / "layer3-engagement" / "NOTES" / "FINDINGS.md").write_text(self._MINIMAL_FINDING)
        (body / "layer3-engagement" / "SCOPE.md").write_text("# Scope\n")
        return root, body, scripts

    def _copy_script(self, name: str, dst_scripts: Path) -> Path:
        dst = dst_scripts / f"{name}.py"
        shutil.copy2(SCRIPTS / f"{name}.py", dst)
        return dst

    def test_growth_runs_without_shell_sibling(self) -> None:
        _, body, scripts = self._setup_body()
        script = self._copy_script("growth", scripts)
        result = subprocess.run(["python3", str(script)], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_stats_runs_without_shell_sibling(self) -> None:
        _, body, scripts = self._setup_body()
        script = self._copy_script("stats", scripts)
        result = subprocess.run(["python3", str(script), "--full"], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue(result.stdout.strip())

    def test_report_ready_and_disclose_create_outputs(self) -> None:
        _, body, scripts = self._setup_body()
        report_script = self._copy_script("report-ready", scripts)
        disclose_script = self._copy_script("disclose", scripts)
        env = {
            **os.environ,
            "BRA_VENDOR": "Acme Cameras",
            "BRA_EMAIL": "researcher@example.com",
            "BRA_PGP_KEY": "0xDEADBEEF",
            "BRA_VENDOR_CONTACT": "security@acme.example",
            "BRA_RESEARCHER": "GainSec Research",
        }

        rr = subprocess.run(
            ["python3", str(report_script), "--types", "generic,vendor,cna", "--non-interactive"],
            cwd=str(body),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(rr.returncode, 0, msg=rr.stderr)

        dc = subprocess.run(
            ["python3", str(disclose_script), "--types", "vendor,cna", "--non-interactive"],
            cwd=str(body),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(dc.returncode, 0, msg=dc.stderr)

        l3 = body / "layer3-engagement"
        disclosure = l3 / "disclosure"
        self.assertTrue((l3 / "REPORT.md").exists())
        self.assertTrue((disclosure / "vendor-submission.md").exists())
        self.assertTrue((disclosure / "cna-submission.md").exists())

    def test_lessons_learned_runs_without_shell_sibling(self) -> None:
        _, body, scripts = self._setup_body()
        script = self._copy_script("lessons-learned", scripts)
        result = subprocess.run(["python3", str(script)], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue((body / "layer3-engagement" / "LESSONS-LEARNED.md").exists())

    def test_reset_force_clears_runtime_state(self) -> None:
        _, body, scripts = self._setup_body()
        script = self._copy_script("reset", scripts)

        (body / ".bra" / "artifacts" / "tmp.txt").write_text("x")
        (body / "layer3-engagement" / "REPORT.md").write_text("r")

        env = os.environ.copy()
        env["DESTRUCTIVE_APPROVAL"] = "1"
        result = subprocess.run(["python3", str(script), "--force"], cwd=str(body), capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        self.assertFalse((body / ".bra" / "artifacts" / "tmp.txt").exists())
        self.assertTrue((body / ".bra" / "artifacts").is_dir())
        self.assertNotEqual((body / "layer3-engagement" / "REPORT.md").read_text(), "r")

    def test_packup_creates_archive(self) -> None:
        _, body, scripts = self._setup_body()
        script = self._copy_script("packup", scripts)

        result = subprocess.run(["python3", str(script), "--minimal"], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        archives = sorted(body.glob("packup_*.tar.gz"))
        self.assertTrue(archives)


if __name__ == "__main__":
    unittest.main()
