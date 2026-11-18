import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "body" / "layer1" / "scripts"
HOOKS = REPO_ROOT / "body" / "layer1" / "hooks"


class GovernanceNativePortTests(unittest.TestCase):
    def _setup_body(self) -> tuple[Path, Path, Path, Path]:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        body = root / "body"
        scripts = body / "layer1" / "scripts"
        hooks = body / "layer1" / "hooks"
        scripts.mkdir(parents=True)
        hooks.mkdir(parents=True)
        (body / ".bra" / "approvals").mkdir(parents=True)
        (body / ".bra" / "logs").mkdir(parents=True)
        (body / "layer3-engagement" / "pitches").mkdir(parents=True)
        return root, body, scripts, hooks

    def _copy_script(self, stem: str, dst_scripts: Path) -> Path:
        dst = dst_scripts / f"{stem}.py"
        shutil.copy2(SCRIPTS / f"{stem}.py", dst)
        return dst

    def _copy_hook(self, stem: str, dst_hooks: Path) -> Path:
        dst = dst_hooks / f"{stem}.py"
        shutil.copy2(HOOKS / f"{stem}.py", dst)
        return dst

    def test_danger_check_shellless(self) -> None:
        _, body, scripts, _ = self._setup_body()
        script = self._copy_script("danger_check", scripts)
        env = {**os.environ, "DANGER_CHECK_DIRECT": "1"}

        safe = subprocess.run(
            ["python3", str(script), "echo", "ok"],
            cwd=str(body),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(safe.returncode, 0, msg=safe.stderr)

        blocked = subprocess.run(
            ["python3", str(script), "rm", "-rf", "/tmp/x"],
            cwd=str(body),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(blocked.returncode, 1, msg=blocked.stderr)

        approved = subprocess.run(
            ["python3", str(script), "rm", "-rf", "/tmp/x"],
            cwd=str(body),
            capture_output=True,
            text=True,
            env={**env, "DESTRUCTIVE_APPROVAL": "1"},
        )
        self.assertEqual(approved.returncode, 2, msg=approved.stderr)

    def test_approval_gate_shellless(self) -> None:
        _, body, scripts, _ = self._setup_body()
        script = self._copy_script("approval-gate", scripts)
        pitches = body / "layer3-engagement" / "pitches"

        (pitches / "one.md").write_text("# one\nSTATUS: approved\n")
        (pitches / "two.md").write_text("# two\nPENDING\n")

        block = subprocess.run(["python3", str(script), "--block"], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(block.returncode, 1, msg=block.stderr)

        (pitches / "two.md.approved").write_text("")
        block2 = subprocess.run(["python3", str(script), "--block"], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(block2.returncode, 0, msg=block2.stderr)

    def test_offensive_gate_shellless(self) -> None:
        _, body, scripts, _ = self._setup_body()
        script = self._copy_script("offensive_gate", scripts)
        scope = body / "layer3-engagement" / "SCOPE.md"
        scope.write_text("ACTIVE-TESTING-APPROVAL: ASK\n")

        check = subprocess.run(["python3", str(script), "--check"], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(check.returncode, 1, msg=check.stderr)

        req = subprocess.run(
            ["python3", str(script), "--request", "fuzzing", "api.example.com", "--description", "test"],
            cwd=str(body),
            capture_output=True,
            text=True,
        )
        self.assertEqual(req.returncode, 2, msg=req.stderr)
        self.assertTrue(any((body / "layer3-engagement" / "pitches").glob("offensive-testing-pitch-*.md")))

        set_ok = subprocess.run(["python3", str(script), "--set"], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(set_ok.returncode, 0, msg=set_ok.stderr)

    def test_notes_guard_shellless(self) -> None:
        _, body, scripts, _ = self._setup_body()
        script = self._copy_script("notes_guard", scripts)
        notes = body / "layer3-engagement" / "NOTES"
        notes.mkdir(parents=True, exist_ok=True)
        target = notes / "FINDINGS.md"
        target.write_text("line1\n")

        ok_append = subprocess.run(["python3", str(script), "append", str(target)], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(ok_append.returncode, 0, msg=ok_append.stderr)

        blocked = subprocess.run(["python3", str(script), "delete", str(target)], cwd=str(body), capture_output=True, text=True)
        self.assertEqual(blocked.returncode, 1, msg=blocked.stderr)

    def test_track_post_shellless(self) -> None:
        _, body, _, hooks = self._setup_body()
        script = self._copy_hook("track-post", hooks)

        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "echo hi"},
        }
        result = subprocess.run(
            ["python3", str(script)],
            input=json.dumps(payload),
            cwd=str(body),
            capture_output=True,
            text=True,
            env={**os.environ, "TRACK": "1"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        track_log = body / ".bra" / "logs" / "track.log"
        self.assertTrue(track_log.exists())
        self.assertIn("Bash", track_log.read_text())


if __name__ == "__main__":
    unittest.main()
