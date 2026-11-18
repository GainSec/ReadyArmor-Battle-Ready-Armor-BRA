import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_BASH_GUARD = REPO_ROOT / "body" / "layer1" / "hooks" / "bash-guard.py"


class BashGuardPythonNativeTests(unittest.TestCase):
    def _run_guard(self, script: Path, payload: dict, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        return subprocess.run(
            ["python3", str(script)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            cwd=str(cwd),
            env=merged_env,
        )

    def test_allows_safe_command_without_shell_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "bash-guard.py"
            shutil.copy2(SRC_BASH_GUARD, dst)
            (body / ".bra" / "logs").mkdir(parents=True)

            payload = {"tool_name": "Bash", "tool_input": {"command": "echo hello"}}
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_blocks_when_killswitch_env_active(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "bash-guard.py"
            shutil.copy2(SRC_BASH_GUARD, dst)

            payload = {"tool_name": "Bash", "tool_input": {"command": "echo hello"}}
            result = self._run_guard(dst, payload, body, env={"BRA_STOP": "1"})
            self.assertEqual(result.returncode, 99)

    def _setup_anon_body(self, td: str, mappings: list[dict]) -> tuple[Path, Path]:
        """Create body dir with anon_map.json and return (body, guard_script)."""
        root = Path(td)
        body = root / "body"
        hooks = body / "layer1" / "hooks"
        hooks.mkdir(parents=True)
        dst = hooks / "bash-guard.py"
        shutil.copy2(SRC_BASH_GUARD, dst)
        (body / ".bra" / "logs").mkdir(parents=True)
        (body / ".bra" / "artifacts" / "raw").mkdir(parents=True)
        map_path = body / ".bra" / "anon_map.json"
        map_data = {
            "version": 1,
            "engagement": "test",
            "created": "2026-01-01T00:00:00Z",
            "mappings": mappings,
        }
        map_path.write_text(json.dumps(map_data))
        return body, dst

    def test_anon_intercept_unmasks_and_captures(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mappings = [
                {"real": "192.168.1.100", "anon": "BLANKET", "type": "ip", "source": "scope"},
            ]
            body, dst = self._setup_anon_body(td, mappings)
            payload = {
                "tool_name": "Bash",
                "tool_input": {"command": "echo target is BLANKET"},
                "tool_use_id": "toolu_test123abc",
                "session_id": "sess_test",
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 2, msg=f"stdout={result.stdout} stderr={result.stderr}")
            self.assertIn("ANON_INTERCEPT_OK", result.stderr)
            self.assertIn("BLANKET", result.stderr)
            self.assertNotIn("192.168.1.100", result.stderr)

    def test_anon_intercept_saves_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mappings = [
                {"real": "10.0.0.5", "anon": "CASTLE", "type": "ip", "source": "scope"},
            ]
            body, dst = self._setup_anon_body(td, mappings)
            payload = {"tool_name": "Bash", "tool_input": {"command": "echo scan result CASTLE"}}
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 2)
            raw_dir = body / ".bra" / "artifacts" / "raw"
            artifacts = list(raw_dir.glob("anon_*.txt"))
            self.assertGreaterEqual(len(artifacts), 1, "No artifact file created")
            content = artifacts[0].read_text()
            self.assertIn("CASTLE", content)
            self.assertNotIn("10.0.0.5", content)

    def test_anon_no_intercept_without_anon_words(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mappings = [
                {"real": "192.168.1.100", "anon": "BLANKET", "type": "ip", "source": "scope"},
            ]
            body, dst = self._setup_anon_body(td, mappings)
            payload = {"tool_name": "Bash", "tool_input": {"command": "echo hello world"}}
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_anon_no_intercept_without_map(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "bash-guard.py"
            shutil.copy2(SRC_BASH_GUARD, dst)
            (body / ".bra" / "logs").mkdir(parents=True)
            payload = {"tool_name": "Bash", "tool_input": {"command": "echo BLANKET"}}
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_unapproved_network_action_requests_scope_modal_without_approve_target_instruction(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "bash-guard.py"
            shutil.copy2(SRC_BASH_GUARD, dst)
            (body / ".bra" / "logs").mkdir(parents=True)
            approvals = body / ".bra" / "approvals"
            approvals.mkdir(parents=True)
            (approvals / "ACTIVE-TESTING-APPROVAL").touch()
            scope_md = body / "layer3-engagement" / "SCOPE.md"
            scope_md.parent.mkdir(parents=True)
            scope_md.write_text(
                "\n".join(
                    [
                        "# Scope",
                        "",
                        "### Network Targets",
                        "- **192.168.18.9**",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            payload = {"tool_name": "Bash", "tool_input": {"command": "nmap google.com"}}
            result = self._run_guard(dst, payload, body)

            self.assertEqual(result.returncode, 2)
            self.assertIn("SCOPE_CHECK_REQUIRED", result.stderr)
            self.assertIn("TARGET=google.com", result.stderr)
            self.assertIn("Wait for the operator's scope approval modal", result.stderr)
            self.assertNotIn("approve-target.py 'google.com'", result.stderr)

    def test_anon_intercept_multiple_mappings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mappings = [
                {"real": "192.168.1.1", "anon": "APPLE", "type": "ip", "source": "scope"},
                {"real": "8080", "anon": "BANANA", "type": "operator-flagged", "source": "scope"},
            ]
            body, dst = self._setup_anon_body(td, mappings)
            payload = {"tool_name": "Bash", "tool_input": {"command": "echo APPLE:BANANA"}}
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 2)
            self.assertIn("APPLE", result.stderr)
            self.assertIn("BANANA", result.stderr)
            self.assertNotIn("192.168.1.1", result.stderr)
            self.assertNotIn("8080", result.stderr)

    def test_anon_intercept_stderr_has_artifact_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mappings = [
                {"real": "secret.local", "anon": "DRAGON", "type": "hostname", "source": "scope"},
            ]
            body, dst = self._setup_anon_body(td, mappings)
            payload = {"tool_name": "Bash", "tool_input": {"command": "echo host DRAGON"}}
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 2)
            self.assertIn(".bra/artifacts/raw/", result.stderr)

    def test_anon_intercept_capture_id_in_artifact_name(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mappings = [
                {"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"},
            ]
            body, dst = self._setup_anon_body(td, mappings)
            payload = {
                "tool_name": "Bash",
                "tool_input": {"command": "echo FALCON"},
                "tool_use_id": "toolu_01abc789xyz",
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 2)
            raw_dir = body / ".bra" / "artifacts" / "raw"
            artifacts = list(raw_dir.glob("*.txt"))
            self.assertGreaterEqual(len(artifacts), 1)
            self.assertTrue(
                artifacts[0].name.startswith("toolu_01abc789xyz_"),
                f"Expected capture_id prefix, got: {artifacts[0].name}",
            )

    def test_anon_intercept_writes_last_capture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mappings = [
                {"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"},
            ]
            body, dst = self._setup_anon_body(td, mappings)
            payload = {
                "tool_name": "Bash",
                "tool_input": {"command": "echo FALCON"},
                "tool_use_id": "toolu_01abc789xyz",
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 2)
            lc = body / ".bra" / "last_capture.json"
            self.assertTrue(lc.exists(), "last_capture.json not written")
            data = json.loads(lc.read_text())
            self.assertEqual(data["capture_id"], "toolu_01abc789xyz")
            self.assertTrue(data["anon_intercepted"])
            self.assertIn("artifacts/raw/", data["path"])
            self.assertIn("FALCON", data["command"])

    def test_anon_intercept_writes_evidence_index(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mappings = [
                {"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"},
            ]
            body, dst = self._setup_anon_body(td, mappings)
            payload = {
                "tool_name": "Bash",
                "tool_input": {"command": "echo FALCON"},
                "tool_use_id": "toolu_01evidence",
                "session_id": "sess_42",
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 2)
            idx = body / ".bra" / "logs" / "evidence_index.jsonl"
            self.assertTrue(idx.exists(), "evidence_index.jsonl not written")
            lines = [l for l in idx.read_text().splitlines() if l.strip()]
            self.assertGreaterEqual(len(lines), 1)
            record = json.loads(lines[-1])
            for field in (
                "capture_id", "session_id", "tool_use_id", "tool_name",
                "action", "target", "artifact_path", "artifact_sha256",
                "source_kind", "created_at",
            ):
                self.assertIn(field, record, f"Missing field: {field}")
            self.assertEqual(record["capture_id"], "toolu_01evidence")
            self.assertEqual(record["session_id"], "sess_42")
            self.assertEqual(record["tool_use_id"], "toolu_01evidence")
            self.assertEqual(record["source_kind"], "anon_intercept")
            self.assertEqual(record["tool_name"], "Bash")

    def test_anon_intercept_preserves_local_redirect_paths_while_unmasking_targets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mappings = [
                {"real": "10.0.0.5", "anon": "CASTLE", "type": "ip", "source": "scope"},
            ]
            body, dst = self._setup_anon_body(td, mappings)
            payload = {
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "echo http://CASTLE/ > .bra/artifacts/raw/CASTLE_root_full.html "
                        "&& cat .bra/artifacts/raw/CASTLE_root_full.html"
                    )
                },
                "tool_use_id": "toolu_01redirect",
            }

            result = self._run_guard(dst, payload, body)

            self.assertEqual(result.returncode, 2, msg=result.stderr)
            self.assertIn("ANON_INTERCEPT_OK", result.stderr)
            self.assertIn("http://CASTLE/", result.stderr)
            self.assertNotIn("http://10.0.0.5/", result.stderr)

            anon_file = body / ".bra" / "artifacts" / "raw" / "CASTLE_root_full.html"
            real_file = body / ".bra" / "artifacts" / "raw" / "10.0.0.5_root_full.html"
            self.assertTrue(anon_file.exists(), "expected redirect path to preserve anon filename")
            self.assertFalse(real_file.exists(), "real target identifier leaked into local redirect filename")
            self.assertIn("http://10.0.0.5/", anon_file.read_text(encoding="utf-8"))

    def test_anon_disable_bypasses_intercept(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mappings = [
                {"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"},
            ]
            body, dst = self._setup_anon_body(td, mappings)
            approvals = body / ".bra" / "approvals"
            approvals.mkdir(parents=True, exist_ok=True)
            (approvals / "ANON-DISABLE").touch()
            payload = {"tool_name": "Bash", "tool_input": {"command": "echo FALCON"}}
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertNotIn("ANON_INTERCEPT_OK", result.stderr)

    def test_blocks_read_of_project_local_bra_claude_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "bash-guard.py"
            shutil.copy2(SRC_BASH_GUARD, dst)
            (body / ".bra" / "logs").mkdir(parents=True)
            (body / ".bra" / ".claude").mkdir(parents=True)

            payload = {"tool_name": "Bash", "tool_input": {"command": "cat .bra/.claude/state.jsonl"}}
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 2)
            self.assertIn(".bra/.claude", result.stderr)

    def test_blocks_access_to_anon_map(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "bash-guard.py"
            shutil.copy2(SRC_BASH_GUARD, dst)
            (body / ".bra" / "logs").mkdir(parents=True)
            (body / ".bra" / "anon_map.json").write_text("{}\n")

            payload = {"tool_name": "Bash", "tool_input": {"command": "cat .bra/anon_map.json"}}
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 2)
            self.assertIn("anon_map.json", result.stderr)

    def test_allows_write_to_project_local_bra_claude_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "bash-guard.py"
            shutil.copy2(SRC_BASH_GUARD, dst)
            (body / ".bra" / "logs").mkdir(parents=True)
            (body / ".bra" / ".claude").mkdir(parents=True)

            payload = {"tool_name": "Bash", "tool_input": {"command": "echo masked > .bra/.claude/state.jsonl"}}
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_allows_absolute_write_to_project_local_bra_claude_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "bash-guard.py"
            shutil.copy2(SRC_BASH_GUARD, dst)
            (body / ".bra" / "logs").mkdir(parents=True)
            (body / ".bra" / ".claude").mkdir(parents=True)
            target = body / ".bra" / ".claude" / "state.jsonl"

            payload = {"tool_name": "Bash", "tool_input": {"command": f"echo masked > {target}"}}
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0, msg=result.stderr)


if __name__ == "__main__":
    unittest.main()
