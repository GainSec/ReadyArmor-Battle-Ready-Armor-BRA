import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_FILE_GUARD = REPO_ROOT / "body" / "layer1" / "hooks" / "file-guard.py"


class FileGuardPythonNativeTests(unittest.TestCase):
    def _run_guard(self, script: Path, payload: dict, cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(script)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            cwd=str(cwd),
        )

    def test_blocks_layer1_write_without_shell_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": "layer1/scripts/reset.sh",
                    "content": "x",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "LAYER1_IMMUTABLE")
            self.assertIn("layer1", decision["reason"])
            self.assertEqual(decision["meta"], {})

    def test_blocks_write_outside_containment_with_stable_policy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": "elsewhere/out.txt",
                    "content": "x",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "FILE_PATH_CONTAINMENT_BLOCKED")
            self.assertIn("outside allowed directories", decision["reason"])

    def test_blocks_layer2_write_without_token_with_stable_policy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": "layer2-templates/plan.md",
                    "content": "x",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "LAYER2_WRITE_TOKEN_REQUIRED")
            self.assertIn("LAYER2-WRITE-APPROVAL", decision["reason"])

    def test_blocks_scope_write_after_confirmation_with_stable_policy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)
            approvals = body / ".bra" / "approvals"
            approvals.mkdir(parents=True)
            (approvals / "SCOPE-CONFIRMED").write_text("yes\n")

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": "layer3-engagement/SCOPE.md",
                    "content": "x",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "SCOPE_LOCKED_AFTER_CONFIRMATION")
            self.assertIn("SCOPE-CONFIRMED", decision["reason"])

    def test_blocks_append_only_shrink_with_stable_policy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)
            layer3 = body / "layer3-engagement"
            layer3.mkdir(parents=True)
            report = layer3 / "REPORT.md"
            report.write_text("existing report content\n")

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": str(report),
                    "content": "tiny\n",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "APPEND_ONLY_VIOLATION")
            self.assertIn("append-only", decision["reason"])

    def test_blocks_undocumented_findings_write_with_stable_policy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)
            notes = body / "layer3-engagement" / "NOTES"
            notes.mkdir(parents=True)
            (notes / "INTEL.md").write_text(
                "## Key Issues Overview\n\n| ID | Title |\n| --- | --- |\n| 001 | Missing auth |\n",
                encoding="utf-8",
            )
            (notes / "FINDINGS.md").write_text("", encoding="utf-8")

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": str(notes / "INTEL-DELTA.md"),
                    "content": "new intel\n",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "UNDOCUMENTED_FINDINGS_BLOCKED")
            self.assertIn("FINDING-001", decision["reason"])

    def test_blocks_finding_like_artifact_content_with_stable_policy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)
            artifacts = body / ".bra" / "artifacts"
            artifacts.mkdir(parents=True)

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": str(artifacts / "finding-notes.md"),
                    "content": "Severity: High\nCWE-79\n",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "ARTIFACT_FINDING_CONTENT_BLOCKED")
            self.assertIn("finding record", decision["reason"])

    def test_blocks_unknown_layer3_subdir_with_stable_policy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": "layer3-engagement/private-cache/out.txt",
                    "content": "x",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "LAYER3_ALLOWLIST_BLOCKED")
            self.assertIn("allowlist", decision["reason"])

    def test_blocks_layer3_artifacts_with_redirect_to_bra_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": "layer3-engagement/artifacts/runtime.txt",
                    "content": "runtime output",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "LAYER3_ARTIFACTS_BLOCKED")
            self.assertIn(".bra/artifacts/", decision["reason"])

    def test_blocks_bra_schema_path_with_stable_policy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": ".bra/approvals/out.txt",
                    "content": "x",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "BRA_SCHEMA_BLOCKED")
            self.assertIn(".bra/approvals", decision["reason"])

    def test_blocks_invalid_write_request_without_file_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "content": "x",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "INVALID_FILE_GUARD_REQUEST")
            self.assertIn("missing required field", decision["reason"])

    def test_blocks_invalid_read_request_without_file_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)

            payload = {
                "tool_name": "Read",
                "tool_input": {},
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "INVALID_FILE_GUARD_REQUEST")
            self.assertIn("missing required path", decision["reason"])

    def test_blocks_invalid_glob_request_without_path_or_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)

            payload = {
                "tool_name": "Glob",
                "tool_input": {},
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "INVALID_FILE_GUARD_REQUEST")
            self.assertIn("missing required path", decision["reason"])

    def test_allows_artifacts_write_without_shell_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)
            (body / ".bra" / "artifacts").mkdir(parents=True)

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": ".bra/artifacts/out.txt",
                    "content": "x",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "allow")
            self.assertEqual(decision["policy"], "ALLOW")
            self.assertEqual(decision["reason"], "")
            self.assertEqual(decision["meta"], {})

    def test_blocks_read_of_bra_claude_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)
            claude_dir = body / ".bra" / ".claude"
            claude_dir.mkdir(parents=True)
            session_file = claude_dir / "state.jsonl"
            session_file.write_text("{}\n")

            payload = {
                "tool_name": "Read",
                "tool_input": {
                    "file_path": str(session_file),
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "BRA_CLAUDE_STATE_READ_BLOCKED")
            self.assertIn(".bra/.claude", decision["reason"])
            self.assertEqual(decision["meta"], {})

    def test_blocks_read_of_anon_map(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)
            bra_dir = body / ".bra"
            bra_dir.mkdir(parents=True)
            map_file = bra_dir / "anon_map.json"
            map_file.write_text("{}\n")

            payload = {
                "tool_name": "Read",
                "tool_input": {
                    "file_path": str(map_file),
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "BRA_ANON_MAP_READ_BLOCKED")
            self.assertIn("anon_map.json", decision["reason"])
            self.assertEqual(decision["meta"], {})

    def test_blocks_grep_of_bra_claude_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)

            payload = {
                "tool_name": "Grep",
                "tool_input": {
                    "path": str(body / ".bra" / ".claude"),
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "BRA_CLAUDE_STATE_READ_BLOCKED")
            self.assertIn(".bra/.claude", decision["reason"])
            self.assertEqual(decision["meta"], {})

    def test_blocks_glob_of_anon_map(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)

            payload = {
                "tool_name": "Glob",
                "tool_input": {
                    "path": str(body / ".bra"),
                    "pattern": "**/anon_map.json",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "BRA_ANON_MAP_READ_BLOCKED")
            self.assertIn("anon_map.json", decision["reason"])
            self.assertEqual(decision["meta"], {})

    def test_allows_write_to_bra_claude_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)
            (body / ".bra" / ".claude").mkdir(parents=True)

            payload = {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": ".bra/.claude/tool-results/toolu_123.txt",
                    "content": "masked output",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "allow")
            self.assertEqual(decision["policy"], "ALLOW")
            self.assertEqual(decision["reason"], "")
            self.assertEqual(decision["meta"], {})

    def test_blocks_edit_to_bra_claude_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)
            claude_dir = body / ".bra" / ".claude" / "tool-results"
            claude_dir.mkdir(parents=True)
            target = claude_dir / "toolu_123.txt"
            target.write_text("masked output\n")

            payload = {
                "tool_name": "Edit",
                "tool_input": {
                    "file_path": ".bra/.claude/tool-results/toolu_123.txt",
                    "old_string": "masked",
                    "new_string": "redacted",
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertEqual(decision["policy"], "BRA_CLAUDE_STATE_BLOCKED")
            self.assertIn(".bra/.claude", decision["reason"])
            self.assertEqual(decision["meta"], {})

    def test_allows_non_claude_read(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            hooks = body / "layer1" / "hooks"
            hooks.mkdir(parents=True)
            dst = hooks / "file-guard.py"
            shutil.copy2(SRC_FILE_GUARD, dst)
            notes_dir = body / "layer3-engagement" / "NOTES"
            notes_dir.mkdir(parents=True)
            notes_file = notes_dir / "INTEL.md"
            notes_file.write_text("intel\n")

            payload = {
                "tool_name": "Read",
                "tool_input": {
                    "file_path": str(notes_file),
                },
            }
            result = self._run_guard(dst, payload, body)
            self.assertEqual(result.returncode, 0)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "allow")
            self.assertEqual(decision["policy"], "ALLOW")
            self.assertEqual(decision["reason"], "")
            self.assertEqual(decision["meta"], {})


if __name__ == "__main__":
    unittest.main()
