from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bra.config import settings as settings_module
from bra.hooks import file_hook, registry


class HeadClaudeStateGuardsTests(unittest.IsolatedAsyncioTestCase):
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
        hooks = root / "body" / "layer1" / "hooks"
        hooks.mkdir(parents=True, exist_ok=True)
        settings_module._bra_root = root
        return td, root, hooks

    @staticmethod
    def _write_exec(path: Path, content: str) -> None:
        path.write_text(content)
        path.chmod(0o755)

    async def test_pre_file_delegates_allow_to_guard(self) -> None:
        td, _, hooks = self._make_root()
        with td:
            self._write_exec(
                hooks / "file-guard.py",
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import json
                    import sys
                    payload = json.loads(sys.stdin.read())
                    assert payload["tool_name"] == "Write"
                    assert payload["tool_input"]["file_path"].endswith("toolu_123.txt")
                    json.dump({"decision": "allow", "policy": "ALLOW", "reason": "", "meta": {}}, sys.stdout)
                    sys.stdout.write("\\n")
                    """
                ).strip()
                + "\n",
            )

            result = await file_hook.pre_file(
                {"tool_input": {"file_path": ".bra/.claude/tool-results/toolu_123.txt", "content": "masked output"}},
                None,
                {},
            )

        self.assertEqual(result, {})

    async def test_pre_read_passes_through_guard_block(self) -> None:
        td, _, hooks = self._make_root()
        with td:
            self._write_exec(
                hooks / "file-guard.py",
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import json
                    import sys
                    payload = json.loads(sys.stdin.read())
                    assert payload["tool_name"] == "Read"
                    json.dump(
                        {
                            "decision": "block",
                            "policy": "BRA_CLAUDE_STATE_READ_BLOCKED",
                            "reason": "blocked by guard",
                            "meta": {},
                        },
                        sys.stdout,
                    )
                    sys.stdout.write("\\n")
                    """
                ).strip()
                + "\n",
            )

            result = await file_hook.pre_read(
                {"tool_input": {"file_path": "/tmp/project/.bra/.claude/tool-results/toolu_123.txt"}},
                None,
                {},
            )

        self.assertEqual(result.get("decision"), "block")
        self.assertEqual(result.get("reason"), "blocked by guard")
        self.assertEqual(result.get("policy"), "BRA_CLAUDE_STATE_READ_BLOCKED")

    async def test_pre_grep_passes_through_guard_block(self) -> None:
        td, _, hooks = self._make_root()
        with td:
            self._write_exec(
                hooks / "file-guard.py",
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import json
                    import sys
                    payload = json.loads(sys.stdin.read())
                    assert payload["tool_name"] == "Grep"
                    assert payload["tool_input"]["path"].endswith(".bra/anon_map.json")
                    json.dump(
                        {
                            "decision": "block",
                            "policy": "BRA_ANON_MAP_READ_BLOCKED",
                            "reason": "grep blocked by guard",
                            "meta": {},
                        },
                        sys.stdout,
                    )
                    sys.stdout.write("\\n")
                    """
                ).strip()
                + "\n",
            )

            result = await file_hook.pre_grep(
                {"tool_input": {"path": "/tmp/project/.bra/anon_map.json"}},
                None,
                {},
            )

        self.assertEqual(result.get("decision"), "block")
        self.assertEqual(result.get("reason"), "grep blocked by guard")
        self.assertEqual(result.get("policy"), "BRA_ANON_MAP_READ_BLOCKED")

    async def test_pre_glob_passes_through_guard_block(self) -> None:
        td, _, hooks = self._make_root()
        with td:
            self._write_exec(
                hooks / "file-guard.py",
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import json
                    import sys
                    payload = json.loads(sys.stdin.read())
                    assert payload["tool_name"] == "Glob"
                    assert payload["tool_input"]["pattern"] == "**/anon_map.json"
                    json.dump(
                        {
                            "decision": "block",
                            "policy": "BRA_ANON_MAP_READ_BLOCKED",
                            "reason": "glob blocked by guard",
                            "meta": {},
                        },
                        sys.stdout,
                    )
                    sys.stdout.write("\\n")
                    """
                ).strip()
                + "\n",
            )

            result = await file_hook.pre_glob(
                {"tool_input": {"path": "/tmp/project/.bra", "pattern": "**/anon_map.json"}},
                None,
                {},
            )

        self.assertEqual(result.get("decision"), "block")
        self.assertEqual(result.get("reason"), "glob blocked by guard")
        self.assertEqual(result.get("policy"), "BRA_ANON_MAP_READ_BLOCKED")

    async def test_pre_read_blocks_when_guard_is_missing(self) -> None:
        td, _, _ = self._make_root()
        with td:
            result = await file_hook.pre_read(
                {"tool_input": {"file_path": "/tmp/project/.bra/.claude/tool-results/toolu_123.txt"}},
                None,
                {},
            )

        self.assertEqual(result.get("decision"), "block")
        self.assertEqual(result.get("policy"), "FILE_GUARD_TRANSPORT_ERROR")
        self.assertIn("missing", result.get("reason", ""))

    async def test_pre_read_blocks_on_invalid_guard_json(self) -> None:
        td, _, hooks = self._make_root()
        with td:
            self._write_exec(
                hooks / "file-guard.py",
                "#!/usr/bin/env python3\nimport sys\nsys.stdout.write('not-json\\n')\n",
            )

            result = await file_hook.pre_read(
                {"tool_input": {"file_path": "/tmp/project/.bra/.claude/tool-results/toolu_123.txt"}},
                None,
                {},
            )

        self.assertEqual(result.get("decision"), "block")
        self.assertEqual(result.get("policy"), "FILE_GUARD_TRANSPORT_ERROR")
        self.assertIn("invalid guard JSON", result.get("reason", ""))

    async def test_pre_file_passes_through_stable_bra_schema_policy(self) -> None:
        td, _, hooks = self._make_root()
        with td:
            self._write_exec(
                hooks / "file-guard.py",
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import json
                    import sys
                    json.dump(
                        {
                            "decision": "block",
                            "policy": "BRA_SCHEMA_BLOCKED",
                            "reason": "schema blocked by guard",
                            "meta": {},
                        },
                        sys.stdout,
                    )
                    sys.stdout.write("\\n")
                    """
                ).strip()
                + "\n",
            )

            result = await file_hook.pre_file(
                {"tool_input": {"file_path": ".bra/approvals/out.txt", "content": "x"}},
                None,
                {},
            )

        self.assertEqual(result.get("decision"), "block")
        self.assertEqual(result.get("policy"), "BRA_SCHEMA_BLOCKED")
        self.assertEqual(result.get("reason"), "schema blocked by guard")

    async def test_pre_file_passes_through_claude_state_edit_block(self) -> None:
        td, _, hooks = self._make_root()
        with td:
            self._write_exec(
                hooks / "file-guard.py",
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import json
                    import sys
                    payload = json.loads(sys.stdin.read())
                    assert payload["tool_name"] == "Edit"
                    json.dump(
                        {
                            "decision": "block",
                            "policy": "BRA_CLAUDE_STATE_BLOCKED",
                            "reason": "claude state blocked",
                            "meta": {},
                        },
                        sys.stdout,
                    )
                    sys.stdout.write("\\n")
                    """
                ).strip()
                + "\n",
            )

            result = await file_hook.pre_file(
                {
                    "tool_input": {
                        "file_path": ".bra/.claude/tool-results/toolu_123.txt",
                        "old_string": "masked",
                        "new_string": "redacted",
                    }
                },
                None,
                {},
            )

        self.assertEqual(result.get("decision"), "block")
        self.assertEqual(result.get("policy"), "BRA_CLAUDE_STATE_BLOCKED")
        self.assertEqual(result.get("reason"), "claude state blocked")
        self.assertEqual(result.get("meta"), {})

    async def test_pre_file_passes_through_layer3_artifacts_block(self) -> None:
        td, _, hooks = self._make_root()
        with td:
            self._write_exec(
                hooks / "file-guard.py",
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import json
                    import sys
                    payload = json.loads(sys.stdin.read())
                    assert payload["tool_name"] == "Write"
                    json.dump(
                        {
                            "decision": "block",
                            "policy": "LAYER3_ARTIFACTS_BLOCKED",
                            "reason": "use .bra/artifacts/",
                            "meta": {},
                        },
                        sys.stdout,
                    )
                    sys.stdout.write("\\n")
                    """
                ).strip()
                + "\n",
            )

            result = await file_hook.pre_file(
                {
                    "tool_input": {
                        "file_path": "layer3-engagement/artifacts/runtime.txt",
                        "content": "runtime output",
                    }
                },
                None,
                {},
            )

        self.assertEqual(result.get("decision"), "block")
        self.assertEqual(result.get("policy"), "LAYER3_ARTIFACTS_BLOCKED")
        self.assertEqual(result.get("reason"), "use .bra/artifacts/")
        self.assertEqual(result.get("meta"), {})

    async def test_pre_read_blocks_on_nonzero_guard_exit(self) -> None:
        td, _, hooks = self._make_root()
        with td:
            self._write_exec(
                hooks / "file-guard.py",
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import json
                    import sys
                    json.dump({"decision": "allow", "policy": "ALLOW", "reason": "", "meta": {}}, sys.stdout)
                    sys.stdout.write("\\n")
                    raise SystemExit(7)
                    """
                ).strip()
                + "\n",
            )

            result = await file_hook.pre_read(
                {"tool_input": {"file_path": "/tmp/project/.bra/.claude/tool-results/toolu_123.txt"}},
                None,
                {},
            )

        self.assertEqual(result.get("decision"), "block")
        self.assertEqual(result.get("policy"), "FILE_GUARD_TRANSPORT_ERROR")
        self.assertIn("exited with code 7", result.get("reason", ""))

    async def test_pre_read_blocks_on_guard_timeout(self) -> None:
        td, _, hooks = self._make_root()
        with td:
            self._write_exec(
                hooks / "file-guard.py",
                "#!/usr/bin/env python3\nraise SystemExit(0)\n",
            )

            with patch.object(
                file_hook.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(cmd=["python3", "file-guard.py"], timeout=30),
            ):
                result = await file_hook.pre_read(
                    {"tool_input": {"file_path": "/tmp/project/.bra/.claude/tool-results/toolu_123.txt"}},
                    None,
                    {},
                )

        self.assertEqual(result.get("decision"), "block")
        self.assertEqual(result.get("policy"), "FILE_GUARD_TRANSPORT_ERROR")
        self.assertIn("timed out", result.get("reason", ""))

    def test_build_hooks_registers_read_grep_and_glob_guards(self) -> None:
        hooks = registry.build_hooks()
        matchers = hooks["PreToolUse"]
        names = [matcher.matcher for matcher in matchers]

        self.assertIn("Read", names)
        self.assertIn("Grep", names)
        self.assertIn("Glob", names)


if __name__ == "__main__":
    unittest.main()
