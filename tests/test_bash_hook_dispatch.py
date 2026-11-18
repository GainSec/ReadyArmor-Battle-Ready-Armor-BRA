from __future__ import annotations

import asyncio
import os
import tempfile
import textwrap
import unittest
from pathlib import Path

from bra.config import settings as settings_module
from bra.hooks.bash_hook import pre_bash
from bra.hooks.tool_approval_hook import check_tool_approval_hook, grant_tool_approval


class BashHookDispatchTests(unittest.TestCase):
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

    def test_python_guard_allows(self) -> None:
        td, _, hooks = self._make_root()
        with td:
            self._write_exec(
                hooks / "bash-guard.py",
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import sys
                    _ = sys.stdin.read()
                    raise SystemExit(0)
                    """
                ).strip()
                + "\n",
            )

            out = asyncio.run(pre_bash({"tool_input": {"command": "echo hi"}}, None, {}))
            self.assertEqual(out, {})

    def test_python_guard_blocks(self) -> None:
        td, _, hooks = self._make_root()
        with td:
            self._write_exec(
                hooks / "bash-guard.py",
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import sys
                    _ = sys.stdin.read()
                    print("BLOCKED", file=sys.stderr)
                    raise SystemExit(2)
                    """
                ).strip()
                + "\n",
            )

            out = asyncio.run(pre_bash({"tool_input": {"command": "echo hi"}}, None, {}))
            self.assertEqual(out.get("decision"), "block")
            self.assertIn("BLOCKED", out.get("reason", ""))

    def test_missing_guard_allows(self) -> None:
        """When bash-guard.py is missing, commands are allowed."""
        td, _, hooks = self._make_root()
        with td:
            out = asyncio.run(pre_bash({"tool_input": {"command": "echo hi"}}, None, {}))
            self.assertEqual(out, {})

    def test_unapproved_bash_blocks_before_guard_executes(self) -> None:
        td, root, hooks = self._make_root()
        with td:
            marker = root / "guard-ran.txt"
            self._write_exec(
                hooks / "bash-guard.py",
                textwrap.dedent(
                    f"""
                    #!/usr/bin/env python3
                    from pathlib import Path
                    import sys
                    _ = sys.stdin.read()
                    Path({str(marker)!r}).write_text("ran", encoding="utf-8")
                    raise SystemExit(0)
                    """
                ).strip()
                + "\n",
            )

            out = asyncio.run(
                pre_bash(
                    {"tool_input": {"command": "nmap -sV 192.168.18.9"}},
                    "toolu_pending_approval",
                    {},
                )
            )
            self.assertEqual(out.get("decision"), "block")
            self.assertIn("TOOL_APPROVAL_REQUIRED", out.get("reason", ""))
            self.assertFalse(marker.exists(), "bash-guard.py should not run before tool approval")

    def test_recently_approved_bash_reaches_guard(self) -> None:
        td, root, hooks = self._make_root()
        with td:
            marker = root / "guard-ran.txt"
            self._write_exec(
                hooks / "bash-guard.py",
                textwrap.dedent(
                    f"""
                    #!/usr/bin/env python3
                    from pathlib import Path
                    import sys
                    _ = sys.stdin.read()
                    Path({str(marker)!r}).write_text("ran", encoding="utf-8")
                    raise SystemExit(0)
                    """
                ).strip()
                + "\n",
            )

            hook_input = {"tool_name": "Bash", "tool_input": {"command": "nmap -sV 192.168.18.9"}}
            grant_tool_approval("toolu_recently_approved", "Bash")
            out = asyncio.run(
                check_tool_approval_hook(
                    hook_input,
                    "toolu_recently_approved",
                    {},
                )
            )
            self.assertEqual(out, {})

            out = asyncio.run(
                pre_bash(
                    {"tool_input": {"command": "nmap -sV 192.168.18.9"}},
                    "toolu_recently_approved",
                    {},
                )
            )
            self.assertEqual(out, {})
            self.assertTrue(marker.exists(), "bash-guard.py should run after approval is consumed")


if __name__ == "__main__":
    unittest.main()
