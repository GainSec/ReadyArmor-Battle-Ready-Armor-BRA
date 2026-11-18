from __future__ import annotations

import asyncio
import importlib
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

boots_main = importlib.import_module("boots.main")
approval_mod = importlib.import_module("bra.core.approval")


class GTokensDiagApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project_root = Path(self.tmp.name)
        self.body_root = self.project_root / "body"
        (self.body_root / ".bra" / "approvals").mkdir(parents=True)
        (self.body_root / ".bra" / "one-time-approvals").mkdir(parents=True)

        self._orig_get_bra_dir = boots_main.get_bra_dir
        self._orig_auth_token = boots_main.AUTH_TOKEN
        self._orig_bra_dir = boots_main.BRA_DIR
        boots_main.get_bra_dir = lambda: str(self.project_root)
        boots_main.AUTH_TOKEN = ""
        boots_main.BRA_DIR = str(self.project_root)
        self.addCleanup(self._restore_main_state)

    def _restore_main_state(self) -> None:
        boots_main.get_bra_dir = self._orig_get_bra_dir
        boots_main.AUTH_TOKEN = self._orig_auth_token
        boots_main.BRA_DIR = self._orig_bra_dir

    def test_toggle_token_creates_and_removes_approval_file(self) -> None:
        token_file = self.body_root / ".bra" / "approvals" / "BRA_VERBOSE"

        activated = asyncio.run(boots_main.toggle_token("BRA_VERBOSE", True))
        self.assertEqual(activated["token"], "BRA_VERBOSE")
        self.assertTrue(activated["active"])
        self.assertTrue(token_file.exists())

        deactivated = asyncio.run(boots_main.toggle_token("BRA_VERBOSE", True))
        self.assertEqual(deactivated["token"], "BRA_VERBOSE")
        self.assertFalse(deactivated["active"])
        self.assertFalse(token_file.exists())

    def test_create_generated_scope_and_tool_tokens(self) -> None:
        create_scope = asyncio.run(
            boots_main.create_generated_token({"family": "scope_grant", "value": "api.example.com"}, True)
        )
        scope_token = self.body_root / ".bra" / "one-time-approvals" / "SCOPE-GRANT-api-example-com"
        self.assertEqual(create_scope["token"], "SCOPE-GRANT-api-example-com")
        self.assertTrue(scope_token.exists())

        create_tool = asyncio.run(
            boots_main.create_generated_token({"family": "tool", "value": "toolu_123abc"}, True)
        )
        tool_token = self.body_root / ".bra" / "one-time-approvals" / "TOOL-toolu_123abc"
        self.assertEqual(create_tool["token"], "TOOL-toolu_123abc")
        self.assertTrue(tool_token.exists())

    def test_create_script_token_uses_backend_hash_naming(self) -> None:
        script_path = "body/layer1/scripts/reset.py"

        created = asyncio.run(
            boots_main.create_generated_token({"family": "script", "value": script_path}, True)
        )

        expected_name = approval_mod._get_approval_token_name(script_path)
        expected_file = self.body_root / ".bra" / "approvals" / expected_name
        self.assertEqual(created["token"], expected_name)
        self.assertTrue(expected_file.exists())


if __name__ == "__main__":
    unittest.main()
