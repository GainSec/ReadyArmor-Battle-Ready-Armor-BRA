from __future__ import annotations

import asyncio
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

engage = importlib.import_module("boots.engage")
boots_main = importlib.import_module("boots.main")
from bra.core.approval import ApprovalType


class EngageAnonRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project_root = Path(self.tmp.name)
        self.body_root = self.project_root / "body"
        (self.body_root / ".bra" / "approvals").mkdir(parents=True)

    def _write_map(self, mappings: list[dict]) -> None:
        map_path = self.body_root / ".bra" / "anon_map.json"
        map_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "engagement": "test",
                    "created": "2026-03-06T00:00:00Z",
                    "mappings": mappings,
                }
            ),
            encoding="utf-8",
        )

    def test_mask_user_input_masks_existing_mapping(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"}]
        )

        with patch("bra.config.settings.get_bra_root", return_value=self.project_root):
            result = engage._mask_user_input("Connect to 10.0.0.1 now")

        self.assertIn("FALCON", result)
        self.assertNotIn("10.0.0.1", result)

    def test_mask_user_input_noops_when_anon_disable_is_active(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"}]
        )
        (self.body_root / ".bra" / "approvals" / "ANON-DISABLE").touch()

        with patch("bra.config.settings.get_bra_root", return_value=self.project_root):
            result = engage._mask_user_input("Connect to 10.0.0.1 now")

        self.assertEqual(result, "Connect to 10.0.0.1 now")

    def test_unmask_output_restores_real_value(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"}]
        )

        with patch("bra.config.settings.get_bra_root", return_value=self.project_root):
            result = engage._unmask_output("Connect to FALCON now")

        self.assertEqual(result, "Connect to 10.0.0.1 now")

    def test_broadcast_unmasks_operator_visible_fields(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"}]
        )

        manager = engage.EngageManager()
        with patch("bra.config.settings.get_bra_root", return_value=self.project_root):
            asyncio.run(manager.broadcast({"type": "text", "content": "Host FALCON"}))

        self.assertEqual(manager.history[-1]["content"], "Host 10.0.0.1")

    def test_tool_approval_event_carries_masked_hover_rehydration_metadata(self) -> None:
        self._write_map(
            [{"real": "192.168.18.9", "anon": "olive", "type": "ip", "source": "scope"}]
        )
        manager = engage.EngageManager()
        blocked = SimpleNamespace(
            approval_type=ApprovalType.TOOL,
            command="wget http://olive:80/",
            reason="Tool 'Bash' requires approval",
            tool_name="Bash",
            tool_input={"command": "wget http://olive:80/"},
            tool_use_id="toolu_test",
        )

        with patch("bra.config.settings.get_bra_root", return_value=self.project_root):
            event = manager._build_approval_event(blocked)

        self.assertEqual(event["command"], "wget http://olive:80/")
        self.assertEqual(event["tool_input"]["command"], "wget http://olive:80/")
        self.assertNotIn("192.168.18.9", event["command"])
        self.assertEqual(
            event["approval_anon_highlights"],
            [{"anon": "olive", "real": "192.168.18.9", "type": "ip"}],
        )

    def test_engage_runtime_has_explicit_scope_token_guards(self) -> None:
        source = (REPO_ROOT / "boots" / "engage.py").read_text(encoding="utf-8")

        self.assertIn('scope_token == "LOCAL-SCOPE"', source)
        self.assertIn('scope_token == "MICRO-SCOPE"', source)
        self.assertIn('raw_scope = scope_token in {"FRONTIER-SCOPE", "NO-SCOPE"}', source)
        self.assertIn("Local Mask is not available yet", source)
        self.assertIn("requires boots to be started with --ner", source)

    def test_main_runtime_has_detection_mode_branching_for_scope_review(self) -> None:
        source = (REPO_ROOT / "boots" / "main.py").read_text(encoding="utf-8")

        self.assertIn('mode == "regex-only"', source)
        self.assertIn('mode == "regex-plus-local"', source)
        self.assertIn("_NER_ENABLED", source)

    def test_claude_runtime_guides_agents_to_use_masked_scope_targets_in_commands(self) -> None:
        source = (REPO_ROOT / "body" / "CLAUDE.md").read_text(encoding="utf-8")

        self.assertIn("Treat anonymized target values already present in governed scope as valid command placeholders.", source)
        self.assertIn("Propose commands using the anonymized target value from scope instead of replacing it with placeholders like `<target-ip>`.", source)
        self.assertIn("Do not ask the operator for the actual IP or hostname solely because the governed target value is anonymized.", source)

    def test_wizard_submit_leaves_scope_raw_for_no_scope(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"}]
        )
        (self.body_root / ".bra" / "approvals" / "NO-SCOPE").touch()
        manager = engage.EngageManager()
        scope = {
            "target_name": "Android Auto Dongle",
            "authorization": True,
            "targets": "10.0.0.1",
            "in_scope": "HTTP service",
            "out_scope": "",
            "notes": "",
        }

        with patch.object(engage, "_wizard_launch_agent", new=AsyncMock(return_value=None)):
            asyncio.run(engage._wizard_submit(manager, str(self.project_root), dict(scope), {}))

        scope_file = engage._body_root(self.project_root) / "layer3-engagement" / "SCOPE.md"
        written = scope_file.read_text(encoding="utf-8")

        self.assertIn("10.0.0.1", written)
        self.assertNotIn("FALCON", written)

    def test_wizard_submit_preserves_selected_scope_and_chat_tokens(self) -> None:
        approvals_dir = self.body_root / ".bra" / "approvals"
        (approvals_dir / "DUMB-SCOPE").touch()
        (approvals_dir / "ANON-SCAN").touch()
        manager = engage.EngageManager()
        scope = {
            "target_name": "Android Auto Dongle",
            "authorization": True,
            "targets": "10.0.0.1",
            "in_scope": "HTTP service",
            "out_scope": "",
            "notes": "",
        }
        stale_tokens = {
            "DUMB-SCOPE": False,
            "ANON-SCAN": False,
            "MAP-SCAN": False,
            "NO-SCOPE": False,
        }

        with patch.object(engage, "_wizard_launch_agent", new=AsyncMock(return_value=None)):
            asyncio.run(engage._wizard_submit(manager, str(self.project_root), dict(scope), dict(stale_tokens)))

        self.assertTrue((approvals_dir / "DUMB-SCOPE").exists())
        self.assertTrue((approvals_dir / "ANON-SCAN").exists())


class EngageAnonScanRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project_root = Path(self.tmp.name)
        self.body_root = self.project_root / "body"
        (self.body_root / ".bra" / "approvals").mkdir(parents=True)

    def _write_map(self, mappings: list[dict]) -> None:
        map_path = self.body_root / ".bra" / "anon_map.json"
        map_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "engagement": "test",
                    "created": "2026-03-06T00:00:00Z",
                    "mappings": mappings,
                }
            ),
            encoding="utf-8",
        )

    def _make_runner(self) -> SimpleNamespace:
        return SimpleNamespace(
            awaiting_input=True,
            continue_with_input=AsyncMock(),
            session_id=None,
        )

    async def test_continue_with_message_blocks_local_scan_until_supported(self) -> None:
        (self.body_root / ".bra" / "approvals" / "LOCAL-SCAN").touch()
        manager = engage.EngageManager()
        manager.runner = self._make_runner()
        manager._cancel_lingering_agent_task = AsyncMock(return_value=None)
        manager._terminate_all_agent_subprocesses = AsyncMock(return_value=[])

        with patch("bra.config.settings.get_bra_root", return_value=self.project_root):
            await manager.continue_with_message("Target 10.0.0.1 is reachable")

        self.assertTrue(any(evt.get("type") == "error" for evt in manager.history))
        self.assertTrue(
            any("Local Mask is not available yet" in evt.get("message", "") for evt in manager.history)
        )
        manager.runner.continue_with_input.assert_not_called()

    async def test_continue_with_message_requires_anon_scan_approval_before_send(self) -> None:
        (self.body_root / ".bra" / "approvals" / "ANON-SCAN").touch()
        manager = engage.EngageManager()
        manager.runner = self._make_runner()
        manager._cancel_lingering_agent_task = AsyncMock(return_value=None)
        manager._terminate_all_agent_subprocesses = AsyncMock(return_value=[])

        with patch("bra.config.settings.get_bra_root", return_value=self.project_root):
            await manager.continue_with_message("Target 10.0.0.1 is reachable")

        self.assertIsNotNone(manager.get_state().get("pending_approval"))
        self.assertEqual(manager.get_state()["pending_approval"]["type"], "approval_anon_map")
        manager.runner.continue_with_input.assert_not_called()

    async def test_anon_scan_mask_decision_persists_and_resumes_masked(self) -> None:
        (self.body_root / ".bra" / "approvals" / "ANON-SCAN").touch()
        manager = engage.EngageManager()
        manager.runner = self._make_runner()
        manager._cancel_lingering_agent_task = AsyncMock(return_value=None)
        manager._terminate_all_agent_subprocesses = AsyncMock(return_value=[])

        with patch("bra.config.settings.get_bra_root", return_value=self.project_root):
            await manager.continue_with_message("Target 10.0.0.1 is reachable")
            await manager.resolve_approval({"decision": "mask"})
            await asyncio.sleep(0)

        manager.runner.continue_with_input.assert_awaited_once()
        sent = manager.runner.continue_with_input.await_args.args[0]
        self.assertNotIn("10.0.0.1", sent)
        self.assertTrue((self.body_root / ".bra" / "anon_map.json").exists())
        history = boots_main.load_override_history(self.body_root)
        self.assertTrue(any(entry["type"] == "ANON_MAP" and entry["decision"] == "MASK" for entry in history))

    async def test_anon_scan_deny_decision_resumes_without_persisting(self) -> None:
        (self.body_root / ".bra" / "approvals" / "ANON-SCAN").touch()
        manager = engage.EngageManager()
        manager.runner = self._make_runner()
        manager._cancel_lingering_agent_task = AsyncMock(return_value=None)
        manager._terminate_all_agent_subprocesses = AsyncMock(return_value=[])

        with patch("bra.config.settings.get_bra_root", return_value=self.project_root):
            await manager.continue_with_message("Target 10.0.0.1 is reachable")
            await manager.resolve_approval({"decision": "deny"})
            await asyncio.sleep(0)

        manager.runner.continue_with_input.assert_awaited_once()
        sent = manager.runner.continue_with_input.await_args.args[0]
        self.assertIn("10.0.0.1", sent)
        map_path = self.body_root / ".bra" / "anon_map.json"
        self.assertFalse(map_path.exists())


if __name__ == "__main__":
    unittest.main()
