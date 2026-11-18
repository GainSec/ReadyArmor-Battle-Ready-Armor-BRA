from __future__ import annotations

import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock


REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from boots import engage
from bra.core.approval import ApprovalType, BlockedOperation


class EngageToolApprovalRetryFlowTests(unittest.IsolatedAsyncioTestCase):
    def _make_manager(self) -> engage.EngageManager:
        mgr = engage.EngageManager()
        mgr.runner = SimpleNamespace(
            handle_approval_result=AsyncMock(return_value=True),
            retry_blocked_operation=AsyncMock(),
            continue_with_input=AsyncMock(),
        )
        mgr._overrides = None
        mgr._prior_approvals = {}
        mgr._record_override_decision = lambda *args, **kwargs: None
        mgr._terminate_all_agent_subprocesses = AsyncMock(return_value=[])
        return mgr

    async def test_token_approval_resolution_still_calls_manual_retry(self) -> None:
        mgr = self._make_manager()
        blocked = BlockedOperation(
            approval_type=ApprovalType.TOKEN,
            token_name="ACTIVE-TESTING-APPROVAL",
            command="nmap -sV 192.168.18.9",
            reason="ACTIVE_TESTING_APPROVAL",
        )

        await mgr._process_approval_result(blocked, {"decision": "grant_session"})

        mgr.runner.handle_approval_result.assert_awaited_once_with(
            blocked, True, scope_level=None, one_time=False
        )
        mgr.runner.retry_blocked_operation.assert_awaited_once_with(blocked)

    async def test_tool_approval_resolution_still_calls_manual_retry_after_grant(self) -> None:
        mgr = self._make_manager()
        blocked = BlockedOperation(
            approval_type=ApprovalType.TOOL,
            tool_name="Bash",
            tool_input={"command": "nmap -sV 192.168.18.9"},
            command="nmap -sV 192.168.18.9",
            reason="TOOL_APPROVAL_REQUIRED",
        )

        await mgr._process_approval_result(blocked, {"decision": "allow_override"})

        mgr.runner.handle_approval_result.assert_awaited_once_with(
            blocked, True, scope_level=None, one_time=False
        )
        mgr.runner.retry_blocked_operation.assert_awaited_once_with(blocked)

    async def test_scope_add_resolution_notifies_agent_without_retrying_approve_target(self) -> None:
        mgr = self._make_manager()
        blocked = BlockedOperation(
            approval_type=ApprovalType.SCOPE_ADD,
            target="192.168.18.9",
            target_type="network",
            command="./layer1/scripts/approve-target.py '192.168.18.9' FULL 'ARP cache confirmed'",
            reason="Target '192.168.18.9' is not in approved scope",
        )

        await mgr._process_approval_result(blocked, {"decision": "full", "scope_level": "FULL"})

        mgr.runner.handle_approval_result.assert_awaited_once_with(
            blocked, True, scope_level="FULL", one_time=False
        )
        mgr.runner.retry_blocked_operation.assert_not_awaited()
        mgr.runner.continue_with_input.assert_awaited_once()
        resumed_message = mgr.runner.continue_with_input.await_args.args[0]
        self.assertIn("192.168.18.9", resumed_message)
        self.assertIn("FULL", resumed_message)
        self.assertIn("Do not rerun approve-target.py", resumed_message)


if __name__ == "__main__":
    unittest.main()
