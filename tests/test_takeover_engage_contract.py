from __future__ import annotations

import asyncio
import sys
import unittest


REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from boots.takeover import TakeoverController


class TakeoverEngageContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_on_engage_event_ignores_takeover_status_events(self) -> None:
        controller = TakeoverController()
        controller.enable_takeover()

        result = await controller.on_engage_event({"type": "takeover_status", "active": True})

        self.assertEqual(result, {"action": "none", "reason": "ignored_event"})

    async def test_dispatch_action_maps_select_with_message(self) -> None:
        controller = TakeoverController()
        dispatched: list[dict] = []

        async def dispatch_fn(msg: dict) -> None:
            dispatched.append(msg)

        ok = await controller.dispatch_action_to_engage(
            {"action": "select", "option": 2, "message": "Continue carefully."},
            dispatch_fn=dispatch_fn,
            notify_fn=None,
        )

        self.assertTrue(ok)
        self.assertEqual(
            dispatched,
            [
                {
                    "type": "select_with_message",
                    "option": 2,
                    "message": "Continue carefully.",
                    "suppress_chat_echo": True,
                }
            ],
        )

    def test_scope_mutation_approval_is_forced_to_deny_during_takeover(self) -> None:
        controller = TakeoverController()
        controller.enable_takeover()

        msg, override_event = controller._map_action_to_route_message(
            {
                "action": "approve",
                "approval_type": "scope_add",
                "decision": "grant_session",
                "scope_level": "FULL",
            }
        )

        self.assertEqual(
            msg,
            {
                "type": "approve_scope_add",
                "decision": "deny",
                "suppress_chat_echo": True,
                "scope_level": "FULL",
            },
        )
        self.assertIsNotNone(override_event)
        self.assertEqual(override_event["policy"], "force_deny_scope_mutation")
        self.assertEqual(override_event["requested_decision"], "grant_session")
        self.assertEqual(override_event["enforced_decision"], "deny")


if __name__ == "__main__":
    unittest.main()
