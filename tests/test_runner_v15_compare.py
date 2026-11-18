from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bra.core.runner import AgentRunner


class RunnerV15CompareTests(unittest.TestCase):
    def test_parse_and_dispatch_text_preserves_service_endpoint_lead_marker_callbacks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)
            bra_state_dir.mkdir(parents=True, exist_ok=True)

            seen_services: list[tuple[str, str, str, str, str]] = []
            seen_endpoints: list[tuple[str, str, str, str, str, str]] = []
            seen_leads: list[str] = []
            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_service=lambda *args: seen_services.append(args),
                on_endpoint=lambda *args: seen_endpoints.append(args),
                on_lead=seen_leads.append,
            )

            runner._parse_and_dispatch_text(
                "\n".join(
                    [
                        "[SERVICE] 443/tcp | open | HTTPS | nginx/1.24 | source: nmap scan",
                        "[ENDPOINT] /login | GET | Authentication | source: index.html",
                        "[LEAD] Check default credentials | priority: High | rationale: Login page exposed",
                    ]
                )
            )

        self.assertEqual(seen_services, [("443/tcp", "open", "HTTPS", "nginx/1.24", "nmap scan")])
        self.assertEqual(
            seen_endpoints,
            [("/login", "GET", "Authentication", "Unknown", "Untested", "index.html")]
        )
        self.assertEqual(seen_leads, ["Check default credentials"])

    def test_option_line_limiting_does_not_drop_real_operator_choice_four(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)
            bra_state_dir.mkdir(parents=True, exist_ok=True)

            seen_text: list[str] = []
            seen_options: list[list[str]] = []
            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_text=seen_text.append,
                on_options=lambda opts: seen_options.append(opts[:]),
            )

            runner._parse_and_dispatch_text(
                "\n".join(
                    [
                        "What would you like to do?",
                        "1. Confirm scope and proceed.",
                        "2. Revise scope.",
                        "3. Ask a clarifying question.",
                        "4. Cancel engagement.",
                    ]
                )
            )

        rendered = "\n".join(seen_text)
        self.assertIn("1. Confirm scope and proceed.", rendered)
        self.assertIn("4. Cancel engagement.", rendered)
        self.assertEqual(
            seen_options,
            [[
                "Confirm scope and proceed.",
                "Revise scope.",
                "Ask a clarifying question.",
                "Cancel engagement.",
            ]],
        )


class RunnerV15ApprovalHydrationCompareTests(unittest.IsolatedAsyncioTestCase):
    async def test_valid_hook_denial_still_rehydrates_real_tool_input(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)
            bra_state_dir.mkdir(parents=True, exist_ok=True)

            seen_blocked = []

            async def on_blocked_operation(blocked) -> bool:
                seen_blocked.append(blocked)
                return False

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_blocked_operation=on_blocked_operation,
            )

            full_tool_input = {
                "file_path": "/tmp/target.txt",
                "offset": 12,
                "limit": 34,
            }
            runner._handle_tool_use("Read", full_tool_input, tool_use_id="toolu_123")

            user_message = type("UserMessage", (), {})()
            user_message.content = [
                SimpleNamespace(
                    is_error=True,
                    content="Hook PreToolUse:Read denied this tool",
                    tool_use_id="toolu_123",
                )
            ]

            with patch("bra.core.runner.write_debug_log"):
                await runner._process_message(user_message)

        self.assertEqual(len(seen_blocked), 1)
        blocked = seen_blocked[0]
        self.assertEqual(blocked.tool_name, "Read")
        self.assertEqual(blocked.tool_use_id, "toolu_123")
        self.assertEqual(blocked.command, "/tmp/target.txt")
        self.assertEqual(blocked.tool_input, full_tool_input)

    async def test_blocked_tool_approval_turn_should_not_finish_like_normal_operator_turn(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)
            bra_state_dir.mkdir(parents=True, exist_ok=True)

            seen_options: list[list[str]] = []
            turn_complete_count = 0

            async def on_blocked_operation(_blocked) -> bool:
                return False

            def on_turn_complete() -> None:
                nonlocal turn_complete_count
                turn_complete_count += 1

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_blocked_operation=on_blocked_operation,
                on_options=lambda opts: seen_options.append(opts[:]),
                on_turn_complete=on_turn_complete,
            )

            tool_use_message = type("LegacyMessage", (), {})()
            tool_use_message.type = "tool_use"
            tool_use_message.name = "Bash"
            tool_use_message.input = {"command": "nmap -sV 192.168.18.9"}
            tool_use_message.id = "toolu_123"
            tool_use_message.tool_use_id = "toolu_123"

            tool_result_message = type("LegacyMessage", (), {})()
            tool_result_message.type = "tool_result"
            tool_result_message.content = "\n".join(
                [
                    "TOOL_APPROVAL_REQUIRED",
                    "TOOL_NAME=Bash",
                    "TOOL_USE_ID=toolu_123",
                    "Command: nmap -sV 192.168.18.9",
                    "Reason: Tool 'Bash' requires approval",
                ]
            )

            async def fake_run_agent(_prompt, **_kwargs):
                yield tool_use_message
                yield tool_result_message

            with (
                patch("bra.core.runner.get_anthropic_api_key", return_value="test-key"),
                patch("bra.core.agent.run_agent", new=fake_run_agent),
                patch("bra.core.runner.write_debug_log"),
            ):
                await runner.run("scan target")

        self.assertEqual(seen_options, [])
        self.assertEqual(turn_complete_count, 0)


if __name__ == "__main__":
    unittest.main()
