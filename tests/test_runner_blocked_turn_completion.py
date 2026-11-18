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


class RunnerBlockedTurnCompletionTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _assistant_message(text: str):
        block = SimpleNamespace(text=text)
        message = type("AssistantMessage", (), {})()
        message.content = [block]
        return message

    @staticmethod
    def _tool_use_message(name: str, tool_input: dict[str, object], *, tool_use_id: str = ""):
        message = type("LegacyMessage", (), {})()
        message.type = "tool_use"
        message.name = name
        message.input = tool_input
        message.id = tool_use_id
        message.tool_use_id = tool_use_id
        return message

    @staticmethod
    def _tool_result_message(content: str):
        message = type("LegacyMessage", (), {})()
        message.type = "tool_result"
        message.content = content
        return message

    async def test_blocked_tool_turn_should_not_emit_fallback_options_while_approval_pending(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)
            bra_state_dir.mkdir(parents=True, exist_ok=True)

            blocked_events = []
            seen_options: list[list[str]] = []
            turn_complete_count = 0

            async def on_blocked_operation(blocked) -> bool:
                blocked_events.append(blocked)
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

            blocked_output = "\n".join(
                [
                    "TOOL_APPROVAL_REQUIRED",
                    "TOOL_NAME=Bash",
                    "TOOL_USE_ID=toolu_123",
                    "Command: nmap -sV 192.168.18.9",
                    "Reason: Tool 'Bash' requires approval",
                ]
            )

            async def fake_run_agent(_prompt, **_kwargs):
                yield self._tool_use_message(
                    "Bash",
                    {"command": "nmap -sV 192.168.18.9"},
                    tool_use_id="toolu_123",
                )
                yield self._tool_result_message(blocked_output)

            with (
                patch("bra.core.runner.get_anthropic_api_key", return_value="test-key"),
                patch("bra.core.agent.run_agent", new=fake_run_agent),
                patch("bra.core.runner.write_debug_log"),
            ):
                await runner.run("scan target")

        self.assertEqual(len(blocked_events), 1)
        self.assertEqual(seen_options, [])
        self.assertEqual(turn_complete_count, 0)

    async def test_blocked_tool_turn_should_not_emit_generic_turn_complete_summary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)
            bra_state_dir.mkdir(parents=True, exist_ok=True)

            seen_text: list[str] = []

            async def on_blocked_operation(_blocked) -> bool:
                return False

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_blocked_operation=on_blocked_operation,
                on_text=seen_text.append,
            )

            blocked_output = "\n".join(
                [
                    "TOOL_APPROVAL_REQUIRED",
                    "TOOL_NAME=Bash",
                    "TOOL_USE_ID=toolu_123",
                    "Command: nmap -sV 192.168.18.9",
                    "Reason: Tool 'Bash' requires approval",
                ]
            )

            async def fake_run_agent(_prompt, **_kwargs):
                yield self._tool_use_message(
                    "Bash",
                    {"command": "nmap -sV 192.168.18.9"},
                    tool_use_id="toolu_123",
                )
                yield self._tool_result_message(blocked_output)

            with (
                patch("bra.core.runner.get_anthropic_api_key", return_value="test-key"),
                patch("bra.core.agent.run_agent", new=fake_run_agent),
                patch("bra.core.runner.write_debug_log"),
            ):
                await runner.run("scan target")

        rendered = "\n".join(seen_text)
        self.assertNotIn("Turn complete", rendered)
        self.assertNotIn("tools executed", rendered)

    async def test_approved_blocked_tool_turn_should_not_emit_fallback_completion_before_retry_runs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)
            bra_state_dir.mkdir(parents=True, exist_ok=True)

            seen_text: list[str] = []
            seen_options: list[list[str]] = []
            turn_complete_count = 0

            async def on_blocked_operation(_blocked) -> bool:
                return True

            def on_turn_complete() -> None:
                nonlocal turn_complete_count
                turn_complete_count += 1

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_blocked_operation=on_blocked_operation,
                on_text=seen_text.append,
                on_options=lambda opts: seen_options.append(opts[:]),
                on_turn_complete=on_turn_complete,
            )

            blocked_output = "\n".join(
                [
                    "TOOL_APPROVAL_REQUIRED",
                    "TOOL_NAME=Bash",
                    "TOOL_USE_ID=toolu_123",
                    "Command: nmap -sV 192.168.18.9",
                    "Reason: Tool 'Bash' requires approval",
                ]
            )

            async def fake_run_agent(_prompt, **_kwargs):
                yield self._tool_use_message(
                    "Bash",
                    {"command": "nmap -sV 192.168.18.9"},
                    tool_use_id="toolu_123",
                )
                yield self._tool_result_message(blocked_output)

            with (
                patch("bra.core.runner.get_anthropic_api_key", return_value="test-key"),
                patch("bra.core.agent.run_agent", new=fake_run_agent),
                patch("bra.core.runner.write_debug_log"),
            ):
                await runner.run("scan target")

        rendered = "\n".join(seen_text)
        self.assertEqual(seen_options, [])
        self.assertEqual(turn_complete_count, 0)
        self.assertNotIn("Turn complete", rendered)

    async def test_manual_retry_replaces_blocked_run_and_ignores_late_stale_text(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)
            bra_state_dir.mkdir(parents=True, exist_ok=True)

            seen_text: list[str] = []
            seen_options: list[list[str]] = []
            turn_complete_count = 0

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_text=seen_text.append,
                on_options=lambda opts: seen_options.append(opts[:]),
                on_turn_complete=lambda: seen_text.append("[TURN_COMPLETE]"),
            )
            runner._session_id = "session-123"

            async def on_blocked_operation(blocked) -> bool:
                await runner.retry_blocked_operation(blocked)
                return True

            runner.on_blocked_operation = on_blocked_operation

            blocked_output = "\n".join(
                [
                    "TOOL_APPROVAL_REQUIRED",
                    "TOOL_NAME=Bash",
                    "TOOL_USE_ID=toolu_123",
                    "Command: nmap -sV 192.168.18.9",
                    "Reason: Tool 'Bash' requires approval",
                ]
            )
            stale_text = (
                "The governance hook is requiring you to approve this command in the "
                "**approval prompt** (TUI) before it can run."
            )
            retry_result = "\n".join(
                [
                    "Web port scan complete.",
                    "What would you like to do?",
                    "1. Fetch the root page (/)",
                    "2. Run a directory/path brute-force against port 80",
                    "3. Check lighttpd 1.4.76 for known CVEs",
                    "4. Do all of the above in sequence",
                ]
            )

            async def fake_run_agent(prompt, **_kwargs):
                if prompt == "scan target":
                    yield self._tool_use_message(
                        "Bash",
                        {"command": "nmap -sV 192.168.18.9"},
                        tool_use_id="toolu_123",
                    )
                    yield self._tool_result_message(blocked_output)
                    yield self._assistant_message(stale_text)
                else:
                    yield self._assistant_message(retry_result)

            with (
                patch("bra.core.runner.get_anthropic_api_key", return_value="test-key"),
                patch("bra.core.agent.run_agent", new=fake_run_agent),
                patch("bra.core.runner.write_debug_log"),
            ):
                await runner.run("scan target")

        rendered = "\n".join(seen_text)
        self.assertIn("Web port scan complete.", rendered)
        self.assertNotIn("approval prompt", rendered)
        self.assertEqual(
            seen_options,
            [[
                "Fetch the root page (/)",
                "Run a directory/path brute-force against port 80",
                "Check lighttpd 1.4.76 for known CVEs",
                "Do all of the above in sequence",
            ]],
        )
        self.assertEqual(rendered.count("[TURN_COMPLETE]"), 1)


if __name__ == "__main__":
    unittest.main()
