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


class RunnerResultDedupTests(unittest.IsolatedAsyncioTestCase):
    async def test_result_message_does_not_replay_streamed_assistant_text(self) -> None:
        response = "\n".join(
            [
                "## Scope Validated",
                "",
                "What would you like to do?",
                "",
                "1. Proceed",
                "2. Revise",
                "3. Ask a question",
                "4. Cancel engagement",
            ]
        )
        text_events: list[str] = []
        options_events: list[list[str]] = []
        turn_complete_count = 0

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)
            bra_state_dir.mkdir(parents=True, exist_ok=True)

            def on_turn_complete() -> None:
                nonlocal turn_complete_count
                turn_complete_count += 1

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_text=text_events.append,
                on_options=options_events.append,
                on_turn_complete=on_turn_complete,
            )

            assistant_message = type("AssistantMessage", (), {})()
            assistant_message.content = [SimpleNamespace(text=response)]

            result_message = type("ResultMessage", (), {})()
            result_message.result = response
            result_message.is_error = False

            with patch("bra.core.runner.write_debug_log"):
                await runner._process_message(assistant_message)
                await runner._process_message(result_message)

        self.assertEqual(
            text_events,
            [
                "## Scope Validated",
                "What would you like to do?",
                "1. Proceed",
                "2. Revise",
                "3. Ask a question",
                "4. Cancel engagement",
            ],
        )
        self.assertEqual(options_events, [["Proceed", "Revise", "Ask a question", "Cancel engagement"]])
        self.assertEqual(turn_complete_count, 1)

    async def test_result_message_fallback_replays_when_no_assistant_text_was_streamed(self) -> None:
        response = "\n".join(
            [
                "## Scope Validated",
                "",
                "What would you like to do?",
                "",
                "1. Proceed",
                "2. Revise",
                "3. Ask a question",
                "4. Cancel engagement",
            ]
        )
        text_events: list[str] = []
        options_events: list[list[str]] = []
        turn_complete_count = 0

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)
            bra_state_dir.mkdir(parents=True, exist_ok=True)

            def on_turn_complete() -> None:
                nonlocal turn_complete_count
                turn_complete_count += 1

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_text=text_events.append,
                on_options=options_events.append,
                on_turn_complete=on_turn_complete,
            )

            result_message = type("ResultMessage", (), {})()
            result_message.result = response
            result_message.is_error = False

            with patch("bra.core.runner.write_debug_log"):
                await runner._process_message(result_message)

        self.assertEqual(
            text_events,
            [
                "## Scope Validated",
                "What would you like to do?",
                "1. Proceed",
                "2. Revise",
                "3. Ask a question",
                "4. Cancel engagement",
            ],
        )
        self.assertEqual(options_events, [["Proceed", "Revise", "Ask a question", "Cancel engagement"]])
        self.assertEqual(turn_complete_count, 1)


if __name__ == "__main__":
    unittest.main()
