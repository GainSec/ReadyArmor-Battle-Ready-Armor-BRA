from __future__ import annotations

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

from bra.core.runner import AgentRunner


class RunnerOptionLabelCleanupTests(unittest.TestCase):
    def test_parse_options_strips_markdown_emphasis_from_labels(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)
            bra_state_dir.mkdir(parents=True, exist_ok=True)

            seen_options: list[list[str]] = []
            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_options=lambda opts: seen_options.append(opts[:]),
            )

            runner._parse_options(
                [
                    "What would you like to do?",
                    "1. **Confirm scope and proceed**.",
                    "2. **Revise scope**.",
                    "3. **Ask a clarifying question**.",
                    "4. **Cancel engagement**.",
                ]
            )

        self.assertEqual(
            seen_options,
            [[
                "Confirm scope and proceed.",
                "Revise scope.",
                "Ask a clarifying question.",
                "Cancel engagement.",
            ]],
        )

    def test_parse_options_strips_markup_but_keeps_first_four_real_choices(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)
            bra_state_dir.mkdir(parents=True, exist_ok=True)

            seen_options: list[list[str]] = []
            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_options=lambda opts: seen_options.append(opts[:]),
            )

            runner._parse_options(
                [
                    "What would you like to do?",
                    "1. **Confirm scope and proceed**.",
                    "2. `Revise scope`.",
                    "3. __Ask a clarifying question__.",
                    "4. **Cancel engagement**.",
                    "5. **Something else**.",
                ]
            )

        self.assertEqual(
            seen_options,
            [[
                "Confirm scope and proceed.",
                "Revise scope.",
                "Ask a clarifying question.",
                "Cancel engagement.",
            ]],
        )


if __name__ == "__main__":
    unittest.main()
