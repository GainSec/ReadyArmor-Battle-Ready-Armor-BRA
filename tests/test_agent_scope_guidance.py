from __future__ import annotations

import re
import unittest
from pathlib import Path


class AgentScopeGuidanceTests(unittest.TestCase):
    def test_agents_attempt_requested_out_of_scope_action_to_trigger_scope_modal(self) -> None:
        prompt = (Path(__file__).resolve().parents[1] / "body" / "CLAUDE.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("Attempt the requested action normally", prompt)
        self.assertIn("BRA will show the operator scope modal", prompt)
        self.assertIn("Do not run `approve-target.py`", prompt)

        section = re.search(
            r"### Handling SCOPE_CHECK_REQUIRED(?P<body>.*?)(?:\n### |\Z)",
            prompt,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(section)
        self.assertNotIn("./layer1/scripts/approve-target.py '<target>'", section.group("body"))


if __name__ == "__main__":
    unittest.main()
