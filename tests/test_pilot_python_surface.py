from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class PilotPythonSurfaceTests(unittest.TestCase):
    def test_bridge_docstring_no_longer_advertises_legacy_shell_names(self) -> None:
        bridge_text = (REPO_ROOT / "head" / "bra" / "core" / "bridge.py").read_text()
        self.assertNotIn("legacy ``foo.sh``", bridge_text)
        self.assertNotIn("status.py\" or legacy \"status.sh", bridge_text)

    def test_cli_fallback_messages_use_python_names(self) -> None:
        cli_text = (REPO_ROOT / "head" / "bra" / "cli.py").read_text()
        self.assertIn("precheck.py not available", cli_text)
        self.assertIn("scope-intake.py not available", cli_text)
        self.assertNotIn("precheck.sh not available", cli_text)
        self.assertNotIn("scope-intake.sh not available", cli_text)

    def test_handoff_harness_error_uses_python_name(self) -> None:
        harness_text = (REPO_ROOT / "boots" / "harness" / "engagement_handoff.py").read_text()
        self.assertIn("agentic-handler.py failed", harness_text)
        self.assertNotIn("agentic-handler.sh failed", harness_text)


if __name__ == "__main__":
    unittest.main()
