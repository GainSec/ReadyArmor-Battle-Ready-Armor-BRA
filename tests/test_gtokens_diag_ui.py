from __future__ import annotations

import unittest
from pathlib import Path


class GTokensDiagUiTests(unittest.TestCase):
    def test_debug_diag_contains_gtokens_section_and_controls(self) -> None:
        page = (Path(__file__).resolve().parents[1] / "boots" / "static" / "index.html").read_text(
            encoding="utf-8"
        )

        self.assertIn("GTokens", page)
        self.assertIn("toggleGToken", page)
        self.assertIn("createGeneratedGToken", page)
        self.assertIn("TOOL-APPROVAL changes may require a restart", page)
        self.assertIn("BRA_VERBOSE", page)

    def test_debug_diag_contains_token_usage_controls(self) -> None:
        root = Path(__file__).resolve().parents[1]
        page = (root / "boots" / "static" / "index.html").read_text(encoding="utf-8")
        tokens_file = (root / "body" / "layer1" / "lib" / "tokens.py").read_text(encoding="utf-8")

        self.assertIn("Token Usage", page)
        self.assertIn("NO-TOKEN-TRACKING", page)
        self.assertIn("loadTokenUsage", page)
        self.assertIn("diagSections.tokenUsage", page)
        self.assertIn("tokenUsageSummary", page)
        self.assertIn("/debug/token-usage", page)
        self.assertIn("formatUsd", page)
        self.assertNotIn("SDK tracking active", page)
        self.assertNotIn("No SDK token usage rows yet.", page)
        self.assertNotIn("disable SDK logging", page)
        self.assertIn('"NO-TOKEN-TRACKING"', tokens_file)

    def test_api_helper_uses_dedicated_auth_token_state(self) -> None:
        page = (Path(__file__).resolve().parents[1] / "boots" / "static" / "index.html").read_text(
            encoding="utf-8"
        )

        self.assertIn("authToken:", page)
        self.assertIn("const authToken = String(this.authToken || '').trim();", page)
        self.assertIn("headers['Authorization'] = `Bearer ${authToken}`;", page)


if __name__ == "__main__":
    unittest.main()
