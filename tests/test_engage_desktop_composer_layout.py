from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class EngageDesktopComposerLayoutTests(unittest.TestCase):
    def test_desktop_engage_composer_is_scoped_and_right_aligned(self) -> None:
        text = (REPO_ROOT / "boots" / "static" / "index.html").read_text(encoding="utf-8")

        self.assertIn('class="engage-options engage-options-desktop-composer"', text)
        self.assertIn(".engage-options.engage-options-desktop-composer", text)
        self.assertIn(".engage-options.engage-options-desktop-composer .engage-options-bar", text)
        self.assertIn("width: 40%;", text)
        self.assertIn(".engage-options.engage-options-desktop-composer .engage-options-bar button", text)


if __name__ == "__main__":
    unittest.main()
