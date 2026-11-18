from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[1]
HTML = (REPO / "boots" / "static" / "index.html").read_text(encoding="utf-8")


class IntelLeadsLinkWiringTests(unittest.TestCase):
    def test_intel_and_leads_preload_artifacts_before_fetch(self) -> None:
        self.assertIn("async ensureArtifactsLoaded()", HTML)
        self.assertIn("async loadIntel() {\n                    await this.ensureArtifactsLoaded();", HTML)
        self.assertIn("async loadLeads() {\n                    await this.ensureArtifactsLoaded();", HTML)


if __name__ == "__main__":
    unittest.main()
