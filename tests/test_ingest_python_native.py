import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_INGEST = REPO_ROOT / "body" / "layer1" / "scripts" / "ingest.py"


class IngestPythonNativeTests(unittest.TestCase):
    def test_ingest_runs_without_shell_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            scripts_dir = body / "layer1" / "scripts"
            scripts_dir.mkdir(parents=True)

            # Copy only Python port (no ingest.sh)
            dst_ingest = scripts_dir / "ingest.py"
            shutil.copy2(SRC_INGEST, dst_ingest)

            layer2 = body / "layer2-templates"
            (layer2 / "methodologies").mkdir(parents=True)
            (layer2 / "attack-chains").mkdir(parents=True)
            (layer2 / "skillset.md").write_text("# Skillset\n")
            (layer2 / "toolset.md").write_text("# Toolset\n")
            (body / "layer3-engagement").mkdir(parents=True)

            pitch = root / "pitch.md"
            pitch.write_text(
                "\n".join(
                    [
                        "# Growth Proposals",
                        "**Engagement:** Acme External",
                        "**Status:** REVIEWED",
                        "",
                        "## 1. Methodology Improvements",
                        "- [x] **Method**: SSRF Mapping",
                        "",
                        "## 2. Attack Chain Patterns",
                        "- [x] **Chain**: [FINDING-101] SSRF to metadata",
                        "",
                        "## 3. Skill Additions",
                        "- [x] **Skill**: HTTP Desync",
                        "",
                        "## 4. Tool Additions",
                        "- [x] **Tool**: ffuf recursion",
                    ]
                )
            )

            result = subprocess.run(
                ["python3", str(dst_ingest), str(pitch)],
                cwd=str(body),
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            payload = json.loads(result.stdout.strip())
            self.assertEqual(payload.get("status"), "ok")

            moved_rel = payload.get("moved")
            self.assertIsInstance(moved_rel, str)
            moved_path = body / "layer3-engagement" / moved_rel
            self.assertTrue(moved_path.exists())
            self.assertIn("**Status:** INGESTED", moved_path.read_text())

            created = payload.get("created", [])
            self.assertTrue(any(item.startswith("methodologies/") for item in created))
            self.assertTrue((layer2 / "skillset.md").read_text().find("Pending Review") != -1)
            self.assertTrue((layer2 / "toolset.md").read_text().find("Pending Review") != -1)


if __name__ == "__main__":
    unittest.main()
