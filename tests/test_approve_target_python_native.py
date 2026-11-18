import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_APPROVE = REPO_ROOT / "body" / "layer1" / "scripts" / "approve-target.py"


class ApproveTargetPythonNativeTests(unittest.TestCase):
    def test_add_target_without_shell_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            body = root / "body"
            scripts_dir = body / "layer1" / "scripts"
            scripts_dir.mkdir(parents=True)
            dst_approve = scripts_dir / "approve-target.py"
            shutil.copy2(SRC_APPROVE, dst_approve)

            bra = body / ".bra"
            (bra / "one-time-approvals").mkdir(parents=True)
            (bra / "logs").mkdir(parents=True)

            scope_md = body / "layer3-engagement" / "SCOPE.md"
            scope_md.parent.mkdir(parents=True)
            scope_md.write_text(
                "\n".join(
                    [
                        "# Scope",
                        "",
                        "### Network Targets",
                        "- **example.com**",
                        "",
                        "### Local Targets",
                    ]
                )
            )

            token = bra / "one-time-approvals" / "SCOPE-GRANT-api-example-com"
            token.write_text("ok")

            result = subprocess.run(
                ["python3", str(dst_approve), "api.example.com", "FULL", "ui-test", "network"],
                cwd=str(body),
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertFalse(token.exists(), msg="one-time token should be consumed")

            approved_targets = bra / "approved_targets.json"
            self.assertTrue(approved_targets.exists())
            payload = json.loads(approved_targets.read_text())
            discovered = payload.get("discovered", [])
            self.assertTrue(any(item.get("target") == "api.example.com" for item in discovered))

            scope_content = scope_md.read_text()
            self.assertIn("**api.example.com**", scope_content)


if __name__ == "__main__":
    unittest.main()
