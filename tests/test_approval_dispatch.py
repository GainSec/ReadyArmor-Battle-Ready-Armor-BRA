from __future__ import annotations

import os
import json
import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from bra.config import settings as settings_module
from bra.core.approval import ApprovalManager

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_APPROVE = REPO_ROOT / "body" / "layer1" / "scripts" / "approve-target.py"


class ApprovalDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._old_bra_root = getattr(settings_module, "_bra_root", None)
        self._old_env = dict(os.environ)

    def tearDown(self) -> None:
        settings_module._bra_root = self._old_bra_root
        os.environ.clear()
        os.environ.update(self._old_env)

    def _make_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        scripts = root / "body" / "layer1" / "scripts"
        scripts.mkdir(parents=True, exist_ok=True)
        (root / "body" / ".bra").mkdir(parents=True, exist_ok=True)
        settings_module._bra_root = root
        return td, root, scripts

    @staticmethod
    def _write_exec(path: Path, content: str) -> None:
        path.write_text(content)
        path.chmod(0o755)

    def test_grant_scope_runs_python_script(self) -> None:
        td, root, scripts = self._make_root()
        with td:
            marker = root / "python_ran"
            self._write_exec(
                scripts / "approve-target.py",
                textwrap.dedent(
                    f"""
                    #!/usr/bin/env python3
                    from pathlib import Path
                    Path({str(marker)!r}).write_text('ok')
                    raise SystemExit(0)
                    """
                ).strip()
                + "\n",
            )

            mgr = ApprovalManager()
            ok = mgr.grant_scope("example.com", "LIMITED", "test")
            self.assertTrue(ok)
            self.assertTrue(marker.exists())

    def test_grant_scope_returns_false_on_failure(self) -> None:
        td, root, scripts = self._make_root()
        with td:
            self._write_exec(
                scripts / "approve-target.py",
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    raise SystemExit(1)
                    """
                ).strip()
                + "\n",
            )

            mgr = ApprovalManager()
            ok = mgr.grant_scope("example.com", "LIMITED", "test")
            self.assertFalse(ok)

    def test_grant_scope_prefers_direct_backend_registration_when_available(self) -> None:
        td, root, scripts = self._make_root()
        with td:
            shutil.copy2(SRC_APPROVE, scripts / "approve-target.py")
            scope_md = root / "body" / "layer3-engagement" / "SCOPE.md"
            scope_md.parent.mkdir(parents=True, exist_ok=True)
            scope_md.write_text(
                "\n".join(
                    [
                        "# Scope",
                        "",
                        "### Network Targets",
                        "- **example.com**",
                        "",
                        "### Local Targets",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            mgr = ApprovalManager()
            with patch("bra.core.approval.subprocess.run") as run_mock:
                ok = mgr.grant_scope("192.168.18.9", "FULL", "UI approval", "network")

            self.assertTrue(ok)
            run_mock.assert_not_called()

            approved_targets = root / "body" / ".bra" / "approved_targets.json"
            payload = json.loads(approved_targets.read_text(encoding="utf-8"))
            discovered = payload.get("discovered", [])
            self.assertTrue(any(item.get("target") == "192.168.18.9" for item in discovered))
            self.assertIn("**192.168.18.9**", scope_md.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
