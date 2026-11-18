from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))

from bra.core.finding_enforcer import FindingEnforcer


class FindingEnforcerArtifactResolutionTests(unittest.TestCase):
    def test_resolve_record_path_remaps_stale_workspace_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            project_root = Path(td)
            body_root = project_root / "body"
            notes_dir = body_root / "layer3-engagement" / "NOTES"
            bra_state_dir = body_root / ".bra"
            raw_dir = bra_state_dir / "artifacts" / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            notes_dir.mkdir(parents=True, exist_ok=True)

            current_artifact = raw_dir / "capture.txt"
            current_artifact.write_text("capture", encoding="utf-8")

            enforcer = FindingEnforcer(notes_dir, bra_state_dir)
            stale_path = "/tmp/old-run/body/.bra/artifacts/raw/capture.txt"

            resolved = enforcer._resolve_record_path(stale_path)

            self.assertEqual(resolved, current_artifact)


if __name__ == "__main__":
    unittest.main()
