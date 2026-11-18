from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bra.hooks import post_hook


class PostHookAnonMaskingTests(unittest.TestCase):
    def test_capture_raw_artifact_masks_real_values_when_anon_map_exists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bra_state = root / ".bra"
            artifacts_dir = bra_state / "artifacts"
            bra_state.mkdir(parents=True, exist_ok=True)
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            map_path = bra_state / "anon_map.json"
            map_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "mappings": [
                            {
                                "real": "10.0.0.1",
                                "anon": "FALCON",
                                "type": "ip",
                                "source": "scope",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with (
                patch.object(post_hook, "ARTIFACTS_DIR", artifacts_dir),
                patch("bra.config.settings.BRA_STATE", bra_state),
            ):
                artifact = post_hook._capture_raw_artifact(
                    "Bash",
                    {"command": "curl http://10.0.0.1/status"},
                    "connected to 10.0.0.1 successfully",
                    "toolu_01abc789xyz",
                )

            self.assertIsNotNone(artifact)
            assert artifact is not None
            persisted = artifact.read_text(encoding="utf-8")
            self.assertIn("FALCON", persisted)
            self.assertNotIn("10.0.0.1", persisted)


if __name__ == "__main__":
    unittest.main()
