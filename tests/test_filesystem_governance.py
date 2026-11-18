from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bra.core import filesystem


class FilesystemGovernanceTests(unittest.TestCase):
    def test_blocks_layer3_artifacts_and_redirects_to_bra_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            layer1 = root / "layer1"
            layer2 = root / "layer2-templates"
            layer3 = root / "layer3-engagement"
            bra_state = root / ".bra"
            for path in (layer1, layer2, layer3, bra_state):
                path.mkdir(parents=True, exist_ok=True)

            target = layer3 / "artifacts" / "runtime.txt"

            with (
                mock.patch.object(filesystem, "LAYER1", layer1),
                mock.patch.object(filesystem, "LAYER2", layer2),
                mock.patch.object(filesystem, "LAYER3", layer3),
                mock.patch.object(filesystem, "BRA_STATE", bra_state),
            ):
                with self.assertRaises(filesystem.ProtectedPathError) as ctx:
                    filesystem.write(target, "runtime output")

            message = str(ctx.exception)
            self.assertIn(".bra/artifacts/", message)
            self.assertIn(".bra/artifacts/raw/", message)


if __name__ == "__main__":
    unittest.main()
