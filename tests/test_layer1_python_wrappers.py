from __future__ import annotations

import unittest
from pathlib import Path


class Layer1PythonWrapperAvailabilityTests(unittest.TestCase):
    REQUIRED_PORTS = {
        "scripts/agentic-handler.py",
        "scripts/approval-gate.py",
        "scripts/approve-target.py",
        "scripts/danger_check.py",
        "scripts/disclose.py",
        "scripts/dry-run.py",
        "scripts/growth.py",
        "scripts/ingest.py",
        "scripts/lessons-learned.py",
        "scripts/packup.py",
        "scripts/precheck.py",
        "scripts/report-ready.py",
        "scripts/reset.py",
        "scripts/stats.py",
        "hooks/bash-guard.py",
        "hooks/file-guard.py",
        "hooks/governance-reminder.py",
        "hooks/track-post.py",
    }

    def test_layer1_has_no_shell_files(self) -> None:
        layer1_dir = Path(__file__).resolve().parents[1] / "body" / "layer1"
        shell_scripts = sorted(layer1_dir.rglob("*.sh"))
        self.assertEqual(shell_scripts, [], "Expected zero shell files under body/layer1.")

    def test_required_python_ports_exist(self) -> None:
        layer1_dir = Path(__file__).resolve().parents[1] / "body" / "layer1"
        missing = [
            rel_path
            for rel_path in sorted(self.REQUIRED_PORTS)
            if not (layer1_dir / rel_path).exists()
        ]
        self.assertEqual(missing, [], "Missing required layer1 Python ports:\n" + "\n".join(missing))

    def test_layer1_python_port_count(self) -> None:
        layer1_dir = Path(__file__).resolve().parents[1] / "body" / "layer1"
        python_files = list(layer1_dir.rglob("*.py"))
        self.assertGreaterEqual(len(python_files), 60, "Expected full layer1 Python port set to be present.")


if __name__ == "__main__":
    unittest.main()
