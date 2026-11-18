from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from boots.telemetry import compute_telemetry


class TelemetryContractTests(unittest.TestCase):
    def test_compute_telemetry_reads_current_body_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            body = Path(td)
            (body / ".bra" / "artifacts").mkdir(parents=True, exist_ok=True)
            (body / ".bra" / "approvals").mkdir(parents=True, exist_ok=True)
            (body / "layer3-engagement" / "NOTES").mkdir(parents=True, exist_ok=True)
            (body / "layer2-templates" / "methodologies").mkdir(parents=True, exist_ok=True)
            (body / "layer2-templates" / "workflows").mkdir(parents=True, exist_ok=True)

            (body / "layer3-engagement" / "NOTES" / "FINDINGS.md").write_text(
                "\n".join(
                    [
                        "## [FINDING-001] Alpha",
                        "| **Severity** | High |",
                        "",
                        "## [FINDING-002] Beta",
                        "| **Severity** | Info |",
                    ]
                )
            )
            (body / "layer3-engagement" / "NOTES" / "LEADS.md").write_text(
                "| 001 | Lead A | High | Why | open |\n| 002 | Lead B | Low | Why | closed |\n"
            )
            (body / ".bra" / "artifacts" / "manifest.json").write_text('{"artifacts":[{"id":"a1"},{"id":"a2"}]}')
            (body / ".bra" / "overrides.json").write_text(
                '{"rules":[{"type":"TOOL","enabled":true,"layer":"3","match":{"tool_name":"rg","command":"rg foo"}},{"type":"TOKEN","enabled":false,"layer":"2","match":{}}]}'
            )
            (body / ".bra" / "approvals" / "WATCH").write_text("")
            (body / ".bra" / "approvals" / "TRACK").write_text("")
            (body / "layer2-templates" / "toolset.md").write_text(
                "## Recon\n- **rg**\n- **nmap**\n"
            )
            (body / "layer3-engagement" / "skillset.md").write_text(
                "## Operator Skills\n- Skill A\n- Skill B\n"
            )
            (body / "layer2-templates" / "methodologies" / "android.md").write_text("# android\n")
            (body / "layer2-templates" / "workflows" / "endgame.md").write_text("# endgame\n")
            (body / ".bra" / "engagement_meta.json").write_text('{"started_at":"2026-03-05T12:00:00Z"}')
            (body / ".bra" / "pipeline_state.json").write_text('{"last_phase":"reporting","status":"in_progress"}')
            (body / ".bra" / "service_state.json").write_text(
                '{"services":{"svc1":{"responding":true},"svc2":{"responding":false}}}'
            )

            payload = compute_telemetry(body)

            self.assertEqual(payload["live"]["findings"]["total"], 2)
            self.assertEqual(payload["live"]["findings"]["by_severity"]["High"], 1)
            self.assertEqual(payload["live"]["findings"]["by_severity"]["Info"], 1)
            self.assertEqual(payload["live"]["leads"]["total"], 2)
            self.assertEqual(payload["live"]["artifacts"]["total"], 2)
            self.assertEqual(payload["live"]["overrides"]["total"], 2)
            self.assertEqual(payload["live"]["tokens"]["total_granted"], 2)
            self.assertEqual(payload["live"]["engagement"]["current_phase"], "reporting")
            self.assertEqual(payload["live"]["service_health"]["targets_total"], 2)
            self.assertEqual(payload["live"]["service_health"]["targets_responding"], 1)
            self.assertIn("battle_card", payload)

    def test_compute_telemetry_counts_real_artifacts_when_manifest_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            body = Path(td)
            raw_dir = body / ".bra" / "artifacts" / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            (body / ".bra" / "artifacts" / "manifest.json").write_text('{"artifacts":[]}')
            (raw_dir / "capture.txt").write_text("raw capture", encoding="utf-8")

            payload = compute_telemetry(body)

            self.assertEqual(payload["live"]["artifacts"]["total"], 1)


if __name__ == "__main__":
    unittest.main()
