from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bra.core.intel_writer import IntelWriter
from bra.core.markers import parse_marker
from bra.core.notes_materializer import replay_marker_events_to_notes
from bra.core.runner import AgentRunner


def _make_notes_and_state() -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    notes = root / "NOTES"
    bra_state = root / ".bra"
    logs = bra_state / "logs"
    notes.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    (notes / "INTEL.md").write_text("# INTEL.md\n\n", encoding="utf-8")
    (notes / "LEADS.md").write_text("# LEADS.md\n\n", encoding="utf-8")
    (notes / "FINDINGS.md").write_text("# Findings\n\n---\n", encoding="utf-8")
    return td, notes, bra_state


class MarkerPipelineV15ParityTests(unittest.TestCase):
    def test_intel_writer_keeps_network_and_firmware_out_of_port_scan_results(self) -> None:
        td, notes, _ = _make_notes_and_state()
        with td:
            writer = IntelWriter(notes)

            writer.append_entry("SERVICE", ["80/tcp", "open", "HTTP", "lighttpd"], source="nmap.txt")
            writer.append_entry("NETWORK", ["Cloud Backend", "198.51.100.57:8080"], source="root.html")
            writer.append_entry("FIRMWARE", ["UI Framework", "WeUI"], source="root.html")

            intel = (notes / "INTEL.md").read_text(encoding="utf-8")
            port_scan = intel.split("## Port Scan Results", 1)[1].split("## ", 1)[0]

            self.assertIn("| 80/tcp | open | HTTP | lighttpd | nmap.txt |", port_scan)
            self.assertNotIn("198.51.100.57:8080", port_scan)
            self.assertNotIn("WeUI", port_scan)
            self.assertIn("## Networks", intel)
            self.assertIn("| Cloud Backend | 198.51.100.57:8080 | root.html |", intel)
            self.assertIn("## Firmwares", intel)
            self.assertIn("| UI Framework | WeUI | root.html |", intel)

    def test_parse_service_marker_supports_v15_shape(self) -> None:
        marker = parse_marker("[SERVICE] 80/tcp | open | HTTP | lighttpd/1.4.76 | source: nmap.txt")

        self.assertIsNotNone(marker)
        assert marker is not None
        self.assertEqual(marker.type.value, "service")
        self.assertEqual(marker.port, "80/tcp")
        self.assertEqual(marker.fields.get("state"), "open")
        self.assertEqual(marker.service, "HTTP")
        self.assertEqual(marker.version, "lighttpd/1.4.76")
        self.assertEqual(marker.fields.get("source"), "nmap.txt")

    def test_runner_service_marker_emits_callback_and_writes_intel(self) -> None:
        td, notes, bra_state = _make_notes_and_state()
        with td:
            on_service = MagicMock()
            runner = AgentRunner(
                notes_dir=notes,
                bra_state_dir=bra_state,
                on_service=on_service,
            )

            runner._parse_and_dispatch_text("[SERVICE] 80/tcp | open | HTTP | lighttpd/1.4.76")

            intel = (notes / "INTEL.md").read_text(encoding="utf-8")
            self.assertIn("## Port Scan Results", intel)
            self.assertIn("lighttpd/1.4.76", intel)
            on_service.assert_called_once_with("80/tcp", "open", "HTTP", "lighttpd/1.4.76", "")

    def test_intel_writer_append_service_matches_v15_port_scan_section(self) -> None:
        td, notes, _ = _make_notes_and_state()
        with td:
            writer = IntelWriter(notes)

            writer.append_service("80/tcp", "open", "HTTP", "lighttpd", source="nmap")

            intel = (notes / "INTEL.md").read_text(encoding="utf-8")
            self.assertIn("## Port Scan Results", intel)
            self.assertIn("| Port | State | Service | Version | Source |", intel)
            self.assertIn("| 80/tcp | open | HTTP | lighttpd | nmap |", intel)

    def test_notes_materializer_replays_service_event_into_intel(self) -> None:
        td, notes, bra_state = _make_notes_and_state()
        with td:
            events_path = bra_state / "logs" / "marker_events.jsonl"
            with events_path.open("w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "category": "SERVICE",
                            "marker_type": "service",
                            "raw_fields": ["80/tcp", "open", "HTTP", "lighttpd/1.4.76"],
                            "fields": {"state": "open"},
                            "port": "80/tcp",
                            "service": "HTTP",
                            "version": "lighttpd/1.4.76",
                            "source": "nmap.txt",
                        }
                    )
                    + "\n"
                )

            applied = replay_marker_events_to_notes(notes, bra_state)

            intel = (notes / "INTEL.md").read_text(encoding="utf-8")
            self.assertEqual(applied["intel"], 1)
            self.assertIn("## Port Scan Results", intel)
            self.assertIn("lighttpd/1.4.76", intel)
            self.assertIn("nmap.txt", intel)

    def test_notes_materializer_does_not_inherit_stale_capture_for_service_with_anon_source(self) -> None:
        td, notes, bra_state = _make_notes_and_state()
        with td:
            events_path = bra_state / "logs" / "marker_events.jsonl"
            evidence_path = bra_state / "logs" / "evidence_index.jsonl"
            artifact_rel = ".bra/artifacts/raw/anon_20260308_195718_024293_nmap_20260308_195718.txt"
            artifact_abs = str(notes.parent / artifact_rel)
            with evidence_path.open("w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "capture_id": "anon_20260308_195718_024293",
                            "session_id": "sess-1",
                            "tool_use_id": "",
                            "tool_name": "Bash",
                            "action": "bash",
                            "target": "nmap -p 80 estuary",
                            "command": "nmap -p 80 estuary",
                            "url": "",
                            "method": "",
                            "host": "estuary",
                            "endpoint": "",
                            "target_kind": "host",
                            "artifact_path": artifact_abs,
                            "artifact_sha256": "deadbeef",
                            "source_kind": "anon_intercept",
                            "created_at": "2026-03-08T19:57:18.578583+00:00",
                        }
                    )
                    + "\n"
                )
            with events_path.open("w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "category": "LEAD",
                            "marker_type": "lead",
                            "capture_id": "toolu_016TnsxygT6mnWpunMqaK6tC",
                            "title": "startup lead",
                            "raw_fields": ["startup lead"],
                            "fields": {},
                        }
                    )
                    + "\n"
                )
                handle.write(
                    json.dumps(
                        {
                            "category": "SERVICE",
                            "marker_type": "service",
                            "raw_fields": ["80/tcp", "open", "HTTP"],
                            "fields": {"source": artifact_rel, "state": "open"},
                            "port": "80/tcp",
                            "service": "open",
                            "version": "HTTP",
                            "source": artifact_rel,
                        }
                    )
                    + "\n"
                )

            applied = replay_marker_events_to_notes(notes, bra_state)

            intel = (notes / "INTEL.md").read_text(encoding="utf-8")
            self.assertEqual(applied["intel"], 1)
            self.assertIn("capture_id:anon_20260308_195718_024293", intel)
            self.assertNotIn("capture_id:toolu_016TnsxygT6mnWpunMqaK6tC", intel)

    def test_notes_materializer_replays_lead_source_into_leads_table(self) -> None:
        td, notes, bra_state = _make_notes_and_state()
        with td:
            events_path = bra_state / "logs" / "marker_events.jsonl"
            evidence_path = bra_state / "logs" / "evidence_index.jsonl"
            artifact_rel = ".bra/artifacts/raw/anon_20260409_220638_580188_curl_20260409_220638.txt"
            artifact_abs = str(notes.parent / artifact_rel)
            with evidence_path.open("w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "capture_id": "anon_20260409_220638_580188",
                            "session_id": "sess-1",
                            "tool_use_id": "",
                            "tool_name": "Bash",
                            "action": "bash",
                            "target": "curl -s -i http://peacock/ -o .bra/artifacts/intel_work/web-root-port80.txt",
                            "command": "curl -s -i http://peacock/ -o .bra/artifacts/intel_work/web-root-port80.txt",
                            "artifact_path": artifact_abs,
                            "artifact_sha256": "deadbeef",
                            "source_kind": "anon_intercept",
                            "created_at": "2026-04-09T22:06:38.612445+00:00",
                        }
                    )
                    + "\n"
                )
            with events_path.open("w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "category": "LEAD",
                            "marker_type": "lead",
                            "title": "Enumerate web interface",
                            "priority": "High",
                            "source": artifact_rel,
                            "fields": {
                                "source": artifact_rel,
                                "capture_id": "anon_20260409_220638_580188",
                                "source_kind": "anon_intercept",
                            },
                            "raw_fields": [
                                "Enumerate web interface",
                                "rationale: inspect root page",
                            ],
                        }
                    )
                    + "\n"
                )

            applied = replay_marker_events_to_notes(notes, bra_state)

            leads = (notes / "LEADS.md").read_text(encoding="utf-8")
            self.assertEqual(applied["leads"], 1)
            self.assertIn(artifact_rel, leads)
            self.assertIn("capture_id:anon_20260409_220638_580188", leads)
            self.assertIn("source_kind:anon_intercept", leads)


if __name__ == "__main__":
    unittest.main()
