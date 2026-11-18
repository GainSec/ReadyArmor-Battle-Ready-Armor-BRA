from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bra.core.capture_provenance import extract_capture_candidates, resolve_capture_hint
from bra.core.findings_materializer import _infer_capture_id_from_text as infer_finding_capture_id
from bra.core.markers import _is_valid_capture_id as is_valid_marker_capture_id
from bra.core.markers import parse_marker
from bra.core.notes_materializer import _infer_capture_id_from_text as infer_notes_capture_id
from bra.core.runner import AgentRunner


class AnonCaptureIdParityTests(unittest.TestCase):
    def _make_runner(self) -> AgentRunner:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        notes_dir = root / "layer3-engagement" / "NOTES"
        bra_state_dir = root / ".bra"
        notes_dir.mkdir(parents=True, exist_ok=True)
        bra_state_dir.mkdir(parents=True, exist_ok=True)
        return AgentRunner(notes_dir=notes_dir, bra_state_dir=bra_state_dir)

    def _append_capture_record(
        self,
        runner: AgentRunner,
        *,
        capture_id: str,
        tool_name: str,
        action: str,
        artifact_path: str,
        command: str = "",
        target: str = "",
        source_kind: str = "tool_capture",
    ) -> None:
        index_path = runner._bra_state_dir / "logs" / "evidence_index.jsonl"
        index_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "capture_id": capture_id,
            "session_id": "sess-1",
            "tool_use_id": capture_id,
            "tool_name": tool_name,
            "action": action,
            "target": target,
            "command": command,
            "url": "",
            "method": "",
            "host": "",
            "endpoint": "",
            "target_kind": "file",
            "artifact_path": artifact_path,
            "artifact_sha256": "deadbeef",
            "source_kind": source_kind,
            "created_at": "2026-03-08T18:49:31.250170+00:00",
        }
        with index_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    def _write_last_capture_sidecar(
        self,
        runner: AgentRunner,
        *,
        capture_id: str,
        path: str,
        command: str,
        source_kind: str = "anon_intercept",
    ) -> None:
        sidecar = runner._bra_state_dir / "last_capture.json"
        sidecar.write_text(
            json.dumps(
                {
                    "capture_id": capture_id,
                    "path": path,
                    "command": command,
                    "source_kind": source_kind,
                }
            ),
            encoding="utf-8",
        )

    def test_runner_accepts_anon_capture_ids(self) -> None:
        runner = self._make_runner()

        self.assertTrue(runner._is_valid_capture_id("anon_20260306_010203_123456"))

    def test_runner_still_accepts_toolu_capture_ids(self) -> None:
        runner = self._make_runner()

        self.assertTrue(runner._is_valid_capture_id("toolu_01WwcjNgMRBve7Vauk9qFEut"))

    def test_runner_infers_anon_capture_id_from_source_text(self) -> None:
        runner = self._make_runner()

        inferred = runner._infer_capture_id_from_source(
            "source: capture_id: anon_20260306_010203_123456"
        )

        self.assertEqual(inferred, "anon_20260306_010203_123456")

    def test_runner_still_infers_toolu_capture_id_from_source_text(self) -> None:
        runner = self._make_runner()

        inferred = runner._infer_capture_id_from_source(
            "source: capture_id: toolu_01WwcjNgMRBve7Vauk9qFEut"
        )

        self.assertEqual(inferred, "toolu_01WwcjNgMRBve7Vauk9qFEut")

    def test_marker_parser_preserves_anon_capture_id(self) -> None:
        marker = parse_marker(
            "[FINDING] HIGH: Example vuln | cvss: 8.0 | attack_surface: Web Service | "
            "capture_id: anon_20260306_010203_123456"
        )

        self.assertIsNotNone(marker)
        assert marker is not None
        self.assertEqual(marker.fields.get("capture_id"), "anon_20260306_010203_123456")

    def test_marker_validation_still_accepts_toolu_and_cap(self) -> None:
        self.assertTrue(is_valid_marker_capture_id("toolu_01WwcjNgMRBve7Vauk9qFEut"))
        self.assertTrue(is_valid_marker_capture_id("cap_session_20260306_010203"))

    def test_findings_materializer_infers_anon_capture_id(self) -> None:
        inferred = infer_finding_capture_id(
            "source marker: capture_id: anon_20260306_010203_123456"
        )

        self.assertEqual(inferred, "anon_20260306_010203_123456")

    def test_notes_materializer_infers_anon_capture_id(self) -> None:
        inferred = infer_notes_capture_id(
            "source marker: capture_id: anon_20260306_010203_123456"
        )

        self.assertEqual(inferred, "anon_20260306_010203_123456")

    def test_materializers_do_not_greedily_parse_anon_artifact_filenames(self) -> None:
        text = ".bra/artifacts/raw/anon_20260308_195718_024293_nmap_20260308_195718.txt"

        self.assertEqual(
            infer_finding_capture_id(text),
            "anon_20260308_195718_024293",
        )
        self.assertEqual(
            infer_notes_capture_id(text),
            "anon_20260308_195718_024293",
        )

    def test_capture_candidate_extraction_stops_at_actual_anon_id(self) -> None:
        candidates = extract_capture_candidates(
            ".bra/artifacts/raw/anon_20260308_195718_024293_nmap_20260308_195718.txt"
        )

        self.assertEqual(candidates, ["anon_20260308_195718_024293"])

    def test_materializers_still_infer_toolu_capture_ids(self) -> None:
        text = "source marker: capture_id: toolu_01WwcjNgMRBve7Vauk9qFEut"
        self.assertEqual(
            infer_finding_capture_id(text),
            "toolu_01WwcjNgMRBve7Vauk9qFEut",
        )
        self.assertEqual(
            infer_notes_capture_id(text),
            "toolu_01WwcjNgMRBve7Vauk9qFEut",
        )

    def test_runner_replaces_stale_marker_capture_with_origin_capture_in_persisted_event(self) -> None:
        runner = self._make_runner()
        origin_capture_id = "anon_20260308_184959_000001"
        derivative_capture_id = "toolu_01Tvyrwhig8aoXqagkhQXCTZ"
        artifact_rel = ".bra/artifacts/raw/port80_root.html"
        artifact_abs = str(runner._bra_state_dir.parent / artifact_rel)
        self._append_capture_record(
            runner,
            capture_id=origin_capture_id,
            tool_name="Bash",
            action="bash",
            command="curl -sv http://octopus/ -o .bra/artifacts/raw/port80_root.html",
            target="curl -sv http://octopus/ -o .bra/artifacts/raw/port80_root.html",
            artifact_path=artifact_abs,
            source_kind="anon_intercept",
        )
        self._append_capture_record(
            runner,
            capture_id=derivative_capture_id,
            tool_name="Read",
            action="read",
            target=artifact_abs,
            artifact_path=str(
                runner._bra_state_dir / "artifacts" / "raw" / "toolu_01tvyrwhig8aoxqagkhqxctz_read_port80_root.html.txt"
            ),
            source_kind="tool_capture",
        )
        runner._latest_tool_capture_id = derivative_capture_id
        runner._latest_tool_source_kind = "tool_capture"

        runner._parse_and_dispatch_text(
            "[FINDING] HIGH: Hardcoded API signing secret exposed in client-side JavaScript "
            "| cvss: 7.5 | attack_surface: Web Service - Information Disclosure "
            "| capture_id: toolu_01T39vwDSxZYNVyEhZNscAtp\n"
        )

        event_path = runner._bra_state_dir / "logs" / "marker_events.jsonl"
        events = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(events[-1]["capture_id"], origin_capture_id)
        self.assertEqual(events[-1]["fields"]["capture_id"], origin_capture_id)
        self.assertEqual(events[-1]["source"], artifact_rel)
        self.assertNotIn("toolu_01T39vwDSxZYNVyEhZNscAtp", json.dumps(events[-1]))

    def test_runner_rewrites_pending_finding_source_marker_to_origin_capture(self) -> None:
        runner = self._make_runner()
        origin_capture_id = "anon_20260308_184959_000002"
        derivative_capture_id = "toolu_01Tvyrwhig8aoXqagkhQXCTZ"
        artifact_rel = ".bra/artifacts/raw/port80_root.html"
        artifact_abs = str(runner._bra_state_dir.parent / artifact_rel)
        self._append_capture_record(
            runner,
            capture_id=origin_capture_id,
            tool_name="Bash",
            action="bash",
            command="curl -sv http://octopus/ -o .bra/artifacts/raw/port80_root.html",
            target="curl -sv http://octopus/ -o .bra/artifacts/raw/port80_root.html",
            artifact_path=artifact_abs,
            source_kind="anon_intercept",
        )
        self._append_capture_record(
            runner,
            capture_id=derivative_capture_id,
            tool_name="Read",
            action="read",
            target=artifact_abs,
            artifact_path=str(
                runner._bra_state_dir / "artifacts" / "raw" / "toolu_01tvyrwhig8aoxqagkhqxctz_read_port80_root.html.txt"
            ),
            source_kind="tool_capture",
        )
        runner._latest_tool_capture_id = derivative_capture_id
        runner._latest_tool_source_kind = "tool_capture"

        runner._parse_and_dispatch_text(
            "[FINDING] HIGH: Hardcoded API signing secret exposed in client-side JavaScript "
            "| cvss: 7.5 | attack_surface: Web Service - Information Disclosure "
            "| capture_id: toolu_01T39vwDSxZYNVyEhZNscAtp\n"
        )

        pending = runner._finding_enforcer.pending_queue
        self.assertEqual(len(pending), 1)
        self.assertIn(f"capture_id: {origin_capture_id}", pending[0].source_marker)
        self.assertNotIn("toolu_01T39vwDSxZYNVyEhZNscAtp", pending[0].source_marker)
        self.assertNotIn(derivative_capture_id, pending[0].source_marker)

    def test_runner_promotes_anon_intercept_result_over_stale_cached_toolsearch_capture(self) -> None:
        runner = self._make_runner()
        stale_capture_id = "toolu_012UwmvPGJqVMP4rM2kFWcVr"
        origin_capture_id = "anon_20260308_194418_576648"
        stale_artifact_abs = str(
            runner._bra_state_dir.parent
            / ".bra"
            / "artifacts"
            / "raw"
            / "toolu_012uwmvpgjqvmp4rm2kfwcvr_toolsearch_select-webfetch_20260308_194044.txt"
        )
        origin_artifact_rel = ".bra/artifacts/raw/anon_20260308_194418_576648_curl_20260308_194418.txt"
        origin_artifact_abs = str(runner._bra_state_dir.parent / origin_artifact_rel)
        self._append_capture_record(
            runner,
            capture_id=stale_capture_id,
            tool_name="ToolSearch",
            action="search",
            target="max_results, query",
            command="max_results, query",
            artifact_path=stale_artifact_abs,
            source_kind="tool_capture",
        )
        self._append_capture_record(
            runner,
            capture_id=origin_capture_id,
            tool_name="Bash",
            action="bash",
            target='curl -si http://squid/ -o .bra/artifacts/intel_work/http-root.txt 2>&1 && echo "DONE"',
            command='curl -si http://squid/ -o .bra/artifacts/intel_work/http-root.txt 2>&1 && echo "DONE"',
            artifact_path=origin_artifact_abs,
            source_kind="anon_intercept",
        )
        self._write_last_capture_sidecar(
            runner,
            capture_id=origin_capture_id,
            path=origin_artifact_abs,
            command='curl -si http://squid/ -o .bra/artifacts/intel_work/http-root.txt 2>&1 && echo "DONE"',
        )
        runner._latest_tool_capture_id = stale_capture_id
        runner._latest_tool_source_kind = "tool_capture"

        block = type(
            "ResultBlock",
            (),
            {
                "is_error": False,
                "content": (
                    "ANON_INTERCEPT_OK (exit 0)\n"
                    f"capture_id: {origin_capture_id}\n\n"
                    "Command executed successfully. Output anonymized.\n"
                    f"Full output: {origin_artifact_rel}\n\nDONE\n"
                ),
                "tool_use_id": "toolu_01QYS3fh2mmZXQPvtvrAeFb4",
            },
        )()
        message = type("UserMessage", (), {"content": [block]})()

        asyncio.run(runner._process_message(message))

        self.assertEqual(runner._latest_tool_capture_id, origin_capture_id)
        self.assertEqual(runner._latest_tool_source_kind, "anon_intercept")

        runner._parse_and_dispatch_text(
            "[FINDING] HIGH: Unauthenticated factory reset via HTTP GET "
            "| cvss: 8.2 | attack_surface: Web Service - Unauthenticated Destructive Action "
            "| capture_id: toolu_012UwmvPGJqVMP4rM2kFWcVr\n"
        )

        event_path = runner._bra_state_dir / "logs" / "marker_events.jsonl"
        events = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(events[-1]["capture_id"], origin_capture_id)
        self.assertEqual(events[-1]["fields"]["capture_id"], origin_capture_id)
        self.assertEqual(events[-1]["source"], origin_artifact_rel)
        self.assertNotIn(stale_capture_id, json.dumps(events[-1]))

    def test_runner_rewrites_service_marker_to_anon_capture_from_source_hint(self) -> None:
        runner = self._make_runner()
        stale_capture_id = "toolu_016TnsxygT6mnWpunMqaK6tC"
        origin_capture_id = "anon_20260308_202642_708992"
        stale_artifact_abs = str(
            runner._bra_state_dir.parent
            / ".bra"
            / "artifacts"
            / "raw"
            / "toolu_016tnsxygt6mnwpunmqak6tc_toolsearch_select-webfetch_20260308_202514.txt"
        )
        origin_artifact_rel = ".bra/artifacts/raw/anon_20260308_202642_708992_nmap_20260308_202643.txt"
        origin_artifact_abs = str(runner._bra_state_dir.parent / origin_artifact_rel)
        self._append_capture_record(
            runner,
            capture_id=stale_capture_id,
            tool_name="ToolSearch",
            action="search",
            target="select:WebFetch",
            command="select:WebFetch",
            artifact_path=stale_artifact_abs,
            source_kind="tool_capture",
        )
        self._append_capture_record(
            runner,
            capture_id=origin_capture_id,
            tool_name="Bash",
            action="bash",
            target="nmap -p 80 twilight",
            command="nmap -p 80 twilight",
            artifact_path=origin_artifact_abs,
            source_kind="anon_intercept",
        )
        runner._latest_tool_capture_id = stale_capture_id
        runner._latest_tool_source_kind = "tool_capture"

        runner._parse_and_dispatch_text(
            "[SERVICE] 80/tcp | open | HTTP | source: "
            f"{origin_artifact_rel}\n"
        )

        event_path = runner._bra_state_dir / "logs" / "marker_events.jsonl"
        events = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(events[-1]["category"], "SERVICE")
        self.assertEqual(events[-1]["capture_id"], origin_capture_id)
        self.assertEqual(events[-1]["fields"]["capture_id"], origin_capture_id)
        self.assertEqual(events[-1]["source"], origin_artifact_rel)
        self.assertNotIn(stale_capture_id, json.dumps(events[-1]))

    def test_runner_canonicalizes_sidecar_only_anon_service_marker_event(self) -> None:
        runner = self._make_runner()
        origin_capture_id = "anon_20260308_210001_000111"
        origin_artifact_rel = ".bra/artifacts/raw/anon_20260308_210001_000111_nmap_20260308_210001.txt"
        origin_artifact_abs = str(runner._bra_state_dir.parent / origin_artifact_rel)
        self._write_last_capture_sidecar(
            runner,
            capture_id=origin_capture_id,
            path=origin_artifact_abs,
            command="nmap -p 80 harbor",
        )
        runner._latest_tool_capture_id = origin_capture_id
        runner._latest_tool_source_kind = "tool_capture"

        runner._parse_and_dispatch_text("[SERVICE] 80/tcp | open | HTTP | lighttpd/1.4.76\n")

        event_path = runner._bra_state_dir / "logs" / "marker_events.jsonl"
        events = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(events[-1]["category"], "SERVICE")
        self.assertEqual(events[-1]["capture_id"], origin_capture_id)
        self.assertEqual(events[-1]["source_kind"], "anon_intercept")
        self.assertEqual(events[-1]["fields"]["source_kind"], "anon_intercept")
        self.assertEqual(events[-1]["source"], origin_artifact_rel)
        self.assertEqual(events[-1]["artifact_path"], origin_artifact_rel)

    def test_runner_rewrites_bare_anon_source_hint_to_artifact_path(self) -> None:
        runner = self._make_runner()
        origin_capture_id = "anon_20260308_210002_000222"
        origin_artifact_rel = ".bra/artifacts/raw/anon_20260308_210002_000222_curl_20260308_210002.txt"
        origin_artifact_abs = str(runner._bra_state_dir.parent / origin_artifact_rel)
        self._write_last_capture_sidecar(
            runner,
            capture_id=origin_capture_id,
            path=origin_artifact_abs,
            command="curl -si http://harbor/",
        )

        runner._parse_and_dispatch_text(
            f"[SERVICE] 80/tcp | open | HTTP | lighttpd/1.4.76 | source: {origin_capture_id}\n"
        )

        event_path = runner._bra_state_dir / "logs" / "marker_events.jsonl"
        events = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(events[-1]["capture_id"], origin_capture_id)
        self.assertEqual(events[-1]["source_kind"], "anon_intercept")
        self.assertEqual(events[-1]["source"], origin_artifact_rel)
        self.assertEqual(events[-1]["artifact_path"], origin_artifact_rel)

    def test_resolve_capture_hint_prefers_exact_artifact_path_match(self) -> None:
        runner = self._make_runner()
        stale_capture_id = "toolu_012UwmvPGJqVMP4rM2kFWcVr"
        origin_capture_id = "anon_20260308_195718_024293"
        stale_artifact_abs = str(
            runner._bra_state_dir.parent
            / ".bra"
            / "artifacts"
            / "raw"
            / "toolu_012uwmvpgjqvmp4rm2kfwcvr_toolsearch_select_read_20260308_195605.txt"
        )
        origin_artifact_rel = ".bra/artifacts/raw/anon_20260308_195718_024293_nmap_20260308_195718.txt"
        origin_artifact_abs = str(runner._bra_state_dir.parent / origin_artifact_rel)
        self._append_capture_record(
            runner,
            capture_id=stale_capture_id,
            tool_name="ToolSearch",
            action="search",
            command="select:Read",
            target="select:Read",
            artifact_path=stale_artifact_abs,
            source_kind="tool_capture",
        )
        self._append_capture_record(
            runner,
            capture_id=origin_capture_id,
            tool_name="Bash",
            action="bash",
            command="nmap -p 80 estuary",
            target="nmap -p 80 estuary",
            artifact_path=origin_artifact_abs,
            source_kind="anon_intercept",
        )

        resolved = resolve_capture_hint(
            runner._bra_state_dir,
            f"[SERVICE] 80/tcp | open | HTTP | source: {origin_artifact_rel}",
        )

        self.assertEqual(resolved, origin_capture_id)

    def test_runner_rewrites_stale_capture_id_when_source_names_file_created_by_newer_capture(self) -> None:
        runner = self._make_runner()
        stale_capture_id = "anon_20260409_193437_544375"
        origin_capture_id = "anon_20260409_193533_885293"
        body_root = runner._bra_state_dir.parent
        source_file = body_root / ".bra" / "artifacts" / "fennel-root-http.txt"
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text("HTTP/1.1 200 OK\n", encoding="utf-8")

        stale_artifact_abs = str(
            body_root
            / ".bra"
            / "artifacts"
            / "raw"
            / "anon_20260409_193437_544375_nmap_20260409_193446.txt"
        )
        origin_artifact_rel = ".bra/artifacts/raw/anon_20260409_193533_885293_curl_20260409_193533.txt"
        origin_artifact_abs = str(body_root / origin_artifact_rel)
        read_capture_id = "toolu_01ReadFennelSource"
        read_artifact_abs = str(
            body_root
            / ".bra"
            / "artifacts"
            / "raw"
            / "toolu_01readfennelsource_read_fennel-root-http.txt_20260409_193536.txt"
        )

        self._append_capture_record(
            runner,
            capture_id=stale_capture_id,
            tool_name="Bash",
            action="bash",
            command="nmap -sV -p 80 fennel -oN .bra/artifacts/nmap-web-fennel.txt",
            target="nmap -sV -p 80 fennel -oN .bra/artifacts/nmap-web-fennel.txt",
            artifact_path=stale_artifact_abs,
            source_kind="anon_intercept",
        )
        self._append_capture_record(
            runner,
            capture_id=origin_capture_id,
            tool_name="Bash",
            action="bash",
            command='curl -s -i http://fennel/ -o .bra/artifacts/fennel-root-http.txt 2>&1 && echo "DONE"',
            target='curl -s -i http://fennel/ -o .bra/artifacts/fennel-root-http.txt 2>&1 && echo "DONE"',
            artifact_path=origin_artifact_abs,
            source_kind="anon_intercept",
        )
        self._append_capture_record(
            runner,
            capture_id=read_capture_id,
            tool_name="Read",
            action="read",
            target=str(source_file),
            artifact_path=read_artifact_abs,
            source_kind="tool_capture",
        )
        self._write_last_capture_sidecar(
            runner,
            capture_id=origin_capture_id,
            path=origin_artifact_abs,
            command='curl -s -i http://fennel/ -o .bra/artifacts/fennel-root-http.txt 2>&1 && echo "DONE"',
        )
        runner._latest_tool_capture_id = read_capture_id
        runner._latest_tool_source_kind = "tool_capture"

        runner._parse_and_dispatch_text(
            "[ENDPOINT] /cgi-bin/getversion.cgi | GET | Returns version info "
            f"| source: fennel-root-http.txt ; capture_id:{stale_capture_id} ; source_kind:anon_intercept\n"
        )

        event_path = runner._bra_state_dir / "logs" / "marker_events.jsonl"
        events = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(events[-1]["capture_id"], origin_capture_id)
        self.assertEqual(events[-1]["fields"]["capture_id"], origin_capture_id)
        self.assertEqual(events[-1]["source"], "fennel-root-http.txt")
        self.assertNotIn(stale_capture_id, json.dumps(events[-1]))

    def test_runner_prefers_promoted_origin_from_source_file_over_cached_nmap_capture(self) -> None:
        runner = self._make_runner()
        stale_capture_id = "anon_20260409_195320_389710"
        origin_capture_id = "anon_20260409_195515_150609"
        read_capture_id = "toolu_01DqRFksi67payuioaT3a2ik"
        body_root = runner._bra_state_dir.parent
        source_file = body_root / ".bra" / "artifacts" / "compass-root.html"
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text("<html></html>\n", encoding="utf-8")

        stale_artifact_abs = str(
            body_root
            / ".bra"
            / "artifacts"
            / "raw"
            / "anon_20260409_195320_389710_nmap_20260409_195331.txt"
        )
        origin_artifact_abs = str(
            body_root
            / ".bra"
            / "artifacts"
            / "raw"
            / "anon_20260409_195515_150609_curl_20260409_195515.txt"
        )
        read_artifact_abs = str(
            body_root
            / ".bra"
            / "artifacts"
            / "raw"
            / "toolu_01dqrfksi67payuioat3a2ik_read_compass-root.html_20260409_195522.txt"
        )

        self._append_capture_record(
            runner,
            capture_id=stale_capture_id,
            tool_name="Bash",
            action="bash",
            command="nmap -sV --open -p 80,443 compass -oN .bra/artifacts/nmap-web-compass.txt 2>&1",
            target="nmap -sV --open -p 80,443 compass -oN .bra/artifacts/nmap-web-compass.txt 2>&1",
            artifact_path=stale_artifact_abs,
            source_kind="anon_intercept",
        )
        self._append_capture_record(
            runner,
            capture_id=origin_capture_id,
            tool_name="Bash",
            action="bash",
            command="curl -sv http://compass/ -o .bra/artifacts/compass-root.html 2>&1",
            target="curl -sv http://compass/ -o .bra/artifacts/compass-root.html 2>&1",
            artifact_path=origin_artifact_abs,
            source_kind="anon_intercept",
        )
        self._append_capture_record(
            runner,
            capture_id=read_capture_id,
            tool_name="Read",
            action="read",
            target=str(source_file),
            artifact_path=read_artifact_abs,
            source_kind="tool_capture",
        )

        runner._latest_tool_capture_id = stale_capture_id
        runner._latest_tool_source_kind = "anon_intercept"

        runner._parse_and_dispatch_text(
            "[ENDPOINT] /cgi-bin/getversion.cgi | GET | Device version | unauthenticated "
            f"| source: .bra/artifacts/compass-root.html ; capture_id:{stale_capture_id} ; source_kind:anon_intercept\n"
        )

        event_path = runner._bra_state_dir / "logs" / "marker_events.jsonl"
        events = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(events[-1]["capture_id"], origin_capture_id)
        self.assertEqual(events[-1]["fields"]["capture_id"], origin_capture_id)
        self.assertEqual(events[-1]["source"], ".bra/artifacts/compass-root.html")
        self.assertNotIn(stale_capture_id, json.dumps(events[-1]))


if __name__ == "__main__":
    unittest.main()
