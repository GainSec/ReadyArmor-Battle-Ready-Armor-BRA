from __future__ import annotations

import asyncio
import importlib
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

boots_main = importlib.import_module("boots.main")


class _FakeRequest:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    async def json(self) -> dict:
        return self._payload


class MainAnonRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project_root = Path(self.tmp.name)
        self.body_root = self.project_root / "body"
        (self.body_root / ".bra" / "approvals").mkdir(parents=True)

        self._orig_get_bra_dir = boots_main.get_bra_dir
        self._orig_auth_token = boots_main.AUTH_TOKEN
        self._orig_bra_dir = boots_main.BRA_DIR
        self._orig_load_config = boots_main.load_config
        boots_main.get_bra_dir = lambda: str(self.project_root)
        boots_main.AUTH_TOKEN = ""
        boots_main.BRA_DIR = str(self.project_root)
        boots_main.load_config = lambda: {}
        self.addCleanup(self._restore_main_state)

    def _restore_main_state(self) -> None:
        boots_main.get_bra_dir = self._orig_get_bra_dir
        boots_main.AUTH_TOKEN = self._orig_auth_token
        boots_main.BRA_DIR = self._orig_bra_dir
        boots_main.load_config = self._orig_load_config

    def _write_map(self, mappings: list[dict]) -> None:
        map_path = self.body_root / ".bra" / "anon_map.json"
        map_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "engagement": "test",
                    "created": "2026-03-06T00:00:00Z",
                    "mappings": mappings,
                }
            ),
            encoding="utf-8",
        )

    def test_anon_mask_chat_masks_existing_mapping(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"}]
        )
        (self.body_root / ".bra" / "approvals" / "MAP-SCAN").touch()

        result = boots_main._anon_mask_chat("Connect to 10.0.0.1 now")

        self.assertIn("FALCON", result)
        self.assertNotIn("10.0.0.1", result)

    def test_anon_mask_chat_detects_and_persists_on_anon_scan(self) -> None:
        (self.body_root / ".bra" / "approvals" / "ANON-SCAN").touch()

        result = boots_main._anon_mask_chat("Target 10.0.0.1 is reachable")

        self.assertNotIn("10.0.0.1", result)
        map_data = json.loads((self.body_root / ".bra" / "anon_map.json").read_text())
        values = [entry["real"] for entry in map_data["mappings"]]
        self.assertIn("10.0.0.1", values)

    def test_anon_mask_chat_detects_on_local_scan(self) -> None:
        (self.body_root / ".bra" / "approvals" / "LOCAL-SCAN").touch()

        class _FakeApi:
            def __init__(self) -> None:
                self.detect_calls = []
                self.saved = False
                self.added = None

            def detect(self, text: str):
                self.detect_calls.append(text)
                return [type("Detection", (), {"value": "10.0.0.1", "type_": "ip"})()]

            def add_mappings(self, detections, *, source: str) -> None:
                self.added = (detections, source)

            def save(self) -> None:
                self.saved = True

            def mask(self, text: str) -> str:
                return text.replace("10.0.0.1", "FALCON")

        fake_api = _FakeApi()
        with patch.object(boots_main, "_get_anon_api", return_value=(fake_api, None)):
            result = boots_main._anon_mask_chat("Target 10.0.0.1 is reachable")

        self.assertEqual(fake_api.detect_calls, ["Target 10.0.0.1 is reachable"])
        self.assertIsNotNone(fake_api.added)
        self.assertEqual(fake_api.added[1], "chat-input")
        self.assertTrue(fake_api.saved)
        self.assertEqual(result, "Target FALCON is reachable")

    def test_get_active_chat_token_defaults_map_scan(self) -> None:
        self.assertEqual(boots_main._get_active_chat_token(), "MAP-SCAN")

    def test_anon_disable_forces_main_helpers_to_noop(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"}]
        )
        approvals_dir = self.body_root / ".bra" / "approvals"
        (approvals_dir / "MAP-SCAN").touch()
        (approvals_dir / "ANON-DISABLE").touch()

        masked = boots_main._anon_mask_chat("Connect to 10.0.0.1 now")
        unmasked, highlights = boots_main._anon_unmask_content("Connect to FALCON now")

        self.assertEqual(masked, "Connect to 10.0.0.1 now")
        self.assertEqual(unmasked, "Connect to FALCON now")
        self.assertEqual(highlights, [])

    def test_anon_unmask_content_returns_highlights(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"}]
        )

        unmasked, highlights = boots_main._anon_unmask_content("Connect to FALCON now")

        self.assertEqual(unmasked, "Connect to 10.0.0.1 now")
        self.assertEqual(highlights, [{"real": "10.0.0.1", "type": "ip"}])

    def test_get_and_set_anon_config_switches_tokens(self) -> None:
        approvals_dir = self.body_root / ".bra" / "approvals"
        (approvals_dir / "FRONTIER-SCOPE").touch()
        (approvals_dir / "MAP-SCAN").touch()

        before = asyncio.run(boots_main.get_anon_config(True))
        self.assertEqual(before["scope_token"], "FRONTIER-SCOPE")
        self.assertEqual(before["chat_token"], "MAP-SCAN")

        updated = asyncio.run(
            boots_main.set_anon_config(
                _FakeRequest({"scope_token": "MICRO-SCOPE", "chat_token": "ANON-SCAN"}),
                True,
            )
        )

        self.assertEqual(updated["scope_token"], "MICRO-SCOPE")
        self.assertEqual(updated["chat_token"], "ANON-SCAN")
        self.assertTrue((approvals_dir / "MICRO-SCOPE").exists())
        self.assertTrue((approvals_dir / "ANON-SCAN").exists())
        self.assertFalse((approvals_dir / "FRONTIER-SCOPE").exists())
        self.assertFalse((approvals_dir / "MAP-SCAN").exists())

    def test_set_anon_config_bootstraps_anon_map_for_scope_intake(self) -> None:
        approvals_dir = self.body_root / ".bra" / "approvals"
        map_path = self.body_root / ".bra" / "anon_map.json"

        self.assertFalse(map_path.exists())

        updated = asyncio.run(
            boots_main.set_anon_config(
                _FakeRequest({"scope_token": "DUMB-SCOPE", "chat_token": "ANON-SCAN"}),
                True,
            )
        )

        self.assertEqual(updated["scope_token"], "DUMB-SCOPE")
        self.assertEqual(updated["chat_token"], "ANON-SCAN")
        self.assertTrue((approvals_dir / "DUMB-SCOPE").exists())
        self.assertTrue((approvals_dir / "ANON-SCAN").exists())
        self.assertTrue(map_path.exists())
        map_data = json.loads(map_path.read_text(encoding="utf-8"))
        self.assertEqual(map_data["version"], 1)
        self.assertEqual(map_data["mappings"], [])

    def test_get_anon_api_enables_local_model_endpoint(self) -> None:
        boots_main.load_config = lambda: {"local_model_endpoint": "http://127.0.0.1:11434/v1"}

        api, err = boots_main._get_anon_api()

        self.assertIsNone(err)
        self.assertIsNotNone(api)
        self.assertEqual(api._ner._config.local_model, "http://127.0.0.1:11434/v1")
        self.assertTrue(api._ner._config.enabled)

    def test_micro_scope_detection_does_not_use_endpoint_config(self) -> None:
        boots_main._NER_ENABLED = True
        self.addCleanup(setattr, boots_main, "_NER_ENABLED", False)
        boots_main.load_config = lambda: {
            "ner_endpoint": "http://127.0.0.1:8080/ner",
            "local_model_endpoint": "http://127.0.0.1:11434/api/generate",
        }

        with patch.object(
            boots_main,
            "_get_anon_api",
            side_effect=AssertionError("regex-plus-local should not call _get_anon_api"),
        ):
            result = asyncio.run(
                boots_main.anon_detect(
                    _FakeRequest({"text": "Host 10.0.0.1", "mode": "regex-plus-local"}),
                    True,
                )
            )

        self.assertIn("proposals", result)

    def test_get_anon_mappings_returns_summary_metadata(self) -> None:
        self._write_map(
            [
                {"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope", "created": "2026-03-06T00:00:01Z"},
                {"real": "db01", "anon": "CASTLE", "type": "operator-flagged", "source": "manual", "created": "2026-03-06T00:00:02Z"},
            ]
        )

        result = asyncio.run(boots_main.get_anon_mappings(True))

        self.assertEqual(result["created"], "2026-03-06T00:00:00Z")
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["counts_by_type"]["ip"], 1)
        self.assertEqual(result["counts_by_type"]["operator-flagged"], 1)

    def test_send_chat_masks_message_before_queueing(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"}]
        )
        (self.body_root / ".bra" / "approvals" / "MAP-SCAN").touch()

        original_chat_file = boots_main.CHAT_FILE
        boots_main.CHAT_FILE = self.body_root / ".bra" / "ui" / "chat.json"
        boots_main.CHAT_FILE.parent.mkdir(parents=True, exist_ok=True)
        boots_main.save_chat({"messages": [], "pending": []})
        self.addCleanup(lambda: setattr(boots_main, "CHAT_FILE", original_chat_file))

        result = asyncio.run(boots_main.send_chat({"message": "Connect to 10.0.0.1 now"}, True))

        self.assertEqual(result["status"], "queued")
        self.assertIn("FALCON", result["message"]["content"])
        self.assertNotIn("10.0.0.1", result["message"]["content"])

    def test_get_engagement_unmasks_scope_and_returns_highlights(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "scope"}]
        )
        scope_dir = self.body_root / "layer3-engagement"
        scope_dir.mkdir(parents=True)
        (scope_dir / "SCOPE.md").write_text(
            "**Name:** Target\n\n### Targets\n- FALCON\n",
            encoding="utf-8",
        )

        result = asyncio.run(boots_main.get_engagement(True))

        self.assertEqual(result["scope"]["raw"], "**Name:** Target\n\n### Targets\n- 10.0.0.1\n")
        self.assertEqual(result["anon_highlights"], [{"real": "10.0.0.1", "type": "ip"}])

    def test_get_engagement_reports_project_root_not_parent_directory(self) -> None:
        result = asyncio.run(boots_main.get_engagement(True))

        self.assertEqual(result["bra_path"], str(self.project_root))

    def test_get_report_unmasks_content_and_returns_highlights(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "report"}]
        )
        report_dir = self.body_root / "layer3-engagement"
        report_dir.mkdir(parents=True)
        (report_dir / "REPORT.md").write_text(
            "# Report\n\nAffected host: FALCON\n",
            encoding="utf-8",
        )

        result = asyncio.run(boots_main.get_report(True))

        self.assertTrue(result["engagement_report"]["exists"])
        self.assertIn("10.0.0.1", result["engagement_report"]["content"])
        self.assertEqual(result["anon_highlights"], [{"real": "10.0.0.1", "type": "ip"}])

    def test_precheck_schema_mirror_knows_anon_map_json(self) -> None:
        precheck = (REPO_ROOT / "body" / "layer1" / "scripts" / "precheck.py").read_text(encoding="utf-8")

        self.assertIn('"anon_map.json"', precheck)

    def test_get_leads_unmasks_content_and_returns_highlights(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "leads"}]
        )
        notes_dir = self.body_root / "layer3-engagement" / "NOTES"
        notes_dir.mkdir(parents=True)
        (notes_dir / "LEADS.md").write_text(
            "# Leads\n\n| ID | Lead | Priority | Rationale | Status |\n| --- | --- | --- | --- | --- |\n| 001 | Reach FALCON | high | check host | open |\n",
            encoding="utf-8",
        )

        result = asyncio.run(boots_main.get_leads(True))

        self.assertTrue(result["exists"])
        self.assertIn("10.0.0.1", result["parsed"]["raw"])
        self.assertEqual(result["anon_highlights"], [{"real": "10.0.0.1", "type": "ip"}])

    def test_get_intel_unmasks_content_and_returns_highlights(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "intel"}]
        )
        notes_dir = self.body_root / "layer3-engagement" / "NOTES"
        notes_dir.mkdir(parents=True)
        (notes_dir / "INTEL.md").write_text(
            "**Date:** 2026-03-06\n**Target:** FALCON\n\n## Summary\nHost FALCON observed.\n",
            encoding="utf-8",
        )

        result = asyncio.run(boots_main.get_intel(True))

        self.assertTrue(result["exists"])
        self.assertIn("10.0.0.1", result["parsed"]["raw"])
        self.assertEqual(result["anon_highlights"], [{"real": "10.0.0.1", "type": "ip"}])

    def test_get_findings_unmasks_content_and_returns_highlights(self) -> None:
        self._write_map(
            [{"real": "10.0.0.1", "anon": "FALCON", "type": "ip", "source": "findings"}]
        )
        notes_dir = self.body_root / "layer3-engagement" / "NOTES"
        notes_dir.mkdir(parents=True)
        (notes_dir / "FINDINGS.md").write_text(
            "### [HIGH] Host FALCON issue\n**Short description:** Service on FALCON leaks data.\n",
            encoding="utf-8",
        )

        result = asyncio.run(boots_main.get_findings(True))

        self.assertEqual(result["anon_highlights"], [{"real": "10.0.0.1", "type": "ip"}])

    def test_get_telemetry_reads_from_body_root(self) -> None:
        notes_dir = self.body_root / "layer3-engagement" / "NOTES"
        notes_dir.mkdir(parents=True)
        (self.body_root / ".bra" / "artifacts").mkdir(parents=True, exist_ok=True)
        (notes_dir / "FINDINGS.md").write_text(
            "## [FINDING-001] Alpha\n| **Severity** | High |\n",
            encoding="utf-8",
        )
        (self.body_root / ".bra" / "artifacts" / "manifest.json").write_text(
            '{"artifacts":[]}',
            encoding="utf-8",
        )

        result = asyncio.run(boots_main.get_telemetry(True))

        self.assertTrue(result["exists"])
        self.assertEqual(result["live"]["findings"]["total"], 1)


if __name__ == "__main__":
    unittest.main()
