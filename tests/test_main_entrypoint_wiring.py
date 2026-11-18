from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from starlette.requests import Request

from boots import main


def _make_project_root() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    body = root / "body"
    (body / ".bra").mkdir(parents=True, exist_ok=True)
    (body / "layer3-engagement" / "pitches").mkdir(parents=True, exist_ok=True)
    return td, root


def _request_with_lease(lease_id: str) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/2x4/engage-status",
        "headers": [(b"x-2x4-lease-id", lease_id.encode("utf-8"))],
    }
    return Request(scope)


class MainEntrypointWiringTests(unittest.IsolatedAsyncioTestCase):
    def test_2x4_connect_params_include_signed_device_identity_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            identity_dir = Path(td)
            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            (identity_dir / "device.json").write_text(
                json.dumps(
                    {
                        "deviceId": "device-123",
                        "publicKeyPem": public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        ).decode("utf-8"),
                        "privateKeyPem": private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption(),
                        ).decode("utf-8"),
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(main, "_resolve_numbuh_2x4_identity_dir", return_value=identity_dir):
                params = main._build_numbuh_2x4_connect_params("token-123", "nonce-abc")

            self.assertEqual(params["auth"], {"token": "token-123"})
            self.assertEqual(params["device"]["id"], "device-123")
            self.assertEqual(params["device"]["nonce"], "nonce-abc")
            self.assertIn("publicKey", params["device"])
            self.assertIn("signature", params["device"])
            self.assertIn("signedAt", params["device"])

    def test_resolve_bra_roots_prefers_body_state_when_both_exist(self) -> None:
        td, root = _make_project_root()
        with td:
            (root / ".bra").mkdir(parents=True, exist_ok=True)

            resolved = main._resolve_bra_body_and_project_roots(root)

            self.assertIsNotNone(resolved)
            body_root, project_root = resolved
            self.assertEqual(body_root.resolve(), (root / "body").resolve())
            self.assertEqual(project_root.resolve(), root.resolve())

    async def test_ingest_endpoint_runs_python_port(self) -> None:
        td, root = _make_project_root()
        pitch_file = root / "body" / "layer3-engagement" / "pitches" / "demo.md"
        pitch_file.write_text("# demo\n")
        with (
            td,
            patch.object(main, "get_bra_dir", return_value=str(root)),
            patch("bra.config.settings.set_bra_root"),
            patch(
                "bra.core.bridge.run_script",
                return_value=SimpleNamespace(returncode=0, stdout='{"status":"ok","message":"ingested"}\n', stderr=""),
            ) as run_script,
        ):
            payload = await main.ingest_pitches("demo.md", _=True)

            run_script.assert_called_once_with("ingest.py", str(pitch_file), timeout=30)
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["message"], "ingested")

    async def test_2x4_file_reads_allowlisted_file_from_body_root(self) -> None:
        td, root = _make_project_root()
        scope_file = root / "body" / "layer3-engagement" / "SCOPE.md"
        scope_file.write_text("# Scope\nalpha\n")
        with td, patch.object(main, "get_bra_dir", return_value=str(root)):
            payload = await main.get_2x4_file(name="scope", _=True)

            self.assertEqual(payload["name"], "scope")
            self.assertEqual(Path(payload["path"]).resolve(), scope_file.resolve())
            self.assertIn("alpha", payload["content"])

    async def test_2x4_engage_status_returns_state_when_lease_matches(self) -> None:
        controller = SimpleNamespace(
            reconcile_timeouts=lambda: None,
            state="takeover_active",
            active=True,
            takeover_lease_id="lease-123",
            active_expires_at=99.0,
        )
        with (
            patch.object(main, "_resolve_2x4_controller_from_config", return_value=controller),
            patch.object(main._engage_manager, "get_state", return_value={"status": "running"}),
        ):
            payload = await main.get_2x4_engage_status(_request_with_lease("lease-123"), _=True)

            self.assertEqual(payload["engage"], {"status": "running"})
            self.assertEqual(payload["takeover"]["lease_id"], "lease-123")

    async def test_2x4_token_sync_uses_body_approvals_for_project_root(self) -> None:
        td, root = _make_project_root()
        with td:
            (root / ".bra" / "approvals").mkdir(parents=True, exist_ok=True)
            config = {
                "numbuh_2x4_enabled": True,
                "numbuh_2x4_ws_url": "ws://localhost:18789",
                "numbuh_2x4_token": "chat-token",
                "voice_call_public_url": "https://voice.example.test/webhook",
                "voice_call_control_boots_base_url": "http://127.0.0.1:7090",
                "voice_call_control_boots_service_token": "voice-token",
            }
            with patch.object(main, "NUMBUH_2X4_SERVICE_TOKEN", "control-token"):
                states = main._sync_2x4_governance_tokens(root, config=config)

            self.assertEqual(
                states,
                {
                    "2x4-ENABLED": True,
                    "2x4-CONTROL": True,
                    "2x4-VOICE-CALL": True,
                },
            )
            for token in ("2x4-ENABLED", "2x4-CONTROL", "2x4-VOICE-CALL"):
                self.assertTrue((root / "body" / ".bra" / "approvals" / token).exists())
                self.assertFalse((root / ".bra" / "approvals" / token).exists())

    async def test_2x4_token_sync_allows_body_root_input(self) -> None:
        td, root = _make_project_root()
        with td:
            config = {
                "numbuh_2x4_enabled": True,
                "numbuh_2x4_ws_url": "ws://localhost:18789",
                "numbuh_2x4_token": "chat-token",
            }
            with patch.object(main, "NUMBUH_2X4_SERVICE_TOKEN", "control-token"):
                states = main._sync_2x4_governance_tokens(root / "body", config=config)

            self.assertTrue(states["2x4-ENABLED"])
            self.assertTrue(states["2x4-CONTROL"])
            self.assertTrue((root / "body" / ".bra" / "approvals" / "2x4-ENABLED").exists())
            self.assertTrue((root / "body" / ".bra" / "approvals" / "2x4-CONTROL").exists())

    async def test_2x4_token_sync_noops_without_body_bra(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".bra" / "approvals").mkdir(parents=True, exist_ok=True)
            config = {
                "numbuh_2x4_enabled": True,
                "numbuh_2x4_ws_url": "ws://localhost:18789",
                "numbuh_2x4_token": "chat-token",
            }
            with patch.object(main, "NUMBUH_2X4_SERVICE_TOKEN", "control-token"):
                states = main._sync_2x4_governance_tokens(root, config=config)

            self.assertEqual(states, {})
            self.assertFalse((root / ".bra" / "approvals" / "2x4-ENABLED").exists())
            self.assertFalse((root / ".bra" / "approvals" / "2x4-CONTROL").exists())

    async def test_get_config_defaults_existing_2x4_agent_modes_to_openclaw(self) -> None:
        with (
            patch.object(main, "load_config", return_value={"chat_provider": "numbuh_2x4_ws"}),
            patch.object(main, "get_bra_dir", return_value=""),
        ):
            payload = await main.get_config(_=True)

        self.assertEqual(payload["numbuh_2x4_agent_provider"], "openclaw")
        self.assertEqual(payload["numbuh_2x4_call_agent_provider"], "openclaw")

    async def test_get_config_normalizes_hermes_2x4_agent_modes(self) -> None:
        with (
            patch.object(
                main,
                "load_config",
                return_value={
                    "numbuh_2x4_agent_provider": "hermes",
                    "numbuh_2x4_call_agent_provider": "hermes",
                },
            ),
            patch.object(main, "get_bra_dir", return_value=""),
        ):
            payload = await main.get_config(_=True)

        self.assertEqual(payload["numbuh_2x4_agent_provider"], "hermes")
        self.assertEqual(payload["numbuh_2x4_call_agent_provider"], "hermes")

    async def test_set_config_persists_2x4_agent_modes_and_rejects_unknown_values(self) -> None:
        saved: dict[str, object] = {}

        def fake_save_config(config: dict) -> None:
            saved.update(config)

        with (
            patch.object(main, "load_config", return_value={}),
            patch.object(main, "save_config", side_effect=fake_save_config),
            patch.object(main, "get_bra_dir", return_value=""),
        ):
            await main.set_config(
                {
                    "numbuh_2x4_agent_provider": "hermes",
                    "numbuh_2x4_call_agent_provider": "bogus",
                },
                _=True,
            )

        self.assertEqual(saved["numbuh_2x4_agent_provider"], "hermes")
        self.assertEqual(saved["numbuh_2x4_call_agent_provider"], "openclaw")

    def test_build_hermes_chat_request_uses_base_url_key_and_session_key(self) -> None:
        url, headers, body = main._build_2x4_hermes_chat_request(
            {
                "numbuh_2x4_hermes_base_url": "http://127.0.0.1:8765/",
                "numbuh_2x4_hermes_api_key": "api-key",
                "numbuh_2x4_hermes_session_key": "bra-debug",
            },
            "hello",
            "fallback-session",
        )

        self.assertEqual(url, "http://127.0.0.1:8765/v1/chat/completions")
        self.assertEqual(headers["authorization"], "Bearer api-key")
        self.assertEqual(headers["x-hermes-session-key"], "bra-debug")
        self.assertEqual(body["messages"], [{"role": "user", "content": "hello"}])
        self.assertFalse(body["stream"])

    def test_extract_hermes_chat_response_supports_chat_completions_shape(self) -> None:
        content = main._extract_hermes_chat_response(
            {"choices": [{"message": {"content": "Hermes here."}}]}
        )

        self.assertEqual(content, "Hermes here.")

    async def test_hermes_debug_chat_intercepts_bra_summary_command(self) -> None:
        sent: list[dict] = []

        async def send_browser(payload: dict) -> None:
            sent.append(payload)

        with patch.object(
            main,
            "get_2x4_summary",
            return_value={"engage": {"status": "idle"}, "takeover": {"state": "standby"}},
        ):
            handled = await main._maybe_intercept_2x4_debug_command(
                "/bra summary",
                "run-123",
                send_browser,
            )

        self.assertTrue(handled)
        self.assertEqual(sent[0]["type"], "assistant.message")
        self.assertEqual(sent[0]["id"], "run-123")
        self.assertIn('"status": "idle"', sent[0]["content"])

    async def test_hermes_debug_chat_intercepts_bra_summ_alias(self) -> None:
        sent: list[dict] = []

        async def send_browser(payload: dict) -> None:
            sent.append(payload)

        with patch.object(
            main,
            "get_2x4_summary",
            return_value={"engage": {"status": "idle"}, "takeover": {"state": "standby"}},
        ):
            handled = await main._maybe_intercept_2x4_debug_command(
                "/bra-summ",
                "run-456",
                send_browser,
            )

        self.assertTrue(handled)
        self.assertEqual(sent[0]["id"], "run-456")
        self.assertIn('"takeover"', sent[0]["content"])

    async def test_hermes_debug_chat_ignores_normal_chat(self) -> None:
        sent: list[dict] = []

        async def send_browser(payload: dict) -> None:
            sent.append(payload)

        handled = await main._maybe_intercept_2x4_debug_command(
            "hello",
            "run-123",
            send_browser,
        )

        self.assertFalse(handled)
        self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()
