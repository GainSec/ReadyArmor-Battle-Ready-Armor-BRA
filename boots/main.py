#!/usr/bin/env python3
"""
BRA Web GUI - FastAPI Backend
Phase 1 MVP: Read-only dashboard for Battle Ready Armor engagements
"""

import asyncio
import base64
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request as UrlRequest, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from bra.anon.api import AnonAPI
from bra.config.settings import get_proxy_config, set_runtime_config
from bra.debug_log import write_debug_log
from boots.harness.base import get_registry, get_harness
from boots.takeover import TakeoverController, get_takeover_controller
from boots.verbose import install as _install_verbose_tracing; _install_verbose_tracing()

try:
    import websockets  # type: ignore[import-untyped]
except Exception:
    websockets = None  # type: ignore[assignment]

# Configuration
DEFAULT_PORT = 9999
TOKEN_FILE = ".bra-gui-token"
AUTH_COOKIE_NAME = "bra_gui_session"
DOCS_SESSION_COOKIE_NAME = "docs_session"
DEBUG_SESSION_COOKIE_NAME = "debug_session"
AUTH_COOKIE_MAX_AGE = 60 * 60 * 24 * 30
NUMBUH_2X4_SERVICE_TOKEN_FILE = ".bra-gui-2x4-service-token"
DOCS_PASSWORD_FILE = ".bra-gui-docs-password"
DEBUG_PASSWORD_FILE = ".bra-gui-debug-password"
DOCS_HIDDEN_FILENAMES = {"integrate-ingest.md", "remote-ingest.md"}
BRA_DIR = os.environ.get("BRA_DIR", "")
CONFIG_FILE = Path(__file__).parent / ".bra-gui-config.json"
CHAT_PROVIDER_LEGACY = "legacy_api"
CHAT_PROVIDER_NUMBUH_2X4_WS = "numbuh_2x4_ws"
CHAT_PROVIDER_OPENCLAW_WS_LEGACY = "openclaw_ws"
CHAT_PROVIDER_ALLOWED = {
    CHAT_PROVIDER_LEGACY,
    CHAT_PROVIDER_NUMBUH_2X4_WS,
    CHAT_PROVIDER_OPENCLAW_WS_LEGACY,
}
NUMBUH_2X4_AGENT_PROVIDER_OPENCLAW = "openclaw"
NUMBUH_2X4_AGENT_PROVIDER_HERMES = "hermes"
NUMBUH_2X4_AGENT_PROVIDER_ALLOWED = {
    NUMBUH_2X4_AGENT_PROVIDER_OPENCLAW,
    NUMBUH_2X4_AGENT_PROVIDER_HERMES,
}
VOICE_CALL_PROVIDER_MOCK = "mock"
VOICE_CALL_PROVIDER_TWILIO = "twilio"
VOICE_CALL_PROVIDER_ALLOWED = {
    VOICE_CALL_PROVIDER_MOCK,
    VOICE_CALL_PROVIDER_TWILIO,
}
NUMBUH_2X4_PROTOCOL_VERSION = 3
NUMBUH_2X4_CONNECT_TIMEOUT_SEC = 8
NUMBUH_2X4_REQUEST_TIMEOUT_SEC = 90
NUMBUH_2X4_DEFAULT_SESSION_KEY = "agent:main:main"
NUMBUH_2X4_CONNECT_SCOPES = [
    "operator.admin",
    "operator.read",
    "operator.write",
    "operator.pairing",
    "operator.approvals",
]
NUMBUH_2X4_FILE_ALLOWLIST = {
    "scope": "layer3-engagement/SCOPE.md",
    "stats": "layer3-engagement/STATS.md",
    "report": "layer3-engagement/REPORT.md",
    "findings": "layer3-engagement/NOTES/FINDINGS.md",
    "precheck": ".bra/PRECHECK_REPORT.md",
}
NUMBUH_2X4_LOG_ALLOWLIST = {
    "engage": "engage.log",
}
TOKEN_2X4_ENABLED = "2x4-ENABLED"
TOKEN_2X4_CONTROL = "2x4-CONTROL"
TOKEN_2X4_VOICE_CALL = "2x4-VOICE-CALL"


def _resolve_bra_body_and_project_roots(path_input: str | Path) -> tuple[Path, Path] | None:
    """Resolve BRA body + project roots from either body-root or project-root input."""
    candidate = Path(path_input).expanduser().resolve()
    if not candidate.exists():
        return None

    if (candidate / "body" / ".bra").exists():
        body_root = candidate / "body"
    elif (candidate / ".bra").exists():
        body_root = candidate
    else:
        return None

    project_root = body_root.parent if body_root.name == "body" else body_root
    return body_root, project_root


def _body_root(bra_dir: str | Path) -> Path:
    """Get body root from project root. Returns project/body if it exists, else project."""
    p = Path(bra_dir)
    body = p / "body"
    return body if body.is_dir() else p


def _debug(event: str, *, bra_root: str | None = None, **fields) -> None:
    resolved_root = bra_root if bra_root is not None else (get_bra_dir() or "")
    if resolved_root:
        root = _body_root(resolved_root)
        approvals_dir = root / ".bra" / "approvals"
        logs_dir = root / ".bra" / "logs"
    else:
        approvals_dir = Path(".bra") / "approvals"
        logs_dir = Path(".bra") / "logs"
    write_debug_log(
        "main",
        event,
        approvals_dir=approvals_dir,
        logs_dir=logs_dir,
        **fields,
    )

def load_config():
    """Load saved configuration."""
    _debug("load_config_start", config_file=str(CONFIG_FILE), exists=CONFIG_FILE.exists(), bra_root=BRA_DIR or "")
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text())
            _debug("load_config_ok", keys=sorted(data.keys()), bra_root=BRA_DIR or "")
            return data
        except:
            _debug("load_config_error", bra_root=BRA_DIR or "")
            pass
    _debug("load_config_empty", bra_root=BRA_DIR or "")
    return {}

def save_config(config):
    """Save configuration."""
    CONFIG_FILE.write_text(json.dumps(config, indent=2))
    _debug("save_config", keys=sorted(config.keys()), bra_root=BRA_DIR or "")


def _mask_api_key(key: str | None) -> str | None:
    """Return a short, non-sensitive API key preview."""
    if not key:
        return None
    trimmed = key.strip()
    if len(trimmed) <= 10:
        return "*" * len(trimmed)
    return f"{trimmed[:6]}...{trimmed[-4:]}"


def _preview_prompt(prompt: str | None) -> str | None:
    """Return a short preview for hidden prompt text without exposing full content."""
    if not prompt:
        return None
    trimmed = str(prompt).strip()
    if not trimmed:
        return None
    if len(trimmed) <= 48:
        return trimmed
    return f"{trimmed[:45]}..."


def _normalize_chat_provider(raw: str | None) -> str:
    """Normalize configured chat provider to a supported value."""
    provider = (raw or "").strip().lower()
    if provider in {CHAT_PROVIDER_NUMBUH_2X4_WS, CHAT_PROVIDER_OPENCLAW_WS_LEGACY}:
        return CHAT_PROVIDER_NUMBUH_2X4_WS
    if provider == CHAT_PROVIDER_LEGACY:
        return CHAT_PROVIDER_LEGACY
    return CHAT_PROVIDER_LEGACY


def _normalize_2x4_agent_provider(raw: str | None) -> str:
    """Normalize the 2x4 upstream agent choice for chat/call modes."""
    provider = (raw or "").strip().lower()
    if provider in NUMBUH_2X4_AGENT_PROVIDER_ALLOWED:
        return provider
    return NUMBUH_2X4_AGENT_PROVIDER_OPENCLAW


def _resolve_numbuh_2x4_settings(config: dict) -> tuple[bool, str, str]:
    """Resolve Numbuh 2x4 settings, honoring legacy OpenClaw keys."""
    enabled = config.get("numbuh_2x4_enabled")
    if enabled is None:
        enabled = config.get("openclaw_enabled", False)
    ws_url = config.get("numbuh_2x4_ws_url")
    if ws_url is None:
        ws_url = config.get("openclaw_ws_url", "")
    token = config.get("numbuh_2x4_token")
    if token is None:
        token = config.get("openclaw_token", "")
    return bool(enabled), str(ws_url or "").strip(), str(token or "").strip()


def _resolve_numbuh_2x4_takeover_prompt(config: dict) -> str:
    """Resolve hidden takeover prompt text, honoring legacy OpenClaw alias."""
    prompt = config.get("numbuh_2x4_takeover_prompt")
    if prompt is None:
        prompt = config.get("openclaw_takeover_prompt", "")
    return str(prompt or "").strip()


def _normalize_voice_call_provider(raw: str | None) -> str:
    """Normalize voice-call provider to a supported value."""
    provider = str(raw or "").strip().lower()
    if provider in VOICE_CALL_PROVIDER_ALLOWED:
        return provider
    return VOICE_CALL_PROVIDER_MOCK


def _is_2x4_chat_transport_configured(config: dict) -> bool:
    """Match the header 2x4 pill condition in the web UI."""
    enabled, ws_url, token = _resolve_numbuh_2x4_settings(config)
    return bool(enabled and ws_url and token)


def _is_2x4_control_configured() -> bool:
    """Match the header takeover-ready requirement in the web UI."""
    return bool(NUMBUH_2X4_SERVICE_TOKEN)


def _resolve_voice_call_control_boots_service_token(config: dict) -> str:
    """Resolve voice-call control token, defaulting to Boots runtime service token."""
    configured = str(config.get("voice_call_control_boots_service_token", "") or "").strip()
    if configured:
        return configured
    return str(NUMBUH_2X4_SERVICE_TOKEN or "").strip()


def _is_2x4_voice_call_configured(config: dict) -> bool:
    """Match the Settings > Current Configuration 2x4 Call status logic."""
    public_url = str(config.get("voice_call_public_url", "") or "").strip()
    boots_base_url = str(config.get("voice_call_control_boots_base_url", "") or "").strip()
    has_control_token = bool(_resolve_voice_call_control_boots_service_token(config))
    return bool(public_url and boots_base_url and has_control_token)


def _resolve_2x4_sync_body_root(path_input: str | Path | None) -> Path | None:
    """Resolve the canonical body root for 2x4 governance token sync only."""
    if not path_input:
        return None
    candidate = Path(path_input).expanduser().resolve()
    if not candidate.exists():
        return None
    if candidate.name == "body" and (candidate / ".bra").exists():
        return candidate
    body = candidate / "body"
    if (body / ".bra").exists():
        return body
    return None


def _sync_2x4_governance_tokens(
    bra_root: str | Path | None,
    *,
    config: dict | None = None,
) -> dict[str, bool]:
    """Auto-sync derived 2x4 governance tokens from current configuration."""
    if not bra_root:
        return {}
    body_root = _resolve_2x4_sync_body_root(bra_root)
    if body_root is None:
        return {}
    approvals_dir = body_root / ".bra" / "approvals"
    approvals_dir.mkdir(parents=True, exist_ok=True)

    cfg = config if config is not None else load_config()
    desired = {
        TOKEN_2X4_ENABLED: _is_2x4_chat_transport_configured(cfg),
        TOKEN_2X4_CONTROL: _is_2x4_control_configured(),
        TOKEN_2X4_VOICE_CALL: _is_2x4_voice_call_configured(cfg),
    }

    for token_name, should_set in desired.items():
        token_file = approvals_dir / token_name
        if should_set:
            token_file.touch(exist_ok=True)
        elif token_file.exists():
            token_file.unlink()

    return desired


def _normalize_governance_token_filename(name: str) -> str:
    """Normalize token file names while preserving 2x4 canonical casing."""
    normalized = str(name or "").strip().replace("_", "-")
    if not normalized:
        return ""
    uppercase = normalized.upper()
    if uppercase == "BRA-VERBOSE":
        return "BRA_VERBOSE"
    if uppercase.startswith("2X4-"):
        return f"2x4-{uppercase[len('2X4-'):]}"
    return uppercase


class GeneratedTokenRequest(BaseModel):
    family: str
    value: str


def _build_numbuh_2x4_upstream_ws_url(ws_url: str, token: str) -> str:
    """Normalize an upstream WS URL and inject token query when needed."""
    normalized = str(ws_url or "").strip()
    auth_token = str(token or "").strip()
    if not normalized:
        return ""
    if normalized.startswith("https://"):
        normalized = f"wss://{normalized[len('https://'):]}"
    elif normalized.startswith("http://"):
        normalized = f"ws://{normalized[len('http://'):]}"
    elif not normalized.lower().startswith(("ws://", "wss://")):
        normalized = f"ws://{normalized}"

    parsed = urlparse(normalized)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    has_auth_query = any(
        key.lower() in {"token", "auth", "api_key", "api-key"}
        for key, _ in query_pairs
    )
    if auth_token and not has_auth_query:
        query_pairs.append(("token", auth_token))
    return urlunparse(parsed._replace(query=urlencode(query_pairs, doseq=True)))


def _build_2x4_hermes_chat_request(
    config: dict,
    content: str,
    fallback_session_key: str,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Build an OpenAI-compatible Hermes chat request for the 2x4 relay."""
    base_url = str(config.get("numbuh_2x4_hermes_base_url") or "").strip().rstrip("/")
    if not base_url:
        raise RuntimeError("Hermes base URL is not configured.")

    session_key = (
        str(config.get("numbuh_2x4_hermes_session_key") or "").strip()
        or str(fallback_session_key or "").strip()
        or NUMBUH_2X4_DEFAULT_SESSION_KEY
    )
    api_key = str(config.get("numbuh_2x4_hermes_api_key") or "").strip()
    headers = {
        "content-type": "application/json",
        "x-hermes-session-key": session_key,
    }
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    body = {
        "messages": [{"role": "user", "content": content}],
        "stream": False,
    }
    return f"{base_url}/v1/chat/completions", headers, body


def _post_json_sync(
    url: str,
    headers: dict[str, str],
    body: dict[str, Any],
    *,
    timeout: float,
) -> dict[str, Any]:
    request = UrlRequest(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        text = response.read().decode("utf-8", errors="replace")
    return json.loads(text) if text.strip() else {}


def _extract_hermes_chat_response(payload: dict[str, Any]) -> str:
    """Extract assistant text from Hermes API response shapes."""
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str) and content.strip():
                    return content
            text = first.get("text")
            if isinstance(text, str) and text.strip():
                return text
    message = payload.get("message")
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            return content
    content = payload.get("content")
    if isinstance(content, str) and content.strip():
        return content
    raise RuntimeError("Hermes response did not include assistant content.")


async def _query_2x4_chat_via_hermes(
    config: dict,
    content: str,
    session_key: str,
    *,
    timeout: float = NUMBUH_2X4_REQUEST_TIMEOUT_SEC,
) -> str:
    url, headers, body = _build_2x4_hermes_chat_request(config, content, session_key)
    payload = await asyncio.to_thread(
        _post_json_sync,
        url,
        headers,
        body,
        timeout=timeout,
    )
    return _extract_hermes_chat_response(payload)


def _validate_numbuh_2x4_client_payload(payload: dict[str, Any]) -> tuple[bool, str]:
    """Validate browser -> relay chat payloads before forwarding upstream."""
    if not isinstance(payload, dict):
        return False, "Payload must be a JSON object."
    msg_type = str(payload.get("type", "")).strip().lower()
    if msg_type == "ping":
        return True, ""
    if msg_type != "chat.message":
        return False, f"Unsupported message type: {msg_type or '(missing)'}"

    role = str(payload.get("role", "user")).strip().lower()
    if role and role != "user":
        return False, "Only user chat messages are accepted by relay."

    content = payload.get("content")
    if not isinstance(content, str) or not content.strip():
        return False, "chat.message payload must include non-empty content."
    if len(content) > 4000:
        return False, "chat.message content exceeds 4000 characters."
    return True, ""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _resolve_numbuh_2x4_identity_dir() -> Path:
    return Path.home() / ".openclaw" / "identity"


def _load_numbuh_2x4_device_identity(
    auth_token: str,
    nonce: str,
    *,
    signed_at_ms: int | None = None,
) -> dict[str, Any] | None:
    identity_dir = _resolve_numbuh_2x4_identity_dir()
    device_file = identity_dir / "device.json"
    if not device_file.exists():
        return None

    try:
        device_data = json.loads(device_file.read_text())
        device_id = str(device_data.get("deviceId") or "").strip()
        public_key_pem = str(device_data.get("publicKeyPem") or "").strip()
        private_key_pem = str(device_data.get("privateKeyPem") or "").strip()
        if not device_id or not public_key_pem or not private_key_pem or not nonce:
            return None

        signed_at = int(signed_at_ms if signed_at_ms is not None else round(time.time() * 1000))
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None,
        )
        if not isinstance(private_key, Ed25519PrivateKey):
            return None

        public_key_raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        signature_payload = "|".join(
            [
                "v3",
                device_id,
                "gateway-client",
                "backend",
                "operator",
                ",".join(NUMBUH_2X4_CONNECT_SCOPES),
                str(signed_at),
                str(auth_token or "").strip(),
                nonce,
                sys.platform or "unknown",
                "",
            ]
        )
        signature = private_key.sign(signature_payload.encode("utf-8"))
        return {
            "id": device_id,
            "publicKey": _b64url_encode(public_key_raw),
            "signature": _b64url_encode(signature),
            "signedAt": signed_at,
            "nonce": nonce,
        }
    except Exception:
        return None


def _build_numbuh_2x4_connect_params(auth_token: str, nonce: str = "") -> dict[str, Any]:
    """Build OpenClaw gateway connect params for relay sessions."""
    token = str(auth_token or "").strip()
    params: dict[str, Any] = {
        "minProtocol": NUMBUH_2X4_PROTOCOL_VERSION,
        "maxProtocol": NUMBUH_2X4_PROTOCOL_VERSION,
        "client": {
            "id": "gateway-client",
            "mode": "backend",
            "version": "boots-relay",
            "platform": sys.platform or "unknown",
        },
        "role": "operator",
        "scopes": list(NUMBUH_2X4_CONNECT_SCOPES),
        "caps": [],
    }
    if token:
        params["auth"] = {"token": token}
    device = _load_numbuh_2x4_device_identity(token, str(nonce or "").strip())
    if device:
        params["device"] = device
    return params


def _extract_numbuh_2x4_text(content: Any) -> str:
    """Extract plain text from OpenClaw chat content blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        text = content.get("text")
        if isinstance(text, str):
            return text
        nested = content.get("content")
        if nested is not None:
            return _extract_numbuh_2x4_text(nested)
        return ""
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if isinstance(item, dict):
                if item.get("type") == "text" and isinstance(item.get("text"), str):
                    parts.append(item["text"])
                    continue
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "".join(parts)
    return ""


def _resolve_numbuh_2x4_session_key(hello_payload: dict[str, Any] | None) -> str:
    """Resolve default chat session key from hello payload snapshot."""
    if not isinstance(hello_payload, dict):
        return NUMBUH_2X4_DEFAULT_SESSION_KEY
    snapshot = hello_payload.get("snapshot")
    if not isinstance(snapshot, dict):
        return NUMBUH_2X4_DEFAULT_SESSION_KEY
    defaults = snapshot.get("sessionDefaults")
    if not isinstance(defaults, dict):
        return NUMBUH_2X4_DEFAULT_SESSION_KEY
    key = str(defaults.get("mainSessionKey") or "").strip()
    return key or NUMBUH_2X4_DEFAULT_SESSION_KEY


def _map_numbuh_2x4_event_to_browser_messages(frame: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert OpenClaw event frames to browser chat payloads."""
    if not isinstance(frame, dict):
        return []
    if str(frame.get("type") or "").lower() != "event":
        return []
    if str(frame.get("event") or "").lower() != "chat":
        return []
    payload = frame.get("payload")
    if not isinstance(payload, dict):
        return []

    run_id = str(payload.get("runId") or "").strip() or uuid.uuid4().hex
    state = str(payload.get("state") or "").strip().lower()
    message = payload.get("message")
    message_obj = message if isinstance(message, dict) else {}
    text = _extract_numbuh_2x4_text(message_obj.get("content"))
    if not text:
        text = _extract_numbuh_2x4_text(message_obj.get("text"))
    error_message = str(payload.get("errorMessage") or "").strip()
    if not text and state == "error" and error_message:
        text = error_message
    if not text:
        return []

    if state == "delta":
        return [{"type": "assistant.delta", "id": run_id, "delta": text}]
    if state in {"final", "error", "aborted"}:
        return [
            {
                "type": "assistant.message",
                "id": run_id,
                "role": "assistant",
                "content": text,
                "done": True,
            }
        ]
    return []


def _build_2x4_takeover_query_message(hidden_instruction: str, context: dict[str, Any]) -> str:
    """Compose a bounded takeover decision prompt with machine-readable context."""
    context_json = json.dumps(context, sort_keys=True, separators=(",", ":"))
    return (
        f"{hidden_instruction.strip()}\n\n"
        "Return one strict JSON action object only.\n"
        f"Context:\n{context_json}"
    )


async def _query_2x4_structured_action_via_gateway(payload: dict[str, Any]) -> str:
    """Query upstream gateway for one structured takeover action response."""
    ws_url = str(payload.get("ws_url") or "").strip()
    token = str(payload.get("token") or "").strip()
    hidden_instruction = str(payload.get("hidden_instruction") or "").strip()
    context = payload.get("context")
    if not ws_url or not token or not hidden_instruction or not isinstance(context, dict):
        raise RuntimeError("2x4 gateway query settings incomplete")

    upstream_url = _build_numbuh_2x4_upstream_ws_url(ws_url, token)
    if not upstream_url:
        raise RuntimeError("2x4 gateway upstream URL invalid")
    if websockets is None:
        raise RuntimeError("Relay dependency missing: websockets.")

    async with websockets.connect(
        upstream_url,
        open_timeout=10,
        ping_interval=20,
        ping_timeout=20,
        max_size=2_000_000,
    ) as upstream_ws:
        loop = asyncio.get_running_loop()
        pending_responses: dict[str, asyncio.Future] = {}
        buffered_responses: dict[str, dict[str, Any]] = {}
        challenge_future: asyncio.Future = loop.create_future()
        final_text_future: asyncio.Future = loop.create_future()
        default_session_key = NUMBUH_2X4_DEFAULT_SESSION_KEY

        async def _upstream_request(
            method: str,
            params: dict[str, Any],
            *,
            timeout: float = NUMBUH_2X4_REQUEST_TIMEOUT_SEC,
        ) -> dict[str, Any]:
            req_id = uuid.uuid4().hex
            future = loop.create_future()
            pending_responses[req_id] = future
            buffered = buffered_responses.pop(req_id, None)
            if buffered is not None and not future.done():
                future.set_result(buffered)
            await upstream_ws.send(
                json.dumps({"type": "req", "id": req_id, "method": method, "params": params})
            )
            try:
                response = await asyncio.wait_for(future, timeout=timeout)
                return response if isinstance(response, dict) else {}
            finally:
                pending_responses.pop(req_id, None)

        async def _upstream_reader() -> None:
            try:
                while True:
                    raw = await upstream_ws.recv()
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8", errors="replace")
                    try:
                        parsed = json.loads(str(raw))
                    except Exception:
                        continue

                    frame_type = str(parsed.get("type") or "").strip().lower()
                    if frame_type == "event":
                        event_name = str(parsed.get("event") or "").strip().lower()
                        if event_name == "connect.challenge":
                            payload_obj = parsed.get("payload")
                            nonce = (
                                str(payload_obj.get("nonce") or "").strip()
                                if isinstance(payload_obj, dict)
                                else ""
                            )
                            if nonce and not challenge_future.done():
                                challenge_future.set_result(nonce)
                            continue
                        if event_name == "chat":
                            for message in _map_numbuh_2x4_event_to_browser_messages(parsed):
                                if message.get("type") == "assistant.message":
                                    content = str(message.get("content") or "")
                                    if content and not final_text_future.done():
                                        final_text_future.set_result(content)
                                        return
                            payload_obj = parsed.get("payload")
                            if isinstance(payload_obj, dict):
                                state = str(payload_obj.get("state") or "").strip().lower()
                                if state in {"error", "aborted"} and not final_text_future.done():
                                    detail = str(payload_obj.get("errorMessage") or "").strip() or "chat failed"
                                    final_text_future.set_exception(RuntimeError(detail))
                                    return
                        continue

                    if frame_type == "res":
                        frame_id = str(parsed.get("id") or "").strip()
                        if frame_id:
                            future = pending_responses.get(frame_id)
                            if future and not future.done():
                                future.set_result(parsed)
                            else:
                                buffered_responses[frame_id] = parsed
                        else:
                            continue
                        continue

                    if frame_type == "error" and not final_text_future.done():
                        detail = str(parsed.get("message") or "").strip() or "Numbuh 2x4 upstream error."
                        final_text_future.set_exception(RuntimeError(detail))
                        return
            except Exception as exc:
                if not final_text_future.done():
                    final_text_future.set_exception(exc)

        reader_task = asyncio.create_task(_upstream_reader())
        try:
            connect_nonce = await asyncio.wait_for(
                challenge_future,
                timeout=NUMBUH_2X4_CONNECT_TIMEOUT_SEC,
            )
            connect_response = await _upstream_request(
                "connect",
                _build_numbuh_2x4_connect_params(token, connect_nonce),
                timeout=NUMBUH_2X4_CONNECT_TIMEOUT_SEC,
            )
            if not connect_response.get("ok"):
                err_obj = connect_response.get("error")
                err_msg = (
                    str(err_obj.get("message"))
                    if isinstance(err_obj, dict) and err_obj.get("message")
                    else "Upstream connect failed."
                )
                raise RuntimeError(err_msg)

            hello_payload = connect_response.get("payload")
            if isinstance(hello_payload, dict):
                resolved = _resolve_numbuh_2x4_session_key(hello_payload)
                direct = str(hello_payload.get("mainSessionKey") or "").strip()
                default_session_key = direct or resolved

            chat_req_id = uuid.uuid4().hex
            run_id = uuid.uuid4().hex
            await upstream_ws.send(
                json.dumps(
                    {
                        "type": "req",
                        "id": chat_req_id,
                        "method": "chat.send",
                        "params": {
                            "sessionKey": default_session_key,
                            "message": _build_2x4_takeover_query_message(hidden_instruction, context),
                            "idempotencyKey": run_id,
                        },
                    }
                )
            )
            return str(
                await asyncio.wait_for(final_text_future, timeout=NUMBUH_2X4_REQUEST_TIMEOUT_SEC)
            )
        finally:
            if not reader_task.done():
                reader_task.cancel()
                await asyncio.gather(reader_task, return_exceptions=True)
            for future in list(pending_responses.values()):
                if not future.done():
                    future.cancel()


async def _maybe_intercept_takeover_control_message(
    content: str,
    controller: TakeoverController,
    send_browser: Callable[[dict[str, Any]], Awaitable[None]],
) -> bool:
    """Handle local takeover control commands and skip upstream relay send."""
    normalized = str(content or "").strip().lower()
    timeout_status = controller.reconcile_timeouts()
    if timeout_status == "pending_expired":
        await send_browser(
            {
                "type": "system",
                "event": "takeover_confirmation_expired",
                "active": False,
                "message": "2x4 takeover confirmation expired. Returned to standby.",
            }
        )
    elif timeout_status == "active_expired":
        await send_browser(
            {
                "type": "system",
                "event": "takeover_auto_expired",
                "active": False,
                "message": "2x4 takeover lease expired. Returned to standby.",
            }
        )
    if normalized == "take over":
        controller.request_takeover_confirmation()
        await send_browser(
            {
                "type": "system",
                "event": "takeover_confirmation_requested",
                "active": False,
                "message": "Confirm takeover with Yes within 15 seconds.",
            }
        )
        _debug("takeover_enable", source="chat_command", bra_root=BRA_DIR or "")
        return True
    if normalized == "yes":
        if controller.confirm_takeover("yes"):
            await send_browser(
                {
                    "type": "system",
                    "event": "takeover_confirmation_received",
                    "active": True,
                    "message": "2x4 takeover active for 30 seconds.",
                }
            )
        else:
            await send_browser(
                {
                    "type": "system",
                    "event": "takeover_status",
                    "active": False,
                    "message": "No pending takeover confirmation.",
                }
            )
        return True
    if normalized == "stand down":
        controller.disable_takeover()
        await send_browser(
            {
                "type": "system",
                "event": "takeover_stand_down",
                "active": False,
                "message": "2x4 takeover inactive.",
            }
        )
        _debug("takeover_disable", source="chat_command", bra_root=BRA_DIR or "")
        return True
    return False


async def _maybe_intercept_2x4_debug_command(
    content: str,
    run_id: str,
    send_browser: Callable[[dict[str, Any]], Awaitable[None]],
) -> bool:
    """Handle local debug-chat commands that should not be sent to Hermes chat."""
    normalized = " ".join(str(content or "").strip().lower().split())
    if normalized not in {"/bra", "/bra summary", "/bra summ", "/bra-summ"}:
        return False

    try:
        maybe_payload = get_2x4_summary(_=True)
        payload = await maybe_payload if asyncio.iscoroutine(maybe_payload) else maybe_payload
    except Exception as exc:
        await send_browser({"type": "error", "message": f"2x4 summary failed: {exc}"})
        return True

    await send_browser(
        {
            "type": "assistant.message",
            "id": run_id,
            "role": "assistant",
            "content": json.dumps(payload, ensure_ascii=False, indent=2),
            "done": True,
        }
    )
    return True


def _resolve_api_key(config: dict | None = None) -> tuple[str | None, str | None]:
    """Resolve effective Anthropic API key and its source."""
    env_key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if env_key:
        _debug("resolve_api_key", source="env", present=True, bra_root=BRA_DIR or "")
        return env_key, "env"

    cfg = config if config is not None else load_config()
    cfg_key = (cfg.get("anthropic_api_key") or "").strip()
    if cfg_key:
        _debug("resolve_api_key", source="config", present=True, bra_root=BRA_DIR or "")
        return cfg_key, "config"
    _debug("resolve_api_key", source="none", present=False, bra_root=BRA_DIR or "")
    return None, None


def _apply_config_api_key(config: dict) -> None:
    """Populate ANTHROPIC_API_KEY from persisted config if env is empty."""
    env_key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if env_key:
        _debug("apply_config_api_key_skip_env_present", bra_root=BRA_DIR or "")
        return
    cfg_key = (config.get("anthropic_api_key") or "").strip()
    if cfg_key:
        os.environ["ANTHROPIC_API_KEY"] = cfg_key
        _debug("apply_config_api_key_from_config", bra_root=BRA_DIR or "")

def _detect_project_root() -> str:
    """Detect project root from boots location on disk.

    boots/main.py lives at {project_root}/boots/main.py, so the project
    root is two levels up from CONFIG_FILE (boots/.bra-gui-config.json).
    Returns empty string if the detected root has no body/ directory.
    """
    detected = CONFIG_FILE.parent.parent.resolve()
    resolved = _resolve_bra_body_and_project_roots(detected)
    if resolved:
        return str(resolved[1])
    return ""


def get_bra_dir():
    """Get current BRA directory.

    Priority:
      1. BRA_DIR env var / global (if already set and valid)
      2. Config file bra_dir — but only if it matches the detected
         project root.  When a project is copied/moved the config
         retains the old absolute path; we detect this and auto-correct.
      3. Detected project root from boots location on disk.
    """
    global BRA_DIR
    if BRA_DIR:
        resolved = _resolve_bra_body_and_project_roots(BRA_DIR)
        if resolved:
            normalized = str(resolved[1])  # project root
            if normalized != BRA_DIR:
                BRA_DIR = normalized
            _debug("get_bra_dir", source="global", bra_root=normalized)
            return normalized
        _debug("get_bra_dir", source="global", bra_root=BRA_DIR)
        return BRA_DIR

    detected = _detect_project_root()
    config = load_config()
    raw = config.get("bra_dir", "")
    resolved = _resolve_bra_body_and_project_roots(raw) if raw else None
    normalized = str(resolved[1]) if resolved else raw  # project root

    # If the config points to a different project than where boots is
    # actually running, prefer the detected root and update the config.
    if detected and normalized and normalized != detected:
        _debug(
            "get_bra_dir_stale_config",
            bra_root=detected,
            config_bra_dir=normalized,
            detected_root=detected,
        )
        config["bra_dir"] = detected
        save_config(config)
        normalized = detected

    if not normalized and detected:
        normalized = detected

    _debug("get_bra_dir", source="config", bra_root=normalized)
    return normalized

app = FastAPI(title="BRA Web GUI", version="0.1.0")
security = HTTPBearer(auto_error=False)


def _extract_bearer_token(raw_value: str | None) -> str:
    value = str(raw_value or "").strip()
    if not value:
        return ""
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return ""


def _resolve_request_auth_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = None,
) -> str:
    if credentials and credentials.credentials:
        return str(credentials.credentials).strip()
    header_token = _extract_bearer_token(request.headers.get("authorization"))
    if header_token:
        return header_token
    return str(request.cookies.get(AUTH_COOKIE_NAME) or "").strip()


def _resolve_websocket_auth_token(websocket: WebSocket, query_token: str = "") -> str:
    header_token = _extract_bearer_token(websocket.headers.get("authorization"))
    if header_token:
        return header_token
    cookie_token = str(websocket.cookies.get(AUTH_COOKIE_NAME) or "").strip()
    if cookie_token:
        return cookie_token
    return str(query_token or "").strip()


def _set_persistent_cookie(response: JSONResponse, name: str, value: str) -> None:
    response.set_cookie(
        key=name,
        value=value,
        max_age=AUTH_COOKIE_MAX_AGE,
        path="/",
        samesite="strict",
        secure=False,
        httponly=False,
    )

# GZip compression for large responses (GLB models, etc.)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_debug_middleware(request: Request, call_next):
    """Route-level debug tracing with correlation IDs."""
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    request.state.request_id = request_id
    started = datetime.now()
    _debug(
        "http_request_start",
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        query=str(request.url.query),
        client=(request.client.host if request.client else ""),
    )
    try:
        response = await call_next(request)
        duration_ms = int((datetime.now() - started).total_seconds() * 1000)
        _debug(
            "http_request_finish",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )
        response.headers["x-request-id"] = request_id
        return response
    except Exception as exc:
        duration_ms = int((datetime.now() - started).total_seconds() * 1000)
        _debug(
            "http_request_error",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            duration_ms=duration_ms,
            error=str(exc),
        )
        raise

# Token storage
AUTH_TOKEN: str = ""
NUMBUH_2X4_SERVICE_TOKEN: str = ""

# Docs password — separate password gate for the Docs tab
DOCS_PASSWORD: str = ""  # SHA-256 hex digest of the password
_docs_session_tokens: set[str] = set()  # valid session tokens after docs auth
DOCS_AUTH_ENABLED = False

# Debug password — separate password gate for the Debug tab
DEBUG_PASSWORD: str = ""
_debug_session_tokens: set[str] = set()
DEBUG_AUTH_ENABLED = False


@app.on_event("startup")
async def startup_event():
    """Initialize token on startup."""
    global AUTH_TOKEN, NUMBUH_2X4_SERVICE_TOKEN, DOCS_PASSWORD, DEBUG_PASSWORD
    AUTH_TOKEN = get_or_create_token()
    NUMBUH_2X4_SERVICE_TOKEN = get_or_create_2x4_service_token()
    DOCS_PASSWORD = _load_docs_password()
    DEBUG_PASSWORD = _load_debug_password()
    config = load_config()
    _apply_config_api_key(config)
    try:
        _sync_2x4_governance_tokens(get_bra_dir(), config=config)
    except Exception as exc:
        _debug("sync_2x4_tokens_startup_error", error=str(exc), bra_root=BRA_DIR or "")
    _debug("startup", bra_root=BRA_DIR or "", auth_token_present=bool(AUTH_TOKEN))
    print(f"\n{'='*60}")
    print("  BRA Web GUI - Battle Ready Armor Dashboard")
    print(f"{'='*60}")
    print(f"\n  Token: {AUTH_TOKEN}")
    print(f"  2x4 Service Token: {NUMBUH_2X4_SERVICE_TOKEN}")
    docs_pw_status = "SET" if (DOCS_AUTH_ENABLED and DOCS_PASSWORD) else "DISABLED"
    debug_pw_status = "SET" if (DEBUG_AUTH_ENABLED and DEBUG_PASSWORD) else "DISABLED"
    print(f"  Docs Password: {docs_pw_status}")
    print(f"  Debug Password: {debug_pw_status}")
    print(f"  BRA Directory: {BRA_DIR}")
    print(f"{'='*60}\n")


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up agent processes on server shutdown."""
    try:
        await _engage_manager.stop_agent()
        print("[shutdown] stopped agent runner/subprocesses", flush=True)
    except Exception as exc:
        print(f"[shutdown] cleanup error: {exc}", flush=True)
    try:
        _stop_cloudflared_tunnel()
    except Exception as exc:
        print(f"[shutdown] cloudflared cleanup error: {exc}", flush=True)
    _debug("shutdown", bra_root=BRA_DIR or "")


def get_or_create_token() -> str:
    """Get existing token or create new one."""
    # Always store token in GUI directory, not BRA directory
    token_path = Path(__file__).parent / TOKEN_FILE
    if token_path.exists():
        token = token_path.read_text().strip()
        _debug("token_loaded", token_file=str(token_path), bra_root=BRA_DIR or "")
        return token
    token = secrets.token_urlsafe(32)
    token_path.write_text(token)
    _debug("token_created", token_file=str(token_path), bra_root=BRA_DIR or "")
    return token


def get_or_create_2x4_service_token() -> str:
    """Get existing 2x4 service token or create a new one."""
    token_path = Path(__file__).parent / NUMBUH_2X4_SERVICE_TOKEN_FILE
    if token_path.exists():
        token = token_path.read_text().strip()
        _debug("token_2x4_loaded", token_file=str(token_path), bra_root=BRA_DIR or "")
        return token
    token = secrets.token_urlsafe(32)
    token_path.write_text(token)
    _debug("token_2x4_created", token_file=str(token_path), bra_root=BRA_DIR or "")
    return token


def _set_2x4_service_token(token: str) -> None:
    """Persist and activate a caller-supplied 2x4 service token."""
    global NUMBUH_2X4_SERVICE_TOKEN
    token_value = str(token or "").strip()
    if not token_value:
        raise ValueError("2x4 service token cannot be empty")
    token_path = Path(__file__).parent / NUMBUH_2X4_SERVICE_TOKEN_FILE
    token_path.write_text(token_value)
    NUMBUH_2X4_SERVICE_TOKEN = token_value
    _debug("token_2x4_set", token_file=str(token_path), bra_root=BRA_DIR or "")


def _clear_2x4_service_token() -> None:
    """Remove persisted 2x4 service token and clear in-memory value."""
    global NUMBUH_2X4_SERVICE_TOKEN
    token_path = Path(__file__).parent / NUMBUH_2X4_SERVICE_TOKEN_FILE
    token_path.unlink(missing_ok=True)
    NUMBUH_2X4_SERVICE_TOKEN = ""
    _debug("token_2x4_cleared", token_file=str(token_path), bra_root=BRA_DIR or "")


def _load_docs_password() -> str:
    """Load docs password from file. Returns empty string if not set.

    To set, write the plaintext password to boots/.bra-gui-docs-password.
    """
    pw_path = Path(__file__).parent / DOCS_PASSWORD_FILE
    if pw_path.exists():
        stored = pw_path.read_text().strip()
        if stored:
            return stored
    return ""


def _load_debug_password() -> str:
    """Load debug password from file. Returns empty string if not set.

    To set, write the plaintext password to boots/.bra-gui-debug-password.
    """
    pw_path = Path(__file__).parent / DEBUG_PASSWORD_FILE
    if pw_path.exists():
        stored = pw_path.read_text().strip()
        if stored:
            return stored
    return ""


def verify_docs_session(request) -> bool:
    """Check if request has a valid docs session token (cookie or header)."""
    if not DOCS_AUTH_ENABLED or not DOCS_PASSWORD:
        return True  # No docs password configured
    token = request.cookies.get(DOCS_SESSION_COOKIE_NAME) or request.headers.get("x-docs-session")
    return token in _docs_session_tokens if token else False


async def verify_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    """Verify bearer token for API access."""
    if not AUTH_TOKEN:
        _debug("verify_token", result="allow_no_auth", bra_root=BRA_DIR or "")
        return True  # No auth configured
    token = _resolve_request_auth_token(request, credentials)
    if not token:
        _debug("verify_token", result="missing_credentials", bra_root=BRA_DIR or "")
        raise HTTPException(status_code=401, detail="Missing authentication token")
    if token != AUTH_TOKEN:
        _debug("verify_token", result="invalid_credentials", bra_root=BRA_DIR or "")
        raise HTTPException(status_code=403, detail="Invalid authentication token")
    _debug("verify_token", result="ok", bra_root=BRA_DIR or "")
    return True


async def verify_2x4_service_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    """Verify dedicated bearer token for /api/2x4 control-plane endpoints."""
    global NUMBUH_2X4_SERVICE_TOKEN
    if not NUMBUH_2X4_SERVICE_TOKEN:
        try:
            NUMBUH_2X4_SERVICE_TOKEN = get_or_create_2x4_service_token()
        except Exception:
            NUMBUH_2X4_SERVICE_TOKEN = ""
    if not NUMBUH_2X4_SERVICE_TOKEN:
        _debug("verify_2x4_service_token", result="missing_server_token", bra_root=BRA_DIR or "")
        raise HTTPException(status_code=503, detail="2x4 service token unavailable")
    if not credentials:
        _debug("verify_2x4_service_token", result="missing_credentials", bra_root=BRA_DIR or "")
        raise HTTPException(status_code=401, detail="Missing 2x4 service token")
    if credentials.credentials != NUMBUH_2X4_SERVICE_TOKEN:
        _debug("verify_2x4_service_token", result="invalid_credentials", bra_root=BRA_DIR or "")
        raise HTTPException(status_code=403, detail="Invalid 2x4 service token")
    _debug("verify_2x4_service_token", result="ok", bra_root=BRA_DIR or "")
    return True


async def require_docs_access(request: Request, _: bool = Depends(verify_token)):
    """Dependency that requires both API auth and docs session."""
    if not verify_docs_session(request):
        raise HTTPException(status_code=403, detail="Docs password required")
    return True


def verify_debug_session(request) -> bool:
    """Check if request has a valid debug session token (cookie or header)."""
    if not DEBUG_AUTH_ENABLED or not DEBUG_PASSWORD:
        return True  # No debug password configured
    token = request.cookies.get(DEBUG_SESSION_COOKIE_NAME) or request.headers.get("x-debug-session")
    return token in _debug_session_tokens if token else False


async def require_debug_access(request: Request, _: bool = Depends(verify_token)):
    """Dependency that requires both API auth and debug session."""
    if not verify_debug_session(request):
        raise HTTPException(status_code=403, detail="Debug password required")
    return True


_PATH_LIKE_ENV_VARS = {
    "BRA_ALLOWED_CLAUDE_DIR",
    "BRA_DIR",
    "BRA_ROOT",
    "CLAUDE_CODE_TMPDIR",
    "CLAUDE_CONFIG_DIR",
    "HOME",
    "PATH",
    "PROJECT",
    "PRJT",
    "PWD",
    "PYTHONPATH",
    "TMPDIR",
    "VIRTUAL_ENV",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_STATE_HOME",
}
_MULTIPATH_ENV_VARS = {"PATH", "PYTHONPATH"}
_SENSITIVE_ENV_MARKERS = {
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASS",
    "AUTH",
    "COOKIE",
    "SESSION",
}
_SENSITIVE_ENV_ALLOWLIST = {
    "PATH",
    "PYTHONPATH",
    "PWD",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "TMPDIR",
    "VIRTUAL_ENV",
    "BRA_DIR",
    "BRA_ROOT",
    "BRA_MODEL",
    "BRA_UI_PROFILE",
    "BRA_UI_PACK",
    "CLAUDE_CONFIG_DIR",
    "BRA_ALLOWED_CLAUDE_DIR",
    "CLAUDE_CODE_TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
}
_FOCUS_ENV_VARS = [
    "BRA_DIR",
    "BRA_ROOT",
    "BRA_MODEL",
    "BRA_UI_PROFILE",
    "BRA_UI_PACK",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "PWD",
    "HOME",
    "CLAUDE_CONFIG_DIR",
    "BRA_ALLOWED_CLAUDE_DIR",
    "CLAUDE_CODE_TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "TMPDIR",
]
_COMPARE_ENV_KEYS = [
    "BRA_DIR",
    "BRA_ROOT",
    "BRA_MODEL",
    "BRA_UI_PROFILE",
    "BRA_UI_PACK",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "PWD",
    "HOME",
    "CLAUDE_CONFIG_DIR",
    "BRA_ALLOWED_CLAUDE_DIR",
    "CLAUDE_CODE_TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "TMPDIR",
]
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")


def _is_sensitive_env_key(key: str) -> bool:
    upper = key.upper()
    if upper in _SENSITIVE_ENV_ALLOWLIST:
        return False
    return any(marker in upper for marker in _SENSITIVE_ENV_MARKERS)


def _mask_env_value(key: str, value: str) -> str:
    if not value:
        return ""
    if not _is_sensitive_env_key(key):
        return value
    preview = _mask_api_key(value)
    if preview:
        return preview
    return "***"


def _resolve_path_entry(raw: str) -> dict[str, Any]:
    expanded = Path(raw).expanduser()
    try:
        resolved = expanded.resolve(strict=False)
    except Exception:
        resolved = expanded
    exists = resolved.exists()
    kind = "dir" if exists and resolved.is_dir() else ("file" if exists and resolved.is_file() else "")
    return {
        "raw": raw,
        "resolved": str(resolved),
        "exists": exists,
        "kind": kind,
    }


def _resolve_env_paths(name: str, value: str) -> list[dict[str, Any]]:
    if not value:
        return []
    if name in _MULTIPATH_ENV_VARS:
        entries = [part for part in value.split(os.pathsep) if part]
    elif (
        name.startswith("PROJECT_")
        or name.startswith("PRJT_")
        or name.startswith("AGENT_")
        or name.endswith("_DIR")
        or name.endswith("_ROOT")
        or name.endswith("_PATH")
    ):
        entries = [value]
    elif name in _PATH_LIKE_ENV_VARS:
        entries = [value]
    else:
        return []
    return [_resolve_path_entry(item) for item in entries]


def _serialize_env_value(name: str, value: str) -> dict[str, Any]:
    paths = _resolve_env_paths(name, value)
    return {
        "name": name,
        "value": _mask_env_value(name, value),
        "set": bool(value),
        "sensitive": _is_sensitive_env_key(name),
        "paths": paths,
    }


def _extract_env_from_ps(pid: int) -> tuple[dict[str, str], str | None]:
    """Extract process environment using `ps eww` output."""
    try:
        result = subprocess.run(
            ["ps", "eww", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception as exc:
        return {}, str(exc)

    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip() or f"ps exit {result.returncode}"
        return {}, err

    line = ""
    for raw in result.stdout.splitlines():
        stripped = raw.strip()
        if stripped:
            line = stripped
            break
    if not line:
        return {}, "no ps output"

    try:
        tokens = shlex.split(line, posix=True)
    except Exception:
        tokens = line.split()

    env_map: dict[str, str] = {}
    for token in tokens:
        if not _ENV_ASSIGN_RE.match(token):
            break
        name, value = token.split("=", 1)
        env_map[name] = value
    if not env_map:
        return {}, "no env vars parsed from ps output"
    return env_map, None


def _build_env_comparison_rows(
    server_env: dict[str, str],
    agent_env: dict[str, str],
    compare_keys: list[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in compare_keys:
        server_value = server_env.get(key, "")
        agent_value = agent_env.get(key, "")
        rows.append(
            {
                "name": key,
                "match": server_value == agent_value,
                "server": _serialize_env_value(key, server_value),
                "agent": _serialize_env_value(key, agent_value),
            }
        )
    return rows


def _collect_debug_env_snapshot() -> dict[str, Any]:
    effective_bra_dir = get_bra_dir() or ""
    resolved = _resolve_bra_body_and_project_roots(effective_bra_dir) if effective_bra_dir else None
    body_root = resolved[0] if resolved else None
    project_root = resolved[1] if resolved else None
    boots_root = Path(__file__).resolve().parent

    roots = {
        "cwd": str(Path.cwd()),
        "boots_root": str(boots_root),
        "boots_parent": str(boots_root.parent),
        "bra_dir_global": BRA_DIR or "",
        "bra_dir_effective": effective_bra_dir,
        "project_root_effective": str(project_root) if project_root else "",
        "body_root_effective": str(body_root) if body_root else "",
        "body_has_bra_state": bool(body_root and (body_root / ".bra").exists()),
    }

    settings_paths: dict[str, str] = {}
    settings_error: str | None = None
    try:
        from bra.config import settings as bra_settings

        settings_paths = {
            "HEAD_ROOT": str(bra_settings.HEAD_ROOT),
            "BRA_ROOT": str(bra_settings.BRA_ROOT),
            "BODY_ROOT": str(bra_settings.BODY_ROOT),
            "LAYER1": str(bra_settings.LAYER1),
            "LAYER2": str(bra_settings.LAYER2),
            "LAYER3": str(bra_settings.LAYER3),
            "BRA_STATE": str(bra_settings.BRA_STATE),
            "LOGS_DIR": str(bra_settings.LOGS_DIR),
            "APPROVALS_DIR": str(bra_settings.APPROVALS_DIR),
        }
    except Exception as exc:
        settings_error = str(exc)

    server_env = dict(os.environ)
    env_rows = [
        _serialize_env_value(name, os.environ.get(name, ""))
        for name in sorted(os.environ.keys())
    ]
    focus = {
        name: _serialize_env_value(name, os.environ.get(name, ""))
        for name in _FOCUS_ENV_VARS
    }
    proc_rows = [
        proc
        for proc in _list_bra_processes()
        if proc.get("category") in {"agent", "agent_child"}
    ]
    all_seen_keys: set[str] = set(server_env.keys())
    prefix_keys: set[str] = {
        key
        for key in server_env.keys()
        if key.startswith("PROJECT_") or key.startswith("PRJT_") or key.startswith("AGENT_")
    }
    agent_records: list[dict[str, Any]] = []
    for proc in proc_rows:
        pid = int(proc.get("pid", 0) or 0)
        if pid <= 0:
            continue
        agent_env_map, agent_err = _extract_env_from_ps(pid)
        if agent_env_map:
            all_seen_keys.update(agent_env_map.keys())
            prefix_keys.update(
                key
                for key in agent_env_map.keys()
                if key.startswith("PROJECT_") or key.startswith("PRJT_") or key.startswith("AGENT_")
            )
        agent_records.append(
            {
                "pid": pid,
                "label": proc.get("label", ""),
                "category": proc.get("category", ""),
                "env_map": agent_env_map,
                "error": agent_err,
            }
        )

    compare_keys = list(dict.fromkeys(_COMPARE_ENV_KEYS + sorted(all_seen_keys) + sorted(prefix_keys)))
    focus_keys = list(dict.fromkeys(_FOCUS_ENV_VARS + sorted(prefix_keys)))
    agent_envs: list[dict[str, Any]] = []
    for record in agent_records:
        pid = int(record.get("pid", 0) or 0)
        agent_env_map = record.get("env_map", {}) or {}
        agent_err = record.get("error")
        agent_focus = {
            key: _serialize_env_value(key, agent_env_map.get(key, ""))
            for key in focus_keys
        }
        comparison_rows = (
            _build_env_comparison_rows(server_env, agent_env_map, compare_keys)
            if agent_env_map
            else []
        )
        mismatch_count = sum(1 for row in comparison_rows if not row.get("match"))
        agent_envs.append(
            {
                "pid": pid,
                "label": record.get("label", ""),
                "category": record.get("category", ""),
                "available": bool(agent_env_map),
                "error": agent_err,
                "focus": agent_focus,
                "comparison": comparison_rows,
                "mismatch_count": mismatch_count,
            }
        )

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "process": {
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "python_executable": sys.executable,
            "argv": sys.argv,
        },
        "python": {
            "version": sys.version.split()[0],
            "prefix": sys.prefix,
            "base_prefix": getattr(sys, "base_prefix", ""),
            "venv_active": bool(os.environ.get("VIRTUAL_ENV")),
        },
        "roots": roots,
        "settings": settings_paths,
        "settings_error": settings_error,
        "comparison_keys": compare_keys,
        "focus": focus,
        "env": env_rows,
        "agent_processes": proc_rows,
        "agent_envs": agent_envs,
    }


def get_bra_path(*parts: str) -> Path:
    """Get path within .bra directory."""
    bra_dir = get_bra_dir()
    if not bra_dir:
        out = Path(".bra") / Path(*parts) if parts else Path(".bra")
        _debug("get_bra_path", source="cwd", path=str(out), bra_root="")
        return out
    body = _body_root(bra_dir)
    out = body / ".bra" / Path(*parts) if parts else body / ".bra"
    _debug("get_bra_path", source="configured", path=str(out), bra_root=bra_dir)
    return out


def safe_path(base: Path, user_path: str) -> Path:
    """Validate path to prevent traversal attacks."""
    # Resolve the full path
    full_path = (base / user_path).resolve()
    # Ensure it's within base
    try:
        full_path.relative_to(base.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Path traversal denied")
    return full_path


def _resolve_2x4_controller_from_config() -> TakeoverController:
    """Load current relay settings into takeover controller and return singleton."""
    controller = get_takeover_controller()
    try:
        controller.configure_relay_settings(load_config())
    except Exception:
        pass
    return controller


def _require_active_2x4_lease(request: Request, controller: TakeoverController) -> str:
    """Require a currently-active takeover lease ID from request headers."""
    controller.reconcile_timeouts()
    lease_id = str(request.headers.get("x-2x4-lease-id") or "").strip()
    if (
        controller.state != "takeover_active"
        or not controller.active
        or not controller.takeover_lease_id
        or lease_id != controller.takeover_lease_id
    ):
        raise HTTPException(status_code=403, detail="2x4 takeover lease required")
    return lease_id


def strip_markdown(text: str) -> str:
    """Strip common markdown formatting from text.

    Removes:
    - Bold: **text** or __text__
    - Italic: *text* or _text_
    - Code: `text`
    - Links: [text](url) -> text
    """
    import re
    if not text:
        return text
    # Remove bold
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'__(.+?)__', r'\1', text)
    # Remove italic (be careful not to break already processed bold)
    text = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'\1', text)
    text = re.sub(r'(?<![\w])_(?!_)(.+?)(?<!_)_(?![\w])', r'\1', text)
    # Remove inline code
    text = re.sub(r'`(.+?)`', r'\1', text)
    # Remove links but keep text
    text = re.sub(r'\[(.+?)\]\(.+?\)', r'\1', text)
    return text.strip()


def parse_markdown_table_cells(line: str) -> list[str]:
    """Parse a markdown table line into cell values, preserving empty cells."""
    raw = line.strip()
    if not raw:
        return []
    if raw.startswith("|"):
        raw = raw[1:]
    if raw.endswith("|"):
        raw = raw[:-1]
    return [strip_markdown(cell.strip()) for cell in raw.split("|")]


_POSITIONAL_HEADER_DEFAULTS = ["Property", "Value", "Detail", "Notes"]


def normalize_table_headers(headers: list[str]) -> list[str]:
    """Return unique, non-empty header labels for stable row mapping.

    Blank headers get positional semantic names (Property, Value, Detail, Notes)
    instead of generic "Column N" labels.
    """
    normalized: list[str] = []
    seen: dict[str, int] = {}
    blank_idx = 0
    for idx, header in enumerate(headers, start=1):
        if header:
            base = header
        else:
            if blank_idx < len(_POSITIONAL_HEADER_DEFAULTS):
                base = _POSITIONAL_HEADER_DEFAULTS[blank_idx]
            else:
                base = f"Column {idx}"
            blank_idx += 1
        count = seen.get(base, 0) + 1
        seen[base] = count
        if count > 1:
            normalized.append(f"{base} ({count})")
        else:
            normalized.append(base)
    return normalized


def parse_stats_markdown(content: str) -> dict:
    """Parse STATS.md into a structured payload shared by /api/stats and /api/summary."""
    import re

    def extract_section(section_title: str) -> str:
        # Stop at horizontal rule or the next top-level "## " section, not at "###".
        pattern = rf'## {re.escape(section_title)}\s*\n\n(.+?)(?=\n\n---|\n\n##\s|\Z)'
        match = re.search(pattern, content, re.DOTALL)
        return match.group(1).strip() if match else ""

    def extract_subsection(parent_text: str, subsection_title: str) -> str:
        pattern = rf'### {re.escape(subsection_title)}\s*\n\n(.+?)(?=\n\n###|\Z)'
        match = re.search(pattern, parent_text, re.DOTALL)
        return match.group(1).strip() if match else ""

    def extract_list_items(block: str) -> list[str]:
        items: list[str] = []
        for raw_line in block.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if re.match(r'^-\s+\[[ xX]\]\s+', line):
                items.append(re.sub(r'^-\s+\[[ xX]\]\s*', '', line))
                continue
            if re.match(r'^\d+\.\s+', line):
                items.append(re.sub(r'^\d+\.\s*', '', line))
                continue
            if line.startswith("- "):
                items.append(line[2:].strip())
        return items

    parsed = {
        "raw": content,
        "title": None,
        "generated": None,
        "overview": {},
        "findings": {},
        "gaps": [],
        "recommendations": {},
        "executive_summary": None,
        "phase_completion_rows": [],
        "phase_last_activity": None,
        "recommendations_detail": {
            "process_improvements": [],
            "template_suggestions": [],
            "skill_development": [],
        },
        "lessons_learned": {
            "technical": [],
            "process": [],
        },
        "next_steps": [],
    }

    title_match = re.search(r'^#\s+(.+)', content, re.MULTILINE)
    gen_match = re.search(r'^Generated:\s*(.+)', content, re.MULTILINE)
    if title_match:
        parsed["title"] = title_match.group(1).strip()
    if gen_match:
        parsed["generated"] = gen_match.group(1).strip()

    # Preserve the existing health parser behavior.
    overview_match = re.search(r'## Overview\s*\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
    if overview_match:
        for line in overview_match.group(1).strip().split('\n'):
            cells = [c.strip() for c in line.split('|') if c.strip()]
            if len(cells) >= 2:
                parsed["overview"][cells[0]] = cells[1]

    findings_match = re.search(r'## Finding Statistics\s*\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
    if findings_match:
        for line in findings_match.group(1).strip().split('\n'):
            cells = [c.strip() for c in line.split('|') if c.strip()]
            if len(cells) >= 2 and not cells[0].startswith('-'):
                severity = cells[0].strip('*').upper()
                count = cells[1].strip('*')
                if count.isdigit():
                    parsed["findings"][severity] = int(count)

    gap_pattern = r'- \[ \] \*\*(\w+)\*\*:\s*(.+)'
    for match in re.finditer(gap_pattern, content):
        parsed["gaps"].append({
            "phase": match.group(1),
            "reason": match.group(2).strip(),
        })

    # Extended section parsing for full STATS.md rendering in Summary.
    exec_summary = extract_section("Executive Summary")
    if exec_summary:
        parsed["executive_summary"] = strip_markdown(exec_summary)

    phase_section = extract_section("Phase Completion Status")
    if phase_section:
        table_match = re.search(
            r'\| Phase \| Status \| Artifacts \|\n\|[-|\s]+\|\n((?:\|.+\n)+)',
            phase_section,
        )
        if table_match:
            for line in table_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 3:
                    parsed["phase_completion_rows"].append({
                        "phase": cells[0],
                        "status": cells[1],
                        "artifacts": cells[2],
                    })
        activity_match = re.search(r'Last activity:\s*(.+)', phase_section)
        if activity_match:
            parsed["phase_last_activity"] = activity_match.group(1).strip()

    recommendations_section = extract_section("Recommendations")
    if recommendations_section:
        parsed["recommendations_detail"]["process_improvements"] = extract_list_items(
            extract_subsection(recommendations_section, "Process Improvements")
        )
        parsed["recommendations_detail"]["template_suggestions"] = extract_list_items(
            extract_subsection(recommendations_section, "Template Suggestions")
        )
        parsed["recommendations_detail"]["skill_development"] = extract_list_items(
            extract_subsection(recommendations_section, "Skill Development")
        )
        parsed["recommendations"] = parsed["recommendations_detail"]

    lessons_section = extract_section("Lessons Learned")
    if lessons_section:
        parsed["lessons_learned"]["technical"] = extract_list_items(
            extract_subsection(lessons_section, "Technical")
        )
        parsed["lessons_learned"]["process"] = extract_list_items(
            extract_subsection(lessons_section, "Process")
        )

    next_steps_section = extract_section("Next Steps")
    if next_steps_section:
        for line in next_steps_section.splitlines():
            step = line.strip()
            if not re.match(r'^-\s+\[[ xX]\]\s+', step):
                continue
            parsed["next_steps"].append({
                "done": "[x]" in step.lower(),
                "text": re.sub(r'^-\s+\[[ xX]\]\s*', '', step).strip(),
            })

    return parsed


# ============== Override Helpers ==============

def require_bra_root_path() -> Path:
    """Get configured BRA body root path or raise an HTTP 400."""
    bra_root = get_bra_dir()
    if not bra_root:
        raise HTTPException(status_code=400, detail="No BRA directory configured.")
    return _body_root(bra_root)


def get_overrides_file(bra_root: Path) -> Path:
    """Get .bra/overrides.json path."""
    return bra_root / ".bra" / "overrides.json"


def load_overrides_rules(bra_root: Path) -> tuple[bool, list[dict]]:
    """Load override rules from .bra/overrides.json."""
    overrides_file = get_overrides_file(bra_root)
    if not overrides_file.exists():
        return False, []
    try:
        payload = json.loads(overrides_file.read_text())
    except (json.JSONDecodeError, OSError):
        return False, []
    if not isinstance(payload, dict):
        return False, []
    rules = payload.get("rules", [])
    if not isinstance(rules, list):
        return False, []
    return True, [rule for rule in rules if isinstance(rule, dict)]


def save_overrides_rules(bra_root: Path, rules: list[dict]) -> None:
    """Persist override rules atomically to .bra/overrides.json."""
    overrides_file = get_overrides_file(bra_root)
    overrides_file.parent.mkdir(parents=True, exist_ok=True)
    tmp_file = overrides_file.with_name(f"{overrides_file.name}.tmp")
    tmp_file.write_text(json.dumps({"rules": rules}, indent=2) + "\n")
    tmp_file.replace(overrides_file)


def has_override_approval(bra_root: Path) -> bool:
    """Check OVERRIDE-APPROVAL authorization state."""
    if os.environ.get("OVERRIDE_APPROVAL") == "1":
        return True
    return (bra_root / ".bra" / "approvals" / "OVERRIDE-APPROVAL").exists()


def is_engagement_active(bra_root: Path) -> bool:
    """Check engagement active state.

    Primary: .bra/engagement_meta.json (started_at set, ended_at not set).
    Fallback: SCOPE-CONFIRMED token exists (covers manual scope imports
    that bypass the wizard and never create engagement_meta.json).
    """
    meta_file = bra_root / ".bra" / "engagement_meta.json"
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text())
        except (json.JSONDecodeError, OSError):
            pass
        else:
            if bool(meta.get("ended_at")):
                return False
            if bool(meta.get("started_at")):
                return True
    # Fallback: SCOPE-CONFIRMED means scope intake completed (wizard or manual)
    return (bra_root / ".bra" / "approvals" / "SCOPE-CONFIRMED").exists()


def load_override_history(bra_root: Path) -> list[dict]:
    """Load override decision history from layer3-engagement/OVERRIDES.md."""
    import re

    overrides_md = bra_root / "layer3-engagement" / "OVERRIDES.md"
    if not overrides_md.exists():
        return []
    try:
        content = overrides_md.read_text()
    except OSError:
        return []

    decisions_start = content.find("## Engagement Decisions")
    if decisions_start == -1:
        return []

    decisions_content = content[decisions_start:]
    header_pattern = re.compile(
        r'^### \[(.+?)\] (\w+) (.+?) \u2014 (.+)$',
        re.MULTILINE,
    )
    matches = list(header_pattern.finditer(decisions_content))
    decisions = []

    for i, match in enumerate(matches):
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(decisions_content)
        detail_block = decisions_content[start:end]

        details = {}
        for line in detail_block.split("\n"):
            line = line.strip()
            detail_match = re.match(r'^- \*\*(.+?):\*\*\s*(.+)', line)
            if detail_match:
                key = detail_match.group(1).lower()
                value = detail_match.group(2).strip().strip("`")
                details[key] = value

        decisions.append({
            "timestamp": match.group(1),
            "type": match.group(2),
            "subtype": match.group(3),
            "decision": match.group(4),
            "command": details.get("command", ""),
            "override_id": details.get("override id", ""),
            "context": details.get("context", ""),
        })

    return decisions


def append_override_history_entry(
    bra_root: Path,
    *,
    decision_type: str,
    subtype: str,
    decision: str,
    override_id: str = "",
    context: str = "",
    command: str = "",
) -> None:
    """Append a structured override event to layer3-engagement/OVERRIDES.md."""
    overrides_md = bra_root / "layer3-engagement" / "OVERRIDES.md"
    try:
        overrides_md.parent.mkdir(parents=True, exist_ok=True)
        if overrides_md.exists():
            content = overrides_md.read_text()
        else:
            content = (
                "# Override Recommendations\n\n"
                "## Engagement Decisions\n\n"
            )
        if "## Engagement Decisions" not in content:
            content = content.rstrip() + "\n\n## Engagement Decisions\n\n"
            overrides_md.write_text(content)
        elif not overrides_md.exists():
            overrides_md.write_text(content)
    except OSError:
        return

    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    entry_lines = [f"### [{ts}] {decision_type} {subtype} — {decision}"]
    if command:
        entry_lines.append(f"- **Command:** `{command}`")
    if override_id:
        entry_lines.append(f"- **Override ID:** {override_id}")
    if context:
        entry_lines.append(f"- **Context:** {context}")

    try:
        with overrides_md.open("a", encoding="utf-8") as handle:
            handle.write("\n" + "\n".join(entry_lines) + "\n")
    except OSError:
        return


def serialize_override_rule(rule: dict) -> dict:
    """Normalize rule fields for API response."""
    return {
        "id": rule.get("id", ""),
        "type": rule.get("type", ""),
        "match": rule.get("match", {}),
        "action": rule.get("action", ""),
        "enabled": bool(rule.get("enabled", True)),
        "created_at": rule.get("created_at", ""),
    }


def build_overrides_payload(bra_root: Path) -> dict:
    """Build unified override payload for API responses."""
    exists, rules = load_overrides_rules(bra_root)
    serialized_rules = [serialize_override_rule(rule) for rule in rules]
    has_token = has_override_approval(bra_root)
    engagement_active = is_engagement_active(bra_root)

    can_mutate_reason = None
    if not has_token:
        can_mutate_reason = "OVERRIDE-APPROVAL token required"

    return {
        "exists": exists,
        "count": len(serialized_rules),
        "active_count": sum(1 for rule in serialized_rules if rule.get("enabled", True)),
        "rules": serialized_rules,
        "history": load_override_history(bra_root),
        "has_override_approval": has_token,
        "engagement_active": engagement_active,
        "can_mutate": bool(has_token),
        "can_mutate_reason": can_mutate_reason,
    }


def require_override_mutation_access(bra_root: Path) -> None:
    """Require OVERRIDE-APPROVAL token for override mutations."""
    if not has_override_approval(bra_root):
        raise HTTPException(status_code=403, detail="OVERRIDE-APPROVAL token required")


# ============== API Routes ==============

@app.get("/api/config")
async def get_config(_: bool = Depends(verify_token)):
    """Get current configuration."""
    config = load_config()
    bra_dir = get_bra_dir()
    try:
        _sync_2x4_governance_tokens(bra_dir, config=config)
    except Exception as exc:
        logging.debug("Failed to sync 2x4 governance tokens during /api/config: %s", exc)

    api_key, api_key_source = _resolve_api_key(config)
    numbuh_2x4_enabled, numbuh_2x4_ws_url, numbuh_2x4_token = _resolve_numbuh_2x4_settings(config)
    numbuh_2x4_takeover_prompt = _resolve_numbuh_2x4_takeover_prompt(config)
    voice_call_control_token = _resolve_voice_call_control_boots_service_token(config)
    proxy_cfg = get_proxy_config()
    bra_path = Path(bra_dir) if bra_dir else None
    resolved = _resolve_bra_body_and_project_roots(bra_path) if bra_path else None
    body_root = resolved[0] if resolved else bra_path
    has_body = bool(
        bra_path
        and bra_path.exists()
        and (bra_path.name == "body" or (bra_path / "body").exists())
    )
    is_valid = bool(body_root and body_root.exists() and (body_root / ".bra").exists())
    
    return {
        "bra_dir": bra_dir,
        "is_valid": is_valid,
        "has_bra_folder": (body_root / ".bra").exists() if body_root and body_root.exists() else False,
        "has_body": has_body,
        "has_layer3": (body_root / "layer3-engagement").exists() if body_root and body_root.exists() else False,
        "model": config.get("model"),
        "api_key_set": bool(api_key),
        "api_key_source": api_key_source,
        "api_key_preview": _mask_api_key(api_key),
        "chat_provider": _normalize_chat_provider(config.get("chat_provider")),
        "numbuh_2x4_agent_provider": _normalize_2x4_agent_provider(
            config.get("numbuh_2x4_agent_provider")
        ),
        "numbuh_2x4_hermes_base_url": str(config.get("numbuh_2x4_hermes_base_url", "") or ""),
        "numbuh_2x4_hermes_session_key": str(
            config.get("numbuh_2x4_hermes_session_key", "") or ""
        ),
        "numbuh_2x4_hermes_api_key_set": bool(config.get("numbuh_2x4_hermes_api_key")),
        "numbuh_2x4_hermes_api_key_preview": _mask_api_key(
            str(config.get("numbuh_2x4_hermes_api_key", "") or "")
        ),
        "numbuh_2x4_enabled": numbuh_2x4_enabled,
        "numbuh_2x4_ws_url": numbuh_2x4_ws_url,
        "numbuh_2x4_token_set": bool(numbuh_2x4_token),
        "numbuh_2x4_token_preview": _mask_api_key(numbuh_2x4_token),
        "numbuh_2x4_service_token_set": bool(NUMBUH_2X4_SERVICE_TOKEN),
        "numbuh_2x4_service_token_preview": _mask_api_key(NUMBUH_2X4_SERVICE_TOKEN),
        "numbuh_2x4_takeover_prompt_set": bool(numbuh_2x4_takeover_prompt),
        "numbuh_2x4_takeover_prompt_preview": _preview_prompt(numbuh_2x4_takeover_prompt),
        "voice_call_set_in_bra": bool(config.get("voice_call_set_in_bra", False)),
        "voice_call_cloudflared_tunnel_name": str(
            config.get("voice_call_cloudflared_tunnel_name", "") or ""
        ),
        "voice_call_cloudflared_config_path": str(
            config.get("voice_call_cloudflared_config_path", "") or ""
        ),
        "voice_call_provider": _normalize_voice_call_provider(config.get("voice_call_provider")),
        "voice_call_from_number": str(config.get("voice_call_from_number", "") or ""),
        "voice_call_to_number": str(config.get("voice_call_to_number", "") or ""),
        "voice_call_public_url": str(config.get("voice_call_public_url", "") or ""),
        "voice_call_twilio_account_sid": str(config.get("voice_call_twilio_account_sid", "") or ""),
        "voice_call_twilio_account_sid_preview": _mask_api_key(
            str(config.get("voice_call_twilio_account_sid", "") or "")
        ),
        "voice_call_twilio_auth_token_set": bool(config.get("voice_call_twilio_auth_token")),
        "voice_call_twilio_auth_token_preview": _mask_api_key(
            str(config.get("voice_call_twilio_auth_token", "") or "")
        ),
        "voice_call_control_boots_base_url": str(
            config.get("voice_call_control_boots_base_url", "http://127.0.0.1:7090") or "http://127.0.0.1:7090"
        ),
        "voice_call_control_boots_service_token_set": bool(voice_call_control_token),
        "voice_call_control_boots_service_token_preview": _mask_api_key(voice_call_control_token),
        "numbuh_2x4_call_agent_provider": _normalize_2x4_agent_provider(
            config.get("numbuh_2x4_call_agent_provider")
        ),
        # Backward compatibility for older clients
        "openclaw_enabled": numbuh_2x4_enabled,
        "openclaw_ws_url": numbuh_2x4_ws_url,
        "openclaw_token_set": bool(numbuh_2x4_token),
        "openclaw_token_preview": _mask_api_key(numbuh_2x4_token),
        "ner_endpoint": config.get("ner_endpoint", ""),
        "local_model_endpoint": config.get("local_model_endpoint", ""),
        "proxy_enabled": proxy_cfg["proxy_enabled"],
        "proxy_port": proxy_cfg["proxy_port"],
        "proxy_backend_url": proxy_cfg["proxy_backend_url"],
        "proxy_backend_api_key_set": bool(proxy_cfg["proxy_backend_api_key"]),
        "proxy_model_map": proxy_cfg["proxy_model_map"],
        "proxy_context_window": proxy_cfg["proxy_context_window"],
        "proxy_max_completion_tokens": proxy_cfg["proxy_max_completion_tokens"],
    }


@app.post("/api/config")
async def set_config(request: dict, _: bool = Depends(verify_token)):
    """Update configuration."""
    global BRA_DIR
    
    bra_dir = request.get("bra_dir", "").strip()
    model = request.get("model")
    anthropic_api_key = request.get("anthropic_api_key")
    clear_api_key = bool(request.get("clear_api_key", False))
    chat_provider = request.get("chat_provider")
    numbuh_2x4_agent_provider = request.get("numbuh_2x4_agent_provider")
    numbuh_2x4_hermes_base_url = request.get("numbuh_2x4_hermes_base_url")
    numbuh_2x4_hermes_session_key = request.get("numbuh_2x4_hermes_session_key")
    numbuh_2x4_hermes_api_key = request.get("numbuh_2x4_hermes_api_key")
    clear_numbuh_2x4_hermes_api_key = bool(request.get("clear_numbuh_2x4_hermes_api_key", False))
    numbuh_2x4_enabled = request.get("numbuh_2x4_enabled", request.get("openclaw_enabled"))
    numbuh_2x4_ws_url = request.get("numbuh_2x4_ws_url", request.get("openclaw_ws_url"))
    numbuh_2x4_token = request.get("numbuh_2x4_token", request.get("openclaw_token"))
    numbuh_2x4_service_token = request.get("numbuh_2x4_service_token")
    numbuh_2x4_takeover_prompt = request.get(
        "numbuh_2x4_takeover_prompt",
        request.get("openclaw_takeover_prompt"),
    )
    clear_numbuh_2x4_token = bool(
        request.get("clear_numbuh_2x4_token", request.get("clear_openclaw_token", False))
    )
    clear_numbuh_2x4_takeover_prompt = bool(
        request.get(
            "clear_numbuh_2x4_takeover_prompt",
            request.get("clear_openclaw_takeover_prompt", False),
        )
    )
    clear_numbuh_2x4_service_token = bool(request.get("clear_numbuh_2x4_service_token", False))
    voice_call_set_in_bra = request.get("voice_call_set_in_bra")
    voice_call_cloudflared_tunnel_name = request.get("voice_call_cloudflared_tunnel_name")
    voice_call_cloudflared_config_path = request.get("voice_call_cloudflared_config_path")
    voice_call_provider = request.get("voice_call_provider")
    voice_call_from_number = request.get("voice_call_from_number")
    voice_call_to_number = request.get("voice_call_to_number")
    voice_call_public_url = request.get("voice_call_public_url")
    voice_call_twilio_account_sid = request.get("voice_call_twilio_account_sid")
    voice_call_twilio_auth_token = request.get("voice_call_twilio_auth_token")
    clear_voice_call_twilio_auth_token = bool(
        request.get("clear_voice_call_twilio_auth_token", False)
    )
    voice_call_control_boots_base_url = request.get("voice_call_control_boots_base_url")
    voice_call_control_boots_service_token = request.get("voice_call_control_boots_service_token")
    clear_voice_call_control_boots_service_token = bool(
        request.get("clear_voice_call_control_boots_service_token", False)
    )
    numbuh_2x4_call_agent_provider = request.get("numbuh_2x4_call_agent_provider")
    ner_endpoint = request.get("ner_endpoint")
    local_model_endpoint = request.get("local_model_endpoint")
    proxy_enabled = request.get("proxy_enabled")
    proxy_port = request.get("proxy_port")
    proxy_backend_url = request.get("proxy_backend_url")
    proxy_backend_api_key = request.get("proxy_backend_api_key")
    proxy_model_map = request.get("proxy_model_map")
    proxy_context_window = request.get("proxy_context_window")
    proxy_max_completion_tokens = request.get("proxy_max_completion_tokens")

    if bra_dir:
        # Validate the path
        path = Path(bra_dir).expanduser().resolve()
        if not path.exists():
            raise HTTPException(status_code=400, detail=f"Directory does not exist: {bra_dir}")
        resolved = _resolve_bra_body_and_project_roots(path)
        if not resolved:
            raise HTTPException(
                status_code=400,
                detail=f"Not a valid BRA project (missing .bra folder): {bra_dir}",
            )
        body_root, project_root = resolved
        bra_dir = str(project_root)
        try:
            from bra.config.settings import set_bra_root

            set_bra_root(project_root)
        except Exception:
            pass

    # Save to config
    config = load_config()
    config["bra_dir"] = bra_dir
    config["model"] = model
    if chat_provider is not None:
        config["chat_provider"] = _normalize_chat_provider(str(chat_provider))
    else:
        config["chat_provider"] = _normalize_chat_provider(config.get("chat_provider"))
    if numbuh_2x4_agent_provider is not None:
        config["numbuh_2x4_agent_provider"] = _normalize_2x4_agent_provider(
            str(numbuh_2x4_agent_provider)
        )
    else:
        config["numbuh_2x4_agent_provider"] = _normalize_2x4_agent_provider(
            config.get("numbuh_2x4_agent_provider")
        )
    if numbuh_2x4_hermes_base_url is not None:
        hermes_base_url = str(numbuh_2x4_hermes_base_url).strip()
        if hermes_base_url:
            config["numbuh_2x4_hermes_base_url"] = hermes_base_url
        else:
            config.pop("numbuh_2x4_hermes_base_url", None)
    if numbuh_2x4_hermes_session_key is not None:
        hermes_session_key = str(numbuh_2x4_hermes_session_key).strip()
        if hermes_session_key:
            config["numbuh_2x4_hermes_session_key"] = hermes_session_key
        else:
            config.pop("numbuh_2x4_hermes_session_key", None)
    if clear_numbuh_2x4_hermes_api_key:
        config.pop("numbuh_2x4_hermes_api_key", None)
    elif numbuh_2x4_hermes_api_key is not None:
        hermes_api_key = str(numbuh_2x4_hermes_api_key).strip()
        if hermes_api_key:
            config["numbuh_2x4_hermes_api_key"] = hermes_api_key
    if numbuh_2x4_enabled is not None:
        config["numbuh_2x4_enabled"] = bool(numbuh_2x4_enabled)
    else:
        config["numbuh_2x4_enabled"] = bool(config.get("numbuh_2x4_enabled", config.get("openclaw_enabled", False)))
    if numbuh_2x4_ws_url is not None:
        config["numbuh_2x4_ws_url"] = str(numbuh_2x4_ws_url).strip()
    else:
        config["numbuh_2x4_ws_url"] = str(
            config.get("numbuh_2x4_ws_url", config.get("openclaw_ws_url", ""))
        ).strip()
    # Keep legacy OpenClaw bootstrap keys in sync for deterministic config reuse
    # across older tooling/scripts that still read openclaw_* fields directly.
    config["openclaw_enabled"] = bool(config.get("numbuh_2x4_enabled", False))
    config["openclaw_ws_url"] = str(config.get("numbuh_2x4_ws_url", "")).strip()
    if clear_api_key:
        config.pop("anthropic_api_key", None)
        os.environ.pop("ANTHROPIC_API_KEY", None)
    elif anthropic_api_key is not None:
        api_key_value = str(anthropic_api_key).strip()
        if api_key_value:
            config["anthropic_api_key"] = api_key_value
            os.environ["ANTHROPIC_API_KEY"] = api_key_value
    if clear_numbuh_2x4_token:
        config.pop("numbuh_2x4_token", None)
        config.pop("openclaw_token", None)
    elif numbuh_2x4_token is not None:
        numbuh_2x4_value = str(numbuh_2x4_token).strip()
        if numbuh_2x4_value:
            config["numbuh_2x4_token"] = numbuh_2x4_value
            # Keep legacy key for backward compatibility
            config["openclaw_token"] = numbuh_2x4_value
    if clear_numbuh_2x4_takeover_prompt:
        config.pop("numbuh_2x4_takeover_prompt", None)
        config.pop("openclaw_takeover_prompt", None)
    elif numbuh_2x4_takeover_prompt is not None:
        prompt_value = str(numbuh_2x4_takeover_prompt).strip()
        if prompt_value:
            config["numbuh_2x4_takeover_prompt"] = prompt_value
            config["openclaw_takeover_prompt"] = prompt_value
        else:
            config.pop("numbuh_2x4_takeover_prompt", None)
            config.pop("openclaw_takeover_prompt", None)
    if clear_numbuh_2x4_service_token:
        _clear_2x4_service_token()
    elif numbuh_2x4_service_token is not None:
        service_token_value = str(numbuh_2x4_service_token).strip()
        if service_token_value:
            _set_2x4_service_token(service_token_value)
    if voice_call_set_in_bra is not None:
        config["voice_call_set_in_bra"] = bool(voice_call_set_in_bra)
    else:
        config["voice_call_set_in_bra"] = bool(config.get("voice_call_set_in_bra", False))
    if numbuh_2x4_call_agent_provider is not None:
        config["numbuh_2x4_call_agent_provider"] = _normalize_2x4_agent_provider(
            str(numbuh_2x4_call_agent_provider)
        )
    else:
        config["numbuh_2x4_call_agent_provider"] = _normalize_2x4_agent_provider(
            config.get("numbuh_2x4_call_agent_provider")
        )

    # Always allow storing public webhook URL, regardless of Set-in-BRA toggle.
    if voice_call_public_url is not None:
        public_url_value = str(voice_call_public_url).strip()
        if public_url_value:
            config["voice_call_public_url"] = public_url_value
        else:
            config.pop("voice_call_public_url", None)

    # Always allow configuring voice control callback target + service token,
    # regardless of Set-in-BRA toggle state.
    if voice_call_control_boots_base_url is not None:
        boots_url_value = str(voice_call_control_boots_base_url).strip()
        if boots_url_value:
            config["voice_call_control_boots_base_url"] = boots_url_value
        else:
            config.pop("voice_call_control_boots_base_url", None)
    if clear_voice_call_control_boots_service_token:
        config.pop("voice_call_control_boots_service_token", None)
    elif voice_call_control_boots_service_token is not None:
        boots_token_value = str(voice_call_control_boots_service_token).strip()
        if boots_token_value:
            config["voice_call_control_boots_service_token"] = boots_token_value

    if config["voice_call_set_in_bra"]:
        if voice_call_provider is not None:
            config["voice_call_provider"] = _normalize_voice_call_provider(voice_call_provider)
        if voice_call_cloudflared_tunnel_name is not None:
            tunnel_name_value = str(voice_call_cloudflared_tunnel_name).strip()
            if tunnel_name_value:
                config["voice_call_cloudflared_tunnel_name"] = tunnel_name_value
            else:
                config.pop("voice_call_cloudflared_tunnel_name", None)
        if voice_call_cloudflared_config_path is not None:
            config_path_value = str(voice_call_cloudflared_config_path).strip()
            if config_path_value:
                config["voice_call_cloudflared_config_path"] = config_path_value
            else:
                config.pop("voice_call_cloudflared_config_path", None)
        if voice_call_from_number is not None:
            from_value = str(voice_call_from_number).strip()
            if from_value:
                config["voice_call_from_number"] = from_value
            else:
                config.pop("voice_call_from_number", None)
        if voice_call_to_number is not None:
            to_value = str(voice_call_to_number).strip()
            if to_value:
                config["voice_call_to_number"] = to_value
            else:
                config.pop("voice_call_to_number", None)
        if voice_call_twilio_account_sid is not None:
            sid_value = str(voice_call_twilio_account_sid).strip()
            if sid_value:
                config["voice_call_twilio_account_sid"] = sid_value
            else:
                config.pop("voice_call_twilio_account_sid", None)
        if clear_voice_call_twilio_auth_token:
            config.pop("voice_call_twilio_auth_token", None)
        elif voice_call_twilio_auth_token is not None:
            token_value = str(voice_call_twilio_auth_token).strip()
            if token_value:
                config["voice_call_twilio_auth_token"] = token_value
    if ner_endpoint is not None:
        config["ner_endpoint"] = str(ner_endpoint).strip()
    if local_model_endpoint is not None:
        config["local_model_endpoint"] = str(local_model_endpoint).strip()
    if proxy_enabled is not None:
        config["proxy_enabled"] = bool(proxy_enabled)
    if proxy_port is not None:
        config["proxy_port"] = int(proxy_port)
    if proxy_backend_url is not None:
        config["proxy_backend_url"] = str(proxy_backend_url).strip()
    if proxy_backend_api_key is not None:
        config["proxy_backend_api_key"] = str(proxy_backend_api_key).strip()
    if proxy_model_map is not None and isinstance(proxy_model_map, dict):
        config["proxy_model_map"] = proxy_model_map
    if proxy_context_window is not None:
        config["proxy_context_window"] = int(proxy_context_window)
    if proxy_max_completion_tokens is not None:
        config["proxy_max_completion_tokens"] = int(proxy_max_completion_tokens)
    save_config(config)
    # Dual-write proxy config to ~/.bra-tui-config.json so engage.py sees it
    set_runtime_config(
        proxy_enabled=config.get("proxy_enabled"),
        proxy_port=config.get("proxy_port"),
        proxy_backend_url=config.get("proxy_backend_url"),
        proxy_backend_api_key=config.get("proxy_backend_api_key"),
        proxy_model_map=config.get("proxy_model_map"),
        proxy_context_window=config.get("proxy_context_window"),
        proxy_max_completion_tokens=config.get("proxy_max_completion_tokens"),
        persist=True,
    )
    _resolve_2x4_controller_from_config()
    try:
        _sync_2x4_governance_tokens(bra_dir, config=config)
    except Exception as exc:
        logging.debug("Failed to sync 2x4 governance tokens during /api/config POST: %s", exc)

    # Update global
    BRA_DIR = bra_dir
    if model:
        os.environ["BRA_MODEL"] = str(model)

    api_key, api_key_source = _resolve_api_key(config)
    saved_numbuh_2x4_enabled, saved_numbuh_2x4_ws_url, saved_numbuh_2x4_token = _resolve_numbuh_2x4_settings(config)
    saved_numbuh_2x4_takeover_prompt = _resolve_numbuh_2x4_takeover_prompt(config)
    saved_voice_call_control_token = _resolve_voice_call_control_boots_service_token(config)

    return {
        "status": "ok",
        "bra_dir": bra_dir,
        "model": model,
        "api_key_set": bool(api_key),
        "api_key_source": api_key_source,
        "api_key_preview": _mask_api_key(api_key),
        "chat_provider": _normalize_chat_provider(config.get("chat_provider")),
        "numbuh_2x4_enabled": saved_numbuh_2x4_enabled,
        "numbuh_2x4_ws_url": saved_numbuh_2x4_ws_url,
        "numbuh_2x4_token_set": bool(saved_numbuh_2x4_token),
        "numbuh_2x4_token_preview": _mask_api_key(saved_numbuh_2x4_token),
        "numbuh_2x4_service_token_set": bool(NUMBUH_2X4_SERVICE_TOKEN),
        "numbuh_2x4_service_token_preview": _mask_api_key(NUMBUH_2X4_SERVICE_TOKEN),
        "numbuh_2x4_takeover_prompt_set": bool(saved_numbuh_2x4_takeover_prompt),
        "numbuh_2x4_takeover_prompt_preview": _preview_prompt(saved_numbuh_2x4_takeover_prompt),
        "voice_call_set_in_bra": bool(config.get("voice_call_set_in_bra", False)),
        "voice_call_cloudflared_tunnel_name": str(
            config.get("voice_call_cloudflared_tunnel_name", "") or ""
        ),
        "voice_call_cloudflared_config_path": str(
            config.get("voice_call_cloudflared_config_path", "") or ""
        ),
        "voice_call_provider": _normalize_voice_call_provider(config.get("voice_call_provider")),
        "voice_call_from_number": str(config.get("voice_call_from_number", "") or ""),
        "voice_call_to_number": str(config.get("voice_call_to_number", "") or ""),
        "voice_call_public_url": str(config.get("voice_call_public_url", "") or ""),
        "voice_call_twilio_account_sid": str(config.get("voice_call_twilio_account_sid", "") or ""),
        "voice_call_twilio_account_sid_preview": _mask_api_key(
            str(config.get("voice_call_twilio_account_sid", "") or "")
        ),
        "voice_call_twilio_auth_token_set": bool(config.get("voice_call_twilio_auth_token")),
        "voice_call_twilio_auth_token_preview": _mask_api_key(
            str(config.get("voice_call_twilio_auth_token", "") or "")
        ),
        "voice_call_control_boots_base_url": str(
            config.get("voice_call_control_boots_base_url", "http://127.0.0.1:7090") or "http://127.0.0.1:7090"
        ),
        "voice_call_control_boots_service_token_set": bool(saved_voice_call_control_token),
        "voice_call_control_boots_service_token_preview": _mask_api_key(saved_voice_call_control_token),
        # Backward compatibility for older clients
        "openclaw_enabled": saved_numbuh_2x4_enabled,
        "openclaw_ws_url": saved_numbuh_2x4_ws_url,
        "openclaw_token_set": bool(saved_numbuh_2x4_token),
        "openclaw_token_preview": _mask_api_key(saved_numbuh_2x4_token),
    }


@app.get("/api/proxy/status")
async def proxy_status(_: bool = Depends(verify_token)):
    """Return proxy sidecar health status."""
    proxy_cfg = get_proxy_config()
    sidecar = getattr(_engage_manager, "_proxy_sidecar", None)
    return {
        "enabled": proxy_cfg["proxy_enabled"],
        "running": sidecar.is_running if sidecar else False,
        "port": proxy_cfg["proxy_port"],
        "backend_url": proxy_cfg["proxy_backend_url"],
        "backend_key_set": bool(proxy_cfg["proxy_backend_api_key"]),
        "pid": sidecar._process.pid if (sidecar and sidecar._process and sidecar._process.poll() is None) else None,
        "healthy": sidecar.is_running if sidecar else False,
        "config_path": str(sidecar.config_path) if sidecar else "",
        "log_path": str(sidecar.log_path) if sidecar else "",
        "model_map": proxy_cfg["proxy_model_map"],
        "context_window": proxy_cfg["proxy_context_window"],
        "max_completion_tokens": proxy_cfg["proxy_max_completion_tokens"],
        "last_error": "",
    }


@app.post("/api/proxy/start")
async def proxy_start(_: bool = Depends(verify_token)):
    """Manually start the LiteLLM proxy sidecar."""
    proxy_cfg = get_proxy_config()
    if not proxy_cfg["proxy_enabled"]:
        return {"error": "Proxy not enabled in config"}
    await _engage_manager._ensure_proxy_running()
    sidecar = getattr(_engage_manager, "_proxy_sidecar", None)
    return {
        "ok": sidecar.is_running if sidecar else False,
        "error": "" if (sidecar and sidecar.is_running) else "Failed to start",
    }


@app.post("/api/proxy/stop")
async def proxy_stop(_: bool = Depends(verify_token)):
    """Manually stop the LiteLLM proxy sidecar."""
    sidecar = getattr(_engage_manager, "_proxy_sidecar", None)
    if sidecar:
        sidecar.stop()
    return {"ok": True}


def _build_target_summary(target: dict, intel_content: str = "") -> str:
    """Build a compact one-line summary for a target entry."""
    ttype = target.get("type", "local")
    text = target.get("text", "")

    if ttype == "network":
        # Prefer labeled target/device IPs over client/operator IPs
        target_ip = re.search(
            r'(?:Dongle|Target|Device|Server|Host)\s+IP[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)',
            text, re.IGNORECASE)
        if target_ip:
            return target_ip.group(1)
        # Find all IPs, skip any labeled as Client/Operator
        _IP_PAT = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?'
        all_ips = [(m.start(), m.group()) for m in re.finditer(_IP_PAT, text)]
        skip_prefixes = re.finditer(r'(?:Client|Operator)\s+IP[:\s]+(' + _IP_PAT + r')', text, re.IGNORECASE)
        skip_set = {m.group(1) for m in skip_prefixes}
        non_client = [ip for _, ip in all_ips if ip not in skip_set]
        if non_client:
            return non_client[0]
        # Fallback: last IP found (most likely the target)
        if all_ips:
            return all_ips[-1][1]
        return text.split(" — ")[0].strip()[:40]

    if ttype == "usb":
        if intel_content:
            usb_match = re.search(r'(?:USB|usb)\s+(?:port|bus)[:\s]+(\S+)', intel_content, re.IGNORECASE)
            if usb_match:
                return usb_match.group(1)
        return "Bus(Port) TBD"

    if ttype == "bt":
        if intel_content:
            bt_name = re.search(r'(?:BT|Bluetooth)\s+(?:device|name)[:\s]+([^\n|]+)', intel_content, re.IGNORECASE)
            if bt_name:
                return bt_name.group(1).strip()
            bt_mac = re.search(r'(?:BT|Bluetooth)\s+MAC[:\s]+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})', intel_content, re.IGNORECASE)
            if bt_mac:
                return bt_mac.group(1)
        return "OUI TBD"

    parts = text.split(" — ")
    return parts[0].strip() if parts else text


@app.get("/api/engagement")
async def get_engagement(_: bool = Depends(verify_token)):
    """Get current engagement status."""
    # Try to read engagement.json
    engagement_file = get_bra_path("engagement.json")
    if engagement_file.exists():
        return json.loads(engagement_file.read_text())
    
    # Synthesize from available data
    bra_dir = get_bra_path()
    bra_root = get_bra_dir()
    artifacts_dir = get_bra_path("artifacts")
    logs_dir = get_bra_path("logs")

    # Count artifacts
    artifact_count = 0
    if artifacts_dir.exists():
        artifact_count = sum(1 for _ in artifacts_dir.rglob("*") if _.is_file())

    # Get log files info
    log_files = []
    if logs_dir.exists():
        log_files = [f.name for f in logs_dir.iterdir() if f.is_file()]

    # Check for findings
    findings_count = 0
    findings_dir = get_bra_path("artifacts", "findings")
    if findings_dir.exists():
        findings_count = sum(1 for _ in findings_dir.glob("*.json"))

    # Read engagement meta (written by TUI scope wizard / end engagement)
    engagement_meta = {}
    meta_file = get_bra_path("engagement_meta.json")
    if meta_file.exists():
        try:
            engagement_meta = json.loads(meta_file.read_text())
        except (json.JSONDecodeError, IOError):
            pass

    # Status: Active only if engagement was started and not ended
    has_started = bool(engagement_meta.get("started_at"))
    has_ended = bool(engagement_meta.get("ended_at"))
    eng_status = "Active" if has_started and not has_ended else "Inactive"

    # Start time from engagement meta
    start_time = engagement_meta.get("started_at")
    
    # Read scope info from layer3-engagement/SCOPE.md
    scope_info = {}
    scope_file = _body_root(bra_root) / "layer3-engagement" / "SCOPE.md" if bra_root else None
    engagement_anon_highlights: list[dict] = []
    if scope_file and scope_file.exists():
        scope_content = scope_file.read_text()
        scope_content, engagement_anon_highlights = _anon_unmask_content(scope_content)
        scope_info["raw"] = scope_content
        # Parse key fields
        import re
        name_match = re.search(r'\*\*Name:\*\*\s*(.+)', scope_content)
        # Support both **Target Type:** and **Type:**
        type_match = re.search(r'\*\*(?:Target )?Type:\*\*\s*(.+)', scope_content)
        method_match = re.search(r'\*\*Methodology:\*\*\s*(.+)', scope_content)
        status_match = re.search(r'\*\*Status:\*\*\s*(.+)', scope_content)
        # Support **Authorization: Yes**, **Authorization:** Yes, and **Authorization: Yes**
        auth_match = re.search(r'\*\*Authorization:\s*(\w+)\*\*', scope_content) or \
                     re.search(r'\*\*Authorization:\*\*\s*(\w+)', scope_content)
        active_match = re.search(r'ACTIVE-TESTING-APPROVAL:\s*(\w+)', scope_content)

        # Extract targets — supports unified ### Targets with [TAG] prefixes
        # and legacy ### Local Targets / ### Network Targets sections
        # Metadata labels that are NOT targets (contextual info about a target)
        _META_LABELS = re.compile(
            r'^\*\*(?:MAC|Hotspot|SSID|Password|Operator|Client|Gateway|Subnet|DNS|Interface)\b',
            re.IGNORECASE)

        def _strip_md(text):
            """Strip markdown formatting (bold, backticks) from a string."""
            text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)  # bold
            text = re.sub(r'`([^`]+)`', r'\1', text)      # inline code
            return text.strip()

        def _parse_target_section(pattern):
            """Extract bullet items from a markdown section, filtering metadata."""
            match = re.search(pattern, scope_content, re.DOTALL | re.IGNORECASE)
            if not match:
                return []
            items = []
            for line in match.group(1).strip().splitlines():
                text = line.strip().lstrip('-').lstrip('*').strip()
                if not text or text.lower() in ('none', 'none specified', 'n/a'):
                    continue
                # Skip metadata lines (MAC, Hotspot SSID, passwords, etc.)
                if _META_LABELS.match(text):
                    continue
                items.append(_strip_md(text))
            return items

        # Try unified format first: ### Targets (with optional [TAG] prefixes)
        _TAG_RE = re.compile(r'^\[(NET|LOCAL|BT|USB)\]\s*', re.IGNORECASE)
        unified_raw = _parse_target_section(
            r'###?\s*Targets\s*\n(.*?)(?=\n---|\n###|\n##|$)')

        def _infer_type(text):
            """Lightweight type inference for untagged targets (display only)."""
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|https?://|/\d{1,2}\b', text):
                return "network"
            if re.search(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', text) or \
               re.search(r'\b(?:bluetooth|ble|bt)\b', text, re.IGNORECASE):
                return "bt"
            if re.search(r'\busb\b', text, re.IGNORECASE):
                return "usb"
            return "local"

        if unified_raw:
            # Parse lines — tagged or untagged
            all_targets = []
            for entry in unified_raw:
                tag_m = _TAG_RE.match(entry)
                if tag_m:
                    tag = tag_m.group(1).upper()
                    text = entry[tag_m.end():]
                    ttype = {"NET": "network", "LOCAL": "local", "BT": "bt", "USB": "usb"}.get(tag, "local")
                else:
                    text = entry
                    ttype = _infer_type(text)
                all_targets.append({"text": text, "type": ttype})
            local_targets = [t["text"] for t in all_targets if t["type"] == "local"]
            network_targets = [t["text"] for t in all_targets if t["type"] == "network"]
        else:
            # Legacy format: separate sections
            local_targets = _parse_target_section(
                r'###?\s*Local\s+Targets.*?\n(.*?)(?=\n---|\n###|\n##|$)')
            network_targets = _parse_target_section(
                r'###?\s*Network\s+(?:Targets|Constraints).*?\n(.*?)(?=\n---|\n###|\n##|$)')
            # Build all_targets with type inference so USB/BT items get correct badges
            all_targets = [
                *[{"text": t, "type": _infer_type(t)} for t in local_targets],
                *[{"text": t, "type": "network"} for t in network_targets],
            ]

        # Extract in-scope and out-of-scope activities
        in_scope_match = re.search(r'##\s*In-Scope(?:\s+Activities)?\s*\n(.*?)(?=\n---|\n##|$)', scope_content, re.DOTALL)
        out_scope_match = re.search(r'##\s*Out-of-Scope\s*\n(.*?)(?=\n---|\n##|$)', scope_content, re.DOTALL)
        # Extract operator IP from SCOPE.md
        operator_ip_match = re.search(r'\*\*Operator\s+IP:\*\*\s*(\S+)', scope_content)
        # Extract time window
        start_date_match = re.search(r'\*\*Start:\*\*\s*(.+)', scope_content)
        end_date_match = re.search(r'\*\*End:\*\*\s*(.+)', scope_content)

        scope_info["name"] = name_match.group(1).strip() if name_match else None
        scope_info["target_type"] = type_match.group(1).strip() if type_match else None
        scope_info["methodology"] = method_match.group(1).strip() if method_match else None
        scope_info["status"] = status_match.group(1).strip() if status_match else None
        scope_info["authorized"] = auth_match.group(1).strip() if auth_match else None
        scope_info["active_testing"] = active_match.group(1).strip() if active_match else None
        scope_info["network_targets"] = network_targets
        scope_info["local_targets"] = local_targets
        if all_targets is not None:
            scope_info["targets"] = all_targets
        else:
            scope_info["targets"] = [
                *[{"text": t, "type": "local"} for t in local_targets],
                *[{"text": t, "type": "network"} for t in network_targets],
            ]
        scope_info["in_scope"] = in_scope_match.group(1).strip().lstrip('- ') if in_scope_match else None
        scope_info["out_of_scope"] = out_scope_match.group(1).strip().lstrip('- ') if out_scope_match else None
        scope_info["operator_ip"] = operator_ip_match.group(1).strip() if operator_ip_match else None
        scope_info["start_date"] = start_date_match.group(1).strip() if start_date_match else None
        scope_info["end_date"] = end_date_match.group(1).strip() if end_date_match else None

    # Read INTEL.md for target summary cross-reference
    intel_content = ""
    intel_file = _body_root(bra_root) / "layer3-engagement" / "NOTES" / "INTEL.md" if bra_root else None
    if intel_file and intel_file.exists():
        try:
            intel_content = intel_file.read_text(errors="replace")
        except Exception:
            pass

    # Add summary field to each target
    for t in scope_info.get("targets", []):
        t["summary"] = _build_target_summary(t, intel_content)

    # Operator IPs from engagement_meta.json (captured at engagement start)
    scope_info["operator_internal_ips"] = engagement_meta.get("operator_internal_ips", [])
    scope_info["operator_external_ip"] = engagement_meta.get("operator_external_ip")
    scope_info["operator_relevant_ip"] = engagement_meta.get("operator_relevant_ip")

    # Pending findings count for status indicator
    pending_findings_count = 0
    pending_file = _body_root(bra_root) / ".bra" / "pending_findings.json" if bra_root else None
    if pending_file and pending_file.exists():
        try:
            pending_data = json.loads(pending_file.read_text())
            if isinstance(pending_data, list):
                pending_findings_count = len(pending_data)
            elif isinstance(pending_data, dict):
                pending_findings_count = len(pending_data.get("pending", []))
        except Exception:
            pass

    return {
        "status": eng_status,
        "bra_path": str(Path(bra_root)) if bra_root else None,
        "start_time": start_time,
        "artifact_count": artifact_count,
        "finding_count": findings_count,
        "pending_findings_count": pending_findings_count,
        "log_files": log_files,
        "lifecycle": {
            "functional": (get_bra_path("PRECHECK_REPORT.md")).exists(),
            "ready": False,
            "in_progress": False,
            "finalized": False,
            "ingested": False,
        },
        "scope": scope_info,
        "anon_highlights": engagement_anon_highlights,
    }


@app.get("/api/summary")
async def get_summary(_: bool = Depends(verify_token)):
    """Get rich summary content from layer3-engagement/STATS.md."""

    bra_root = get_bra_dir()
    if not bra_root:
        return {"exists": False, "message": "No BRA directory configured."}

    stats_file = _body_root(bra_root) / "layer3-engagement" / "STATS.md"
    if not stats_file.exists():
        return {
            "exists": False,
            "message": "No STATS.md found. Run End Engagement to generate.",
        }

    stats_parsed = parse_stats_markdown(stats_file.read_text())

    # Pull target from scope metadata when available.
    scope_file = _body_root(bra_root) / "layer3-engagement" / "SCOPE.md"
    if scope_file.exists():
        scope_content = scope_file.read_text()
        import re
        target_match = re.search(r'\*\*Name:\*\*\s*(.+)', scope_content)
        if target_match:
            target = target_match.group(1).strip()
        else:
            target = None
    else:
        target = None

    parsed = {
        "raw": stats_parsed["raw"],
        "title": stats_parsed["title"],
        "target": target,
        "generated": stats_parsed["generated"],
        "executive_summary": stats_parsed["executive_summary"],
        "phase_completion": {
            "rows": stats_parsed["phase_completion_rows"],
            "last_activity": stats_parsed["phase_last_activity"],
        },
        "finding_statistics": stats_parsed["findings"],
        "coverage_gaps": {
            "items": stats_parsed["gaps"],
            "gap_count": len(stats_parsed["gaps"]),
        },
        "recommendations": stats_parsed["recommendations_detail"],
        "lessons_learned": stats_parsed["lessons_learned"],
        "next_steps": stats_parsed["next_steps"],
    }

    # Backwards-compatible fields still used by some UI branches.
    parsed["date"] = parsed["generated"]
    parsed["tldr"] = parsed["executive_summary"]
    parsed["findings_table"] = []
    for severity, count in parsed["finding_statistics"].items():
        if severity == "TOTAL":
            continue
        parsed["findings_table"].append(
            {
                "severity": severity,
                "finding": f"{count} finding(s)",
                "cvss": "-",
            }
        )
    parsed["recommendations_flat"] = (
        parsed["recommendations"]["process_improvements"]
        + parsed["recommendations"]["template_suggestions"]
        + parsed["recommendations"]["skill_development"]
    )

    # Keep response stable: STATS.md existence means summary exists.
    return {
        "exists": True,
        "path": str(stats_file),
        "parsed": parsed,
        "modified": datetime.fromtimestamp(stats_file.stat().st_mtime).isoformat(),
    }


@app.get("/api/report")
async def get_report(_: bool = Depends(verify_token)):
    """Get disclosure report (timeline + package)."""
    import re
    bra_root = get_bra_dir()
    if not bra_root:
        return {"exists": False, "message": "No BRA directory configured."}
    
    layer3_dir = _body_root(bra_root) / "layer3-engagement"
    disclosure_dir = layer3_dir / "disclosure"
    engagement_report_file = layer3_dir / "REPORT.md"
    
    result = {
        "exists": False,
        "timeline": None,
        "package": None,
        "engagement_report": {
            "exists": False,
            "path": str(engagement_report_file),
            "content": "",
            "has_content": False,
            "modified": None,
        },
    }

    report_anon_highlights: list[dict] = []
    if engagement_report_file.exists():
        report_content = engagement_report_file.read_text()
        report_content, report_anon_highlights = _anon_unmask_content(report_content)
        # Strip template-only content so it's treated as empty
        _stripped = report_content.strip()
        _lines = [ln.strip() for ln in _stripped.splitlines() if ln.strip()]
        _template_lines = {"# Report (Instance)", "> Generate using /report-ready command."}
        _is_template_only = all(ln in _template_lines for ln in _lines)
        has_real_content = bool(_stripped) and not _is_template_only
        result["exists"] = True
        result["engagement_report"] = {
            "exists": True,
            "path": str(engagement_report_file),
            "content": report_content if has_real_content else "",
            "has_content": has_real_content,
            "modified": datetime.fromtimestamp(engagement_report_file.stat().st_mtime).isoformat(),
        }
    
    # Parse timeline
    timeline_file = disclosure_dir / "timeline.md"
    if timeline_file.exists():
        result["exists"] = True
        content = timeline_file.read_text()
        
        timeline = {
            "raw": content,
            "created": None,
            "policy": None,
            "events": [],
            "status": []
        }
        
        # Extract metadata
        created_match = re.search(r'>\s*Created:\s*(.+)', content)
        policy_match = re.search(r'>\s*Policy:\s*(.+)', content)
        if created_match:
            timeline["created"] = created_match.group(1).strip()
        if policy_match:
            timeline["policy"] = policy_match.group(1).strip()
        
        # Parse timeline table
        table_match = re.search(r'\| Date \| Day \| Event \| Status \| Notes \|\n\|[-|\s]+\|\n((?:\|.+\n)+)', content)
        if table_match:
            for line in table_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 4:
                    timeline["events"].append({
                        "date": cells[0],
                        "day": cells[1],
                        "event": cells[2],
                        "status": cells[3],
                        "notes": cells[4] if len(cells) > 4 else ""
                    })
        
        # Parse status checkboxes
        status_pattern = r'-\s*\[([ xX])\]\s*(.+)'
        for match in re.finditer(status_pattern, content):
            timeline["status"].append({
                "checked": match.group(1).lower() == 'x',
                "text": match.group(2).strip()
            })
        
        result["timeline"] = timeline
    
    # Parse disclosure package
    package_file = disclosure_dir / "disclosure-package.md"
    if package_file.exists():
        result["exists"] = True
        content = package_file.read_text()
        
        package = {
            "raw": content,
            "status": None,
            "summary": {},
            "vuln_counts": {}
        }
        
        # Extract status
        status_match = re.search(r'>\s*Status:\s*(.+)', content)
        if status_match:
            package["status"] = status_match.group(1).strip()
        
        # Parse executive summary table
        summary_match = re.search(r'## Executive Summary\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
        if summary_match:
            for line in summary_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 2:
                    package["summary"][cells[0]] = cells[1]
        
        # Parse vulnerability counts
        vuln_match = re.search(r'## Vulnerability Summary\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
        if vuln_match:
            for line in vuln_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 2 and cells[1].isdigit():
                    package["vuln_counts"][cells[0]] = int(cells[1])
        
        # Parse findings from the package
        package["findings"] = []
        finding_pattern = r'###\s*\[(\w+)\]\s*(.+?)(?=\n###\s*\[|\n---|\Z)'
        for match in re.finditer(finding_pattern, content, re.DOTALL):
            severity = match.group(1).lower()
            block = match.group(2).strip()
            lines = block.split('\n')
            title = lines[0].strip() if lines else "Unknown"
            
            finding = {"severity": severity, "title": title}
            
            # Parse fields
            field_map = {
                "affected": r'\*\*Affected artifact:\*\*\s*(.+)',
                "description": r'\*\*Short description:\*\*\s*(.+)',
                "cvss": r'CVSS[^=]*=\s*([\d.]+)\s*\((\w+)\)',
                "remediation": r'\*\*Remediation:\*\*\s*([\s\S]+?)(?=\n\n-\s*\*\*|\n\n---|\Z)',
            }
            
            for field, pattern in field_map.items():
                m = re.search(pattern, block)
                if m:
                    if field == "cvss":
                        finding["cvss_score"] = m.group(1)
                        finding["cvss_rating"] = m.group(2)
                    elif field == "remediation":
                        # Parse numbered list
                        rem_text = m.group(1).strip()
                        items = re.findall(r'\d+\.\s*(.+)', rem_text)
                        finding["remediation"] = items if items else [rem_text]
                    else:
                        finding[field] = m.group(1).strip()
            
            package["findings"].append(finding)

        # Fallback: accept schema-style findings blocks even when package
        # does not include ### [SEV] render blocks.
        if not package["findings"]:
            for parsed in parse_findings_md(content):
                severity = str(parsed.get("severity", "unknown") or "unknown").lower()
                finding = {
                    "severity": severity,
                    "title": parsed.get("title") or parsed.get("finding_id") or "Unknown",
                }
                for key in ("affected", "description", "cvss_score", "cvss_rating"):
                    value = parsed.get(key)
                    if value:
                        finding[key] = value

                remediation = parsed.get("remediation")
                if remediation:
                    rem_lines = []
                    for line in str(remediation).splitlines():
                        clean = re.sub(r'^\s*(?:[-*]|\d+\.)\s*', '', line).strip()
                        if clean:
                            rem_lines.append(clean)
                    if rem_lines:
                        finding["remediation"] = rem_lines
                package["findings"].append(finding)
        
        # Parse evidence manifest
        package["evidence"] = []
        evidence_match = re.search(r'## Evidence Manifest\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
        if evidence_match:
            for line in evidence_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 2:
                    package["evidence"].append({
                        "file": cells[0],
                        "hash": cells[1] if len(cells) > 1 else "",
                        "description": cells[2] if len(cells) > 2 else ""
                    })
        
        # Parse contact info
        package["contacts"] = {}
        contact_match = re.search(r'## Contact Information\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
        if contact_match:
            for line in contact_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 2:
                    package["contacts"][cells[0]] = cells[1]
        
        # Parse disclosure timeline from package
        package["pkg_timeline"] = []
        pkg_timeline_match = re.search(r'## Disclosure Timeline\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
        if pkg_timeline_match:
            for line in pkg_timeline_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 3:
                    package["pkg_timeline"].append({
                        "date": cells[0],
                        "action": cells[1],
                        "status": cells[2]
                    })
        
        # Parse files in package
        package["files"] = []
        files_match = re.search(r'## Files in This Package\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
        if files_match:
            for line in files_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 2:
                    package["files"].append({
                        "file": cells[0],
                        "purpose": cells[1]
                    })
        
        # Get generated date
        generated_match = re.search(r'>\s*Generated:\s*(.+)', content)
        if generated_match:
            package["generated"] = generated_match.group(1).strip()
        
        result["package"] = package
    
    # Parse vendor submission
    vendor_file = disclosure_dir / "vendor-submission.md"
    if vendor_file.exists():
        result["exists"] = True
        content = vendor_file.read_text()
        
        vendor = {
            "raw": content,
            "status": None,
            "generated": None,
            "product_info": {},
            "intro": None
        }
        
        # Extract metadata
        status_match = re.search(r'>\s*Status:\s*(.+)', content)
        gen_match = re.search(r'>\s*Generated:\s*(.+)', content)
        if status_match:
            vendor["status"] = status_match.group(1).strip()
        if gen_match:
            vendor["generated"] = gen_match.group(1).strip()
        
        # Extract introduction
        intro_match = re.search(r'## Introduction\n\n(.+?)(?=\n\n---|\n\n##)', content, re.DOTALL)
        if intro_match:
            vendor["intro"] = intro_match.group(1).strip()
        
        # Parse affected product table
        product_match = re.search(r'## Affected Product\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
        if product_match:
            for line in product_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 2:
                    vendor["product_info"][cells[0]] = cells[1]
        
        result["vendor"] = vendor
    
    # Parse vendor submission more fully
    if "vendor" in result:
        content = result["vendor"]["raw"]
        
        # Parse findings from vendor submission (same format as disclosure package)
        result["vendor"]["findings"] = []
        finding_pattern = r'###\s*\[(\w+)\]\s*(.+?)(?=\n###\s*\[|\n---|\Z)'
        for match in re.finditer(finding_pattern, content, re.DOTALL):
            severity = match.group(1).lower()
            block = match.group(2).strip()
            lines = block.split('\n')
            title = lines[0].strip() if lines else "Unknown"
            
            finding = {"severity": severity, "title": title}
            
            desc_match = re.search(r'\*\*Short description:\*\*\s*(.+)', block)
            cvss_match = re.search(r'CVSS[^=]*=\s*([\d.]+)\s*\((\w+)\)', block)
            
            if desc_match:
                finding["description"] = desc_match.group(1).strip()
            if cvss_match:
                finding["cvss_score"] = cvss_match.group(1)
            
            result["vendor"]["findings"].append(finding)
    
    # Parse CNA submission
    cna_file = disclosure_dir / "cna-submission.md"
    if cna_file.exists():
        result["exists"] = True
        content = cna_file.read_text()
        
        cna = {
            "raw": content,
            "status": None,
            "product": {},
            "vuln_type": {},
            "description": None,
            "impact": None,
            "references": [],
            "timeline": [],
            "credit": None,
            "checklist": []
        }
        
        status_match = re.search(r'>\s*Status:\s*(.+)', content)
        if status_match:
            cna["status"] = status_match.group(1).strip()
        
        # Parse product table
        product_match = re.search(r'### Product\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
        if product_match:
            for line in product_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 2:
                    cna["product"][cells[0]] = cells[1]
        
        # Parse vulnerability type table
        vuln_match = re.search(r'### Vulnerability Type\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
        if vuln_match:
            for line in vuln_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 2:
                    cna["vuln_type"][cells[0]] = cells[1]
        
        # Parse description
        desc_match = re.search(r'## Description\n\n(.+?)(?=\n\n---|\n\n##)', content, re.DOTALL)
        if desc_match:
            cna["description"] = desc_match.group(1).strip()
        
        # Parse impact
        impact_match = re.search(r'## Impact\n\n(.+?)(?=\n\n---|\n\n##)', content, re.DOTALL)
        if impact_match:
            cna["impact"] = impact_match.group(1).strip()
        
        # Parse references
        ref_match = re.search(r'## References\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
        if ref_match:
            for line in ref_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 2:
                    cna["references"].append({"type": cells[0], "url": cells[1]})
        
        # Parse timeline
        timeline_match = re.search(r'## Disclosure Timeline\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
        if timeline_match:
            for line in timeline_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 2:
                    cna["timeline"].append({"date": cells[0], "event": cells[1]})
        
        # Parse credit
        credit_match = re.search(r'## Credit\n\n(.+?)(?=\n\n---|\n\n##)', content, re.DOTALL)
        if credit_match:
            cna["credit"] = credit_match.group(1).strip()
        
        # Parse checklist
        checklist_pattern = r'-\s*\[([ xX])\]\s*(.+)'
        for match in re.finditer(checklist_pattern, content):
            cna["checklist"].append({
                "checked": match.group(1).lower() == 'x',
                "text": match.group(2).strip()
            })
        
        result["cna"] = cna
    
    if not result["exists"]:
        result["message"] = ""

    result["anon_highlights"] = report_anon_highlights

    return result


import subprocess
import signal
import time

# ttyd process management
ttyd_process = None
ttyd_port = 7681

# cloudflared quick-tunnel management (debug/diag convenience)
CLOUDFLARED_DEFAULT_TARGET_URL = "http://127.0.0.1:3334"
CLOUDFLARED_DEFAULT_WEBHOOK_PATH = "/voice/webhook"
CLOUDFLARED_TUNNEL_MODE_QUICK = "quick"
CLOUDFLARED_TUNNEL_MODE_NAMED = "named"
_cloudflared_tunnel_process: subprocess.Popen[str] | None = None
_cloudflared_tunnel_public_url: str = ""
_cloudflared_tunnel_target_url: str = CLOUDFLARED_DEFAULT_TARGET_URL
_cloudflared_tunnel_last_error: str = ""
_cloudflared_tunnel_mode: str = CLOUDFLARED_TUNNEL_MODE_QUICK
_cloudflared_tunnel_name: str = ""
_cloudflared_tunnel_config_path: str = ""


def _resolve_ttyd_binary() -> str:
    """Resolve ttyd binary path across environments."""
    detected = shutil.which("ttyd")
    if detected:
        return detected
    fallback = Path("/opt/homebrew/bin/ttyd")
    if fallback.exists():
        return str(fallback)
    raise FileNotFoundError("ttyd not installed")


def _is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) == 0


def _choose_ttyd_port(preferred: int, *, max_scan: int = 20) -> int:
    """Pick preferred ttyd port, or first free one within scan window."""
    for offset in range(max_scan + 1):
        candidate = preferred + offset
        if not _is_port_in_use(candidate):
            return candidate
    raise HTTPException(status_code=500, detail=f"No free ttyd port available in range {preferred}-{preferred + max_scan}")


def _is_managed_cloudflared_running() -> bool:
    """Return True when the in-process managed cloudflared tunnel is alive."""
    return bool(_cloudflared_tunnel_process and _cloudflared_tunnel_process.poll() is None)


def _resolve_cloudflared_webhook_path() -> str:
    """Resolve webhook path from voice config; fallback to default call webhook path."""
    try:
        config = load_config()
    except Exception:
        config = {}
    configured_public_url = str(config.get("voice_call_public_url", "") or "").strip()
    if configured_public_url:
        parsed = urlparse(configured_public_url)
        if parsed.path:
            path = parsed.path.strip()
            if path and path != "/":
                return path if path.startswith("/") else f"/{path}"
    return CLOUDFLARED_DEFAULT_WEBHOOK_PATH


def _build_cloudflared_webhook_url(public_url: str, webhook_path: str) -> str:
    """Build full webhook URL from a public base URL and a path."""
    base = str(public_url or "").strip()
    if not base:
        return ""
    path = str(webhook_path or "").strip() or CLOUDFLARED_DEFAULT_WEBHOOK_PATH
    if not path.startswith("/"):
        path = f"/{path}"
    parsed = urlparse(base)
    if parsed.path and parsed.path != "/":
        return base
    return f"{base.rstrip('/')}{path}"


def _resolve_cloudflared_named_tunnel_config(config: dict | None = None) -> tuple[str, str]:
    """Resolve optional named-tunnel settings from Boots config."""
    cfg = config if config is not None else load_config()
    tunnel_name = str(cfg.get("voice_call_cloudflared_tunnel_name", "") or "").strip()
    config_path = str(cfg.get("voice_call_cloudflared_config_path", "") or "").strip()
    return tunnel_name, config_path


def _find_external_cloudflared_named_tunnel(tunnel_name: str) -> dict[str, Any] | None:
    """Detect externally started named tunnels (`cloudflared tunnel run <name>`)."""
    resolved_name = str(tunnel_name or "").strip()
    if not resolved_name:
        return None
    try:
        output = subprocess.check_output(
            ["ps", "-Ao", "pid=,command="],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return None

    name_pattern = re.compile(rf"\bcloudflared\b.*\btunnel\s+run\s+{re.escape(resolved_name)}\b", re.IGNORECASE)
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        command = parts[1]
        if not name_pattern.search(command):
            continue
        if _is_managed_cloudflared_running() and _cloudflared_tunnel_process and pid == _cloudflared_tunnel_process.pid:
            continue
        return {"pid": pid, "command": command}

    return None


def _find_external_cloudflared_quick_tunnel(target_url: str | None = None) -> dict[str, Any] | None:
    """Detect externally started quick tunnels (cloudflared tunnel --url ...)."""
    try:
        output = subprocess.check_output(
            ["ps", "-Ao", "pid=,command="],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        command = parts[1]
        lowered = command.lower()
        if "cloudflared" not in lowered:
            continue
        if " tunnel " not in lowered:
            continue
        if "--url" not in lowered:
            continue
        if target_url and target_url not in command:
            continue
        if _is_managed_cloudflared_running() and _cloudflared_tunnel_process and pid == _cloudflared_tunnel_process.pid:
            continue
        return {"pid": pid, "command": command}

    return None


def _cloudflared_status_payload() -> dict[str, Any]:
    """Return consistent cloudflared tunnel status for Debug/Diag UI."""
    webhook_path = _resolve_cloudflared_webhook_path()
    try:
        config = load_config()
    except Exception:
        config = {}
    configured_public_url = str(config.get("voice_call_public_url", "") or "").strip()
    configured_tunnel_name, configured_config_path = _resolve_cloudflared_named_tunnel_config(config)
    if _is_managed_cloudflared_running():
        managed_pid = _cloudflared_tunnel_process.pid if _cloudflared_tunnel_process else None
        public_url = _cloudflared_tunnel_public_url
        return {
            "running": True,
            "managed": True,
            "mode": _cloudflared_tunnel_mode,
            "tunnel_name": _cloudflared_tunnel_name,
            "config_path": _cloudflared_tunnel_config_path,
            "pid": managed_pid,
            "public_url": public_url,
            "webhook_url": _build_cloudflared_webhook_url(public_url, webhook_path),
            "target_url": _cloudflared_tunnel_target_url,
            "last_error": _cloudflared_tunnel_last_error,
        }

    if configured_tunnel_name:
        external_named = _find_external_cloudflared_named_tunnel(configured_tunnel_name)
        if external_named:
            return {
                "running": True,
                "managed": False,
                "mode": CLOUDFLARED_TUNNEL_MODE_NAMED,
                "tunnel_name": configured_tunnel_name,
                "config_path": configured_config_path,
                "pid": external_named["pid"],
                "public_url": configured_public_url,
                "webhook_url": _build_cloudflared_webhook_url(configured_public_url, webhook_path),
                "target_url": _cloudflared_tunnel_target_url,
                "last_error": _cloudflared_tunnel_last_error,
                "note": "External named cloudflared tunnel detected.",
            }

    external = _find_external_cloudflared_quick_tunnel(_cloudflared_tunnel_target_url)
    if external:
        return {
            "running": True,
            "managed": False,
            "mode": CLOUDFLARED_TUNNEL_MODE_QUICK,
            "tunnel_name": "",
            "config_path": "",
            "pid": external["pid"],
            "public_url": "",
            "webhook_url": "",
            "target_url": _cloudflared_tunnel_target_url,
            "last_error": _cloudflared_tunnel_last_error,
            "note": "External cloudflared process detected (URL unknown to Boots).",
        }

    return {
        "running": False,
        "managed": False,
        "mode": CLOUDFLARED_TUNNEL_MODE_NAMED if configured_tunnel_name else CLOUDFLARED_TUNNEL_MODE_QUICK,
        "tunnel_name": configured_tunnel_name,
        "config_path": configured_config_path,
        "pid": None,
        "public_url": configured_public_url if configured_tunnel_name else "",
        "webhook_url": _build_cloudflared_webhook_url(configured_public_url, webhook_path)
        if configured_tunnel_name
        else "",
        "target_url": _cloudflared_tunnel_target_url,
        "last_error": _cloudflared_tunnel_last_error,
    }


def _read_cloudflared_public_url(proc: subprocess.Popen[str], timeout_sec: float = 8.0) -> str:
    """Read cloudflared startup output until a trycloudflare URL appears or timeout is hit."""
    pattern = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")
    if not proc.stdout:
        return ""
    try:
        os.set_blocking(proc.stdout.fileno(), False)
    except Exception:
        pass

    deadline = time.monotonic() + max(0.1, timeout_sec)
    buffer: list[str] = []

    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            chunk = proc.stdout.read() or ""
        except Exception:
            chunk = ""
        if chunk:
            buffer.append(chunk)
            match = pattern.search(chunk)
            if match:
                return match.group(0)
        time.sleep(0.05)

    if buffer:
        match = pattern.search("".join(buffer))
        if match:
            return match.group(0)
    return ""


def _terminate_cloudflared_pid(pid: int) -> None:
    """Terminate a process PID gracefully, then force-kill if needed."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _start_cloudflared_tunnel(
    target_url: str,
    *,
    tunnel_name: str = "",
    config_path: str = "",
) -> dict[str, Any]:
    """Start cloudflared quick tunnel for the configured local target URL."""
    global _cloudflared_tunnel_process, _cloudflared_tunnel_public_url, _cloudflared_tunnel_target_url
    global _cloudflared_tunnel_last_error, _cloudflared_tunnel_mode, _cloudflared_tunnel_name
    global _cloudflared_tunnel_config_path

    normalized_target = str(target_url or "").strip() or CLOUDFLARED_DEFAULT_TARGET_URL
    _cloudflared_tunnel_target_url = normalized_target
    resolved_tunnel_name = str(tunnel_name or "").strip()
    resolved_config_path = str(config_path or "").strip()

    if _is_managed_cloudflared_running():
        return _cloudflared_status_payload()

    if resolved_tunnel_name:
        external_named = _find_external_cloudflared_named_tunnel(resolved_tunnel_name)
        if external_named:
            return _cloudflared_status_payload()
    else:
        external = _find_external_cloudflared_quick_tunnel(normalized_target)
        if external:
            return _cloudflared_status_payload()

    cloudflared_bin = shutil.which("cloudflared") or "/opt/homebrew/bin/cloudflared"
    if not Path(cloudflared_bin).exists():
        raise HTTPException(status_code=500, detail="cloudflared binary not found")

    if resolved_tunnel_name:
        cmd = [cloudflared_bin, "tunnel"]
        if resolved_config_path:
            cmd.extend(["--config", resolved_config_path])
        cmd.extend(["run", resolved_tunnel_name])
    else:
        cmd = [
            cloudflared_bin,
            "tunnel",
            "--config",
            "/dev/null",
            "--no-autoupdate",
            "--protocol",
            "http2",
            "--url",
            normalized_target,
        ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to start cloudflared: {exc}")

    _cloudflared_tunnel_process = proc
    _cloudflared_tunnel_public_url = ""
    _cloudflared_tunnel_last_error = ""
    _cloudflared_tunnel_mode = (
        CLOUDFLARED_TUNNEL_MODE_NAMED if resolved_tunnel_name else CLOUDFLARED_TUNNEL_MODE_QUICK
    )
    _cloudflared_tunnel_name = resolved_tunnel_name
    _cloudflared_tunnel_config_path = resolved_config_path

    if resolved_tunnel_name:
        try:
            config = load_config()
        except Exception:
            config = {}
        _cloudflared_tunnel_public_url = str(config.get("voice_call_public_url", "") or "").strip()
        time.sleep(0.3)
    else:
        public_url = _read_cloudflared_public_url(proc, timeout_sec=8.0)
        if public_url:
            _cloudflared_tunnel_public_url = public_url

    if proc.poll() is not None:
        _cloudflared_tunnel_process = None
        _cloudflared_tunnel_last_error = "cloudflared exited during startup"
        raise HTTPException(status_code=500, detail=_cloudflared_tunnel_last_error)

    return _cloudflared_status_payload()


def _stop_cloudflared_tunnel() -> dict[str, Any]:
    """Stop managed cloudflared tunnel. Preserve external named tunnels by default."""
    global _cloudflared_tunnel_process, _cloudflared_tunnel_public_url, _cloudflared_tunnel_last_error
    global _cloudflared_tunnel_mode, _cloudflared_tunnel_name, _cloudflared_tunnel_config_path

    stopped_pid: int | None = None
    source = "none"

    if _is_managed_cloudflared_running() and _cloudflared_tunnel_process:
        stopped_pid = _cloudflared_tunnel_process.pid
        source = "managed"
        try:
            _cloudflared_tunnel_process.terminate()
            _cloudflared_tunnel_process.wait(timeout=3)
        except Exception:
            try:
                _cloudflared_tunnel_process.kill()
            except Exception:
                pass
        _cloudflared_tunnel_process = None
    else:
        _cloudflared_tunnel_process = None
        if _cloudflared_tunnel_mode == CLOUDFLARED_TUNNEL_MODE_QUICK:
            external = _find_external_cloudflared_quick_tunnel(_cloudflared_tunnel_target_url)
            if external:
                stopped_pid = int(external["pid"])
                source = "external"
                _terminate_cloudflared_pid(stopped_pid)
        else:
            source = "external_preserved"

    _cloudflared_tunnel_public_url = ""
    _cloudflared_tunnel_mode = CLOUDFLARED_TUNNEL_MODE_QUICK
    _cloudflared_tunnel_name = ""
    _cloudflared_tunnel_config_path = ""
    if source == "none":
        _cloudflared_tunnel_last_error = ""

    stopped = source in {"managed", "external"}
    return {
        "status": "ok",
        "stopped": stopped,
        "source": source,
        "pid": stopped_pid,
    }


def _persist_voice_call_public_url(webhook_url: str) -> bool:
    """Persist cloudflared webhook URL into Boots 2x4 Call config."""
    normalized = str(webhook_url or "").strip()
    if not normalized:
        return False

    config = load_config()
    if not bool(config.get("voice_call_set_in_bra", False)):
        return False
    current = str(config.get("voice_call_public_url", "") or "").strip()
    if current == normalized:
        return False

    config["voice_call_public_url"] = normalized
    save_config(config)
    try:
        _sync_2x4_governance_tokens(get_bra_dir(), config=config)
    except Exception as exc:
        _debug("sync_2x4_tokens_cloudflared_start_error", error=str(exc), bra_root=BRA_DIR or "")
    return True


@app.get("/api/live/status")
async def get_live_status(_: bool = Depends(require_debug_access)):
    """Get live terminal status."""
    global ttyd_process
    
    # Check if ttyd is running
    is_running = ttyd_process is not None and ttyd_process.poll() is None
    
    # Check for tmux sessions
    try:
        result = subprocess.run(
            ["tmux", "list-sessions", "-F", "#{session_name}"],
            capture_output=True, text=True, timeout=5
        )
        sessions = [s.strip() for s in result.stdout.strip().split('\n') if s.strip()]
    except:
        sessions = []
    
    return {
        "ttyd_running": is_running,
        "ttyd_port": ttyd_port if is_running else None,
        "tmux_sessions": sessions
    }


@app.post("/api/live/start")
async def start_live(request: dict, _: bool = Depends(require_debug_access)):
    """Start ttyd for a tmux session."""
    global ttyd_process, ttyd_port, current_tmux_session
    
    session = request.get("session", "")
    readonly = request.get("readonly", True)
    current_tmux_session = session  # Track for scroll commands
    
    if not session:
        raise HTTPException(status_code=400, detail="No tmux session specified")

    # Validate tmux session exists before launching ttyd attach command.
    try:
        exists = subprocess.run(
            ["tmux", "has-session", "-t", session],
            capture_output=True, text=True, timeout=5
        )
        if exists.returncode != 0:
            raise HTTPException(status_code=400, detail=f"tmux session not found: {session}")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="tmux not found")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="tmux session check timed out")
    
    # Kill existing ttyd if running
    if ttyd_process and ttyd_process.poll() is None:
        ttyd_process.terminate()
        try:
            ttyd_process.wait(timeout=3)
        except:
            ttyd_process.kill()
    
    # Start ttyd
    ttyd_bin = _resolve_ttyd_binary()
    selected_port = _choose_ttyd_port(ttyd_port)
    if selected_port != ttyd_port:
        _debug("live_port_reassigned", old_port=ttyd_port, new_port=selected_port, session=session)
    ttyd_port = selected_port

    cmd = [
        ttyd_bin,
        "--port", str(ttyd_port),
        "-t", "scrollback=10000",  # Allow scrolling back 10k lines
    ]
    if not readonly:
        cmd.append("--writable")
    cmd.extend(["tmux", "attach-session", "-t", session])
    
    try:
        ttyd_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True
        )
        await asyncio.sleep(0.5)  # Give it time to start
        
        if ttyd_process.poll() is not None:
            startup_err = ""
            if ttyd_process.stderr:
                startup_err = (ttyd_process.stderr.read() or "").strip()
            ttyd_process = None
            if startup_err:
                first_line = startup_err.splitlines()[0][:240]
                raise HTTPException(status_code=500, detail=f"ttyd failed to start: {first_line}")
            raise HTTPException(status_code=500, detail="ttyd failed to start")
        
        return {
            "status": "started",
            "port": ttyd_port,
            "session": session,
            "readonly": readonly
        }
    except HTTPException:
        raise
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="ttyd not installed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/live/stop")
async def stop_live(_: bool = Depends(require_debug_access)):
    """Stop ttyd."""
    global ttyd_process
    
    if ttyd_process and ttyd_process.poll() is None:
        ttyd_process.terminate()
        try:
            ttyd_process.wait(timeout=3)
        except:
            ttyd_process.kill()
        ttyd_process = None
        return {"status": "stopped"}
    
    return {"status": "not_running"}


@app.post("/api/live/spawn")
async def spawn_tmux(_: bool = Depends(require_debug_access)):
    """Spawn a new tmux session in the BRA directory."""
    # Get BRA directory from config
    bra_dir = get_bra_dir()
    if not bra_dir or not Path(bra_dir).exists():
        raise HTTPException(status_code=400, detail="BRA directory not configured or invalid")
    
    # Generate a session name
    import time
    session_name = f"bra-{int(time.time()) % 10000}"
    
    try:
        # Create new tmux session in BRA directory
        result = subprocess.run(
            ["tmux", "new-session", "-d", "-s", session_name, "-c", bra_dir],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Failed to create tmux session: {result.stderr}")
        
        return {"status": "created", "session": session_name, "directory": bra_dir}
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="tmux not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class KillRequest(BaseModel):
    session: str

@app.post("/api/live/kill")
async def kill_tmux(req: KillRequest, _: bool = Depends(require_debug_access)):
    """Kill a tmux session."""
    if not req.session:
        raise HTTPException(status_code=400, detail="Session name required")
    
    try:
        result = subprocess.run(
            ["tmux", "kill-session", "-t", req.session],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Failed to kill session: {result.stderr}")
        
        return {"status": "killed", "session": req.session}
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="tmux not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/live/scroll")
async def scroll_terminal(direction: str = "up", lines: int = 10, _: bool = Depends(require_debug_access)):
    """Scroll tmux terminal up/down. Enters copy mode if needed."""
    global current_tmux_session
    
    if not current_tmux_session:
        raise HTTPException(status_code=400, detail="No active tmux session")
    
    try:
        # Check if already in copy mode
        mode_check = subprocess.run(
            ["tmux", "display-message", "-p", "-t", current_tmux_session, "#{pane_in_mode}"],
            capture_output=True, text=True
        )
        in_copy_mode = mode_check.stdout.strip() == "1"
        
        if not in_copy_mode:
            # Enter copy mode
            subprocess.run(["tmux", "copy-mode", "-t", current_tmux_session], check=True)
        
        # Send scroll keys
        if direction == "up":
            # Scroll up using Page Up or multiple cursor-up
            for _ in range(lines):
                subprocess.run(["tmux", "send-keys", "-t", current_tmux_session, "-X", "cursor-up"], check=True)
        elif direction == "down":
            for _ in range(lines):
                subprocess.run(["tmux", "send-keys", "-t", current_tmux_session, "-X", "cursor-down"], check=True)
        elif direction == "page-up":
            subprocess.run(["tmux", "send-keys", "-t", current_tmux_session, "-X", "page-up"], check=True)
        elif direction == "page-down":
            subprocess.run(["tmux", "send-keys", "-t", current_tmux_session, "-X", "page-down"], check=True)
        elif direction == "top":
            subprocess.run(["tmux", "send-keys", "-t", current_tmux_session, "-X", "history-top"], check=True)
        elif direction == "bottom":
            subprocess.run(["tmux", "send-keys", "-t", current_tmux_session, "-X", "history-bottom"], check=True)
            subprocess.run(["tmux", "send-keys", "-t", current_tmux_session, "-X", "cancel"], check=True)
        elif direction == "exit":
            # Exit copy mode
            subprocess.run(["tmux", "send-keys", "-t", current_tmux_session, "-X", "cancel"], check=True)
        
        return {"status": "ok", "direction": direction, "lines": lines}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"tmux command failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/live/send")
async def send_to_terminal(request: dict, _: bool = Depends(require_debug_access)):
    """Send a command to the tmux session."""
    global current_tmux_session
    
    command = request.get("command", "")
    enter = request.get("enter", True)  # Whether to press Enter after
    
    if not current_tmux_session:
        raise HTTPException(status_code=400, detail="No active tmux session")
    
    if not command:
        raise HTTPException(status_code=400, detail="No command provided")
    
    try:
        # Send the command text
        subprocess.run(
            ["tmux", "send-keys", "-t", current_tmux_session, command],
            check=True
        )
        
        # Press Enter if requested
        if enter:
            subprocess.run(
                ["tmux", "send-keys", "-t", current_tmux_session, "Enter"],
                check=True
            )
        
        return {"status": "ok", "command": command, "enter": enter}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"tmux command failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Track current tmux session for scroll commands
current_tmux_session = None


# =============================================================================
# Chat Integration (file-based message queue for Clawdbot)
# =============================================================================

CHAT_FILE = Path(__file__).parent / ".bra-chat.json"

def load_chat():
    """Load chat history."""
    if CHAT_FILE.exists():
        try:
            return json.loads(CHAT_FILE.read_text())
        except:
            pass
    return {"messages": [], "pending": []}

def save_chat(data):
    """Save chat history."""
    CHAT_FILE.write_text(json.dumps(data, indent=2))


@app.get("/api/chat")
async def get_chat(_: bool = Depends(verify_token)):
    """Get chat messages."""
    chat = load_chat()
    return {
        "messages": chat.get("messages", []),
        "pending": len(chat.get("pending", []))
    }


@app.post("/api/chat")
async def send_chat(request: dict, _: bool = Depends(verify_token)):
    """Send a chat message (queued for assistant pickup)."""
    message = request.get("message", "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message required")

    message = _anon_mask_chat(message)

    chat = load_chat()

    # Add to messages
    user_msg = {
        "role": "user",
        "content": message,
        "timestamp": datetime.now().isoformat()
    }
    chat["messages"].append(user_msg)

    # Add to pending queue for assistant pickup
    chat["pending"].append(user_msg)

    save_chat(chat)
    return {"status": "queued", "message": user_msg}


@app.get("/api/chat/pending")
async def get_pending_chat(_: bool = Depends(verify_token)):
    """Get pending messages (for assistant polling)."""
    chat = load_chat()
    return {"pending": chat.get("pending", [])}


@app.post("/api/chat/respond")
async def respond_chat(request: dict, _: bool = Depends(verify_token)):
    """Add assistant response and clear pending."""
    response = request.get("message", "").strip()
    clear_pending = request.get("clear_pending", True)
    
    chat = load_chat()
    
    if response:
        assistant_msg = {
            "role": "assistant", 
            "content": response,
            "timestamp": datetime.now().isoformat()
        }
        chat["messages"].append(assistant_msg)
    
    if clear_pending:
        chat["pending"] = []
    
    save_chat(chat)
    return {"status": "ok"}


@app.delete("/api/chat")
async def clear_chat(_: bool = Depends(verify_token)):
    """Clear chat history."""
    save_chat({"messages": [], "pending": []})
    return {"status": "cleared"}


# =============================================================================
# Control Signals (DRIVE/BRAKES - hidden from chat, goes to pending only)
# =============================================================================

CONTROL_FILE = Path(__file__).parent / ".bra-control.json"

def load_control():
    """Load control state."""
    if CONTROL_FILE.exists():
        try:
            return json.loads(CONTROL_FILE.read_text())
        except:
            pass
    return {"signals": [], "driving": False}

def save_control(data):
    """Save control state."""
    CONTROL_FILE.write_text(json.dumps(data, indent=2))


@app.post("/api/control")
async def send_control(request: dict, _: bool = Depends(verify_token)):
    """Send a control signal (DRIVE/BRAKES). Does not appear in chat."""
    signal = request.get("signal", "").strip().upper()
    
    valid_signals = {
        "DRIVE": "TAKE-THE-WHEEL",
        "BRAKES": "HIT-THE-BRAKES"
    }
    
    if signal not in valid_signals:
        raise HTTPException(status_code=400, detail=f"Invalid signal. Use: {list(valid_signals.keys())}")
    
    message = valid_signals[signal]
    
    # Add to chat pending queue (but not messages - won't show in UI)
    chat = load_chat()
    control_msg = {
        "role": "control",
        "signal": signal,
        "content": message,
        "timestamp": datetime.now().isoformat()
    }
    chat["pending"].append(control_msg)
    save_chat(chat)
    
    # Also update control state
    control = load_control()
    control["signals"].append(control_msg)
    control["driving"] = (signal == "DRIVE")
    save_control(control)
    
    return {"status": "sent", "signal": signal, "message": message}


@app.get("/api/control")
async def get_control(_: bool = Depends(verify_token)):
    """Get current control state."""
    return load_control()


@app.get("/api/pitches")
async def get_pitches(_: bool = Depends(verify_token)):
    """Get pitch documents."""
    import re
    bra_root = get_bra_dir()
    if not bra_root:
        return {"exists": False, "pitches": [], "message": "No BRA directory configured."}
    
    pitches_dir = _body_root(bra_root) / "layer3-engagement" / "pitches"
    if not pitches_dir.exists():
        # Fallback to old location
        pitches_dir = _body_root(bra_root) / "docs" / "pitches"
    if not pitches_dir.exists():
        return {"exists": False, "pitches": [], "message": "No pitches directory found."}
    
    pitches = []
    for pitch_file in sorted(pitches_dir.glob("*.md"), reverse=True):
        content = pitch_file.read_text()
        
        pitch = {
            "filename": pitch_file.name,
            "path": str(pitch_file),
            "raw": content,
            "generated": None,
            "engagement": None,
            "status": None,
            "proposals": [],
            "sources": []
        }
        
        # Parse metadata
        gen_match = re.search(r'\*\*Generated:\*\*\s*(.+)', content)
        eng_match = re.search(r'\*\*Engagement:\*\*\s*(.+)', content)
        status_match = re.search(r'\*\*Status:\*\*\s*(.+)', content)
        
        if gen_match:
            pitch["generated"] = gen_match.group(1).strip()
        if eng_match:
            pitch["engagement"] = eng_match.group(1).strip()
        if status_match:
            raw_status = status_match.group(1).strip()
            # Normalize internal statuses for display
            raw_status = re.sub(r'\s*/brainblast\s*', ' ', raw_status).strip()
            if 'NEEDS' in raw_status.upper() and 'REVIEW' in raw_status.upper():
                raw_status = 'PENDING REVIEW'
            pitch["status"] = raw_status
        
        # Parse data sources
        sources_match = re.search(r'## Data Sources Analyzed\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
        if sources_match:
            for line in sources_match.group(1).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 2:
                    pitch["sources"].append({"source": cells[0], "status": cells[1]})
        
        # Parse proposals (checkboxes with sections)
        current_section = None
        for line in content.split('\n'):
            section_match = re.match(r'^## \d+\.\s+(.+)', line)
            if section_match:
                current_section = section_match.group(1).strip()
            
            checkbox_match = re.match(r'^- \[([ xX\-\?])\]\s*\*\*(.+?)\*\*:?\s*(.*)', line)
            if checkbox_match and current_section:
                status_char = checkbox_match.group(1)
                if status_char == ' ':
                    status = 'pending'
                elif status_char.lower() == 'x':
                    status = 'approved'
                elif status_char == '-':
                    status = 'denied'
                elif status_char == '?':
                    status = 'deferred'
                else:
                    status = 'pending'
                
                title = checkbox_match.group(2).strip()
                description = checkbox_match.group(3).strip()
                
                # Make title unique by appending description if title is generic
                display_title = title
                if description and title in ['New Methodology', 'Address', 'Expand', 'Technique Pattern', 'Multi-Stage Chain']:
                    display_title = f"{title}: {description[:60]}"
                
                pitch["proposals"].append({
                    "section": current_section,
                    "title": title,
                    "display_title": display_title,
                    "description": description,
                    "status": status,
                    "line": content[:content.find(line)].count('\n') + 1,
                    "raw_line": line.strip()
                })
        
        pitches.append(pitch)
    
    return {"exists": True, "pitches": pitches}


@app.post("/api/pitches/{filename}/proposal")
async def update_proposal(filename: str, request: dict, _: bool = Depends(verify_token)):
    """Update a proposal status in a pitch document by line number."""
    import re
    bra_root = get_bra_dir()
    if not bra_root:
        raise HTTPException(status_code=400, detail="No BRA directory configured.")

    pitch_file = _body_root(bra_root) / "layer3-engagement" / "pitches" / filename
    if not pitch_file.exists():
        # Fallback to old location
        pitch_file = _body_root(bra_root) / "docs" / "pitches" / filename
    if not pitch_file.exists():
        raise HTTPException(status_code=404, detail="Pitch file not found.")

    line_num = request.get("line")  # Line number (1-based)
    new_status = request.get("status")  # approved, denied, deferred, pending

    if not line_num or not new_status:
        raise HTTPException(status_code=400, detail="Missing line or status.")

    status_chars = {
        "approved": "x",
        "denied": "-",
        "deferred": "?",
        "pending": " "
    }

    if new_status not in status_chars:
        raise HTTPException(status_code=400, detail=f"Invalid status: {new_status}")

    lines = pitch_file.read_text().split('\n')

    # Validate line number
    if line_num < 1 or line_num > len(lines):
        raise HTTPException(status_code=404, detail=f"Invalid line number: {line_num}")

    # Get the line (convert to 0-based index)
    line_idx = line_num - 1
    line = lines[line_idx]

    # Verify it's a checkbox line and update it
    checkbox_match = re.match(r'^(- \[)[ xX\-\?](\]\s*\*\*.+)', line)
    if not checkbox_match:
        raise HTTPException(status_code=400, detail=f"Line {line_num} is not a proposal checkbox")

    # Replace the checkbox status
    new_line = f"{checkbox_match.group(1)}{status_chars[new_status]}{checkbox_match.group(2)}"
    lines[line_idx] = new_line

    new_content = '\n'.join(lines)
    pitch_file.write_text(new_content)

    # Also update the overall status if all proposals are reviewed
    pending_count = len(re.findall(r'^- \[ \]', new_content, re.MULTILINE))
    if pending_count == 0:
        new_content = re.sub(
            r'\*\*Status:\*\*\s*PENDING REVIEW',
            '**Status:** REVIEWED',
            new_content
        )
        pitch_file.write_text(new_content)

    return {"status": "ok", "updated_line": line_num, "new_status": new_status}


@app.post("/api/pitches/{filename}/ingest")
async def ingest_pitches(filename: str, _: bool = Depends(verify_token)):
    """Run ingest script for approved proposals (python-port first)."""

    bra_root = get_bra_dir()
    if not bra_root:
        raise HTTPException(status_code=400, detail="No BRA directory configured.")

    body_root = _body_root(bra_root)
    pitch_file = body_root / "layer3-engagement" / "pitches" / filename
    if not pitch_file.exists():
        raise HTTPException(status_code=404, detail="Pitch file not found.")

    try:
        import subprocess
        from bra.config.settings import set_bra_root
        from bra.core.bridge import run_script

        # Keep bridge path resolution synchronized with currently configured BRA root.
        set_bra_root(Path(bra_root))
        result = run_script("ingest.py", str(pitch_file), timeout=30)
        output = result.stdout.strip()
        # Parse the script's JSON output
        try:
            data = json.loads(output)
        except Exception:
            data = {"status": "ok", "message": output or "Ingest complete.", "raw": output}

        if result.returncode != 0:
            data["errors"] = data.get("errors", [])
            if result.stderr.strip():
                data["errors"].append(result.stderr.strip())

        return data
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Ingest script timed out.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/leads")
async def get_leads(_: bool = Depends(verify_token)):
    """Get investigation leads."""
    import re
    bra_root = get_bra_dir()
    if not bra_root:
        return {"exists": False, "message": "No BRA directory configured."}
    
    leads_locations = [
        _body_root(bra_root) / "layer3-engagement" / "NOTES" / "LEADS.md",
        _body_root(bra_root) / "NOTES" / "LEADS.md",
        _body_root(bra_root) / "layer3-engagement" / "LEADS.md",
        _body_root(bra_root) / "LEADS.md",
    ]
    
    for loc in leads_locations:
        if loc.exists():
            content = loc.read_text()
            content, anon_highlights = _anon_unmask_content(content)

            parsed = {
                "raw": content,
                "leads": [],
                "todos": []
            }

            # Parse table rows: | ID | Lead | Priority | Rationale | Status |
            table_row_pattern = r'^\|\s*(\d{3})\s*\|(.+)\|$'
            for line in content.split('\n'):
                m = re.match(table_row_pattern, line.strip())
                if m:
                    cells = [c.strip() for c in m.group(2).split('|')]
                    # cells: [Lead, Priority, Rationale, Status]
                    lead_text = cells[0] if len(cells) > 0 else ""
                    priority = cells[1] if len(cells) > 1 else ""
                    rationale = cells[2] if len(cells) > 2 else ""
                    status = cells[3] if len(cells) > 3 else "open"
                    if lead_text:
                        parsed["leads"].append({
                            "id": m.group(1),
                            "status": status.lower().strip() or "open",
                            "title": lead_text,
                            "priority": priority,
                            "body": rationale,
                        })

            # Parse lead sections: ### [STATUS] Title or ### Title
            lead_pattern = r'###\s*(?:\[([\w-]+)\])?\s*(.+?)(?=\n###|\n---|\Z)'
            for match in re.finditer(lead_pattern, content, re.DOTALL):
                status = match.group(1) or "open"
                title_and_body = match.group(2).strip()
                lines = title_and_body.split('\n')
                title = lines[0].strip() if lines else "Untitled"
                body = '\n'.join(lines[1:]).strip() if len(lines) > 1 else ""

                if title and not title.startswith('>'):  # Skip blockquotes
                    parsed["leads"].append({
                        "status": status.lower(),
                        "title": title,
                        "body": body
                    })

            # Parse todos: - [ ] or - [x]
            todo_pattern = r'-\s*\[([ xX])\]\s*(.+)'
            for match in re.finditer(todo_pattern, content):
                checked = match.group(1).lower() == 'x'
                text = match.group(2).strip()
                parsed["todos"].append({
                    "checked": checked,
                    "text": text
                })
            
            has_content = len(parsed["leads"]) > 0 or len(parsed["todos"]) > 0
            
            return {
                "exists": True,
                "has_content": has_content,
                "path": str(loc),
                "parsed": parsed,
                "modified": datetime.fromtimestamp(loc.stat().st_mtime).isoformat(),
                "anon_highlights": anon_highlights,
            }
    
    return {
        "exists": False,
        "message": "No leads file found. Create layer3-engagement/NOTES/LEADS.md to track investigation leads."
    }


@app.get("/api/intel")
async def get_intel(_: bool = Depends(verify_token)):
    """Get intelligence report content parsed into structured data."""
    import re

    # Check possible locations for INTEL.md
    bra_root = get_bra_dir()
    if not bra_root:
        return {"exists": False, "parsed": None, "message": "No BRA directory configured."}
    
    intel_locations = [
        _body_root(bra_root) / "layer3-engagement" / "NOTES" / "INTEL.md",
        _body_root(bra_root) / "NOTES" / "INTEL.md",
        _body_root(bra_root) / "layer3-engagement" / "INTEL.md",
        _body_root(bra_root) / "INTEL.md",
    ]

    for loc in intel_locations:
        if loc.exists():
            content = loc.read_text()
            content, anon_highlights = _anon_unmask_content(content)

            # Parse structured data from markdown
            parsed = {
                "raw": content,
                "sections": [],
                "tables": {},
                "lists": {},
                "metadata": {}
            }
            
            # Extract date and target from header
            date_match = re.search(r'\*\*Date:\*\*\s*(.+)', content)
            target_match = re.search(r'\*\*Target:\*\*\s*(.+)', content)
            if date_match:
                parsed["metadata"]["date"] = date_match.group(1).strip()
            if target_match:
                parsed["metadata"]["target"] = target_match.group(1).strip()
            
            # Parse tables (key-value and multi-column)
            # Strip markdown formatting from cell values for cleaner display
            table_pattern = r'#{2,3}\s*(.+?)\n+(\|.+)\n\|[-|\s]+\n((?:\|.+\n?)+)'
            for match in re.finditer(table_pattern, content):
                section_name = strip_markdown(match.group(1).strip())
                headers = normalize_table_headers(parse_markdown_table_cells(match.group(2)))
                if not headers:
                    continue
                rows = []
                for row in match.group(3).strip().split('\n'):
                    cells = parse_markdown_table_cells(row)
                    if cells:
                        if len(headers) == 2 and headers[0].lower() in ['property', 'key', 'name']:
                            # Key-value table (exactly 2 columns)
                            if section_name not in parsed["tables"]:
                                parsed["tables"][section_name] = {}
                            if len(cells) >= 2:
                                parsed["tables"][section_name][cells[0]] = cells[1]
                        else:
                            # Multi-column table — align values and preserve overflow in the last column.
                            while len(cells) < len(headers):
                                cells.append("")
                            if len(cells) > len(headers):
                                cells = cells[:len(headers) - 1] + [" | ".join(cells[len(headers) - 1:])]
                            rows.append(dict(zip(headers, cells[:len(headers)])))
                if rows:
                    parsed["tables"][section_name] = {"headers": headers, "rows": rows}

            # Parse bullet lists
            # Strip markdown formatting from list items
            list_pattern = r'#{2,3}\s*(.+?)\n+(?=-)((?: *-\s*.+\n?)+)'
            for match in re.finditer(list_pattern, content):
                section_name = strip_markdown(match.group(1).strip())
                if section_name not in parsed["tables"]:  # Don't overwrite tables
                    items = [strip_markdown(line.strip('- \n')) for line in match.group(2).strip().split('\n') if line.strip().startswith('-')]
                    if items:
                        parsed["lists"][section_name] = items

            # Parse numbered lists (like Paired Devices)
            numbered_pattern = r'#{2,3}\s*(.+?)\n+(?=\d)((?:\d+\.\s*.+\n?)+)'
            for match in re.finditer(numbered_pattern, content):
                section_name = strip_markdown(match.group(1).strip())
                items = [strip_markdown(re.sub(r'^\d+\.\s*', '', line.strip())) for line in match.group(2).strip().split('\n') if re.match(r'\d+\.', line.strip())]
                if items:
                    parsed["lists"][section_name] = items
            
            # Post-process: detect severity/title column swap in Key Issues tables.
            # IntelWriter may produce rows where the severity keyword lands in the
            # Title column and a default "INFO" ends up in Severity.
            _SEV_KEYWORDS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            for _tbl_name, _tbl_data in parsed["tables"].items():
                if not isinstance(_tbl_data, dict) or "rows" not in _tbl_data:
                    continue
                hdrs = _tbl_data.get("headers", [])
                if "Title" not in hdrs or "Severity" not in hdrs:
                    continue
                for row in _tbl_data["rows"]:
                    title_val = (row.get("Title") or "").strip()
                    sev_val = (row.get("Severity") or "").strip()
                    if title_val.upper() in _SEV_KEYWORDS:
                        # Title holds a severity keyword — swap columns
                        real_sev = title_val
                        if sev_val.upper() in ("INFO", "") or sev_val.upper() not in _SEV_KEYWORDS:
                            # Severity column was a default/placeholder — generate title from ID
                            row["Title"] = f"Finding #{row.get('ID', '???')}"
                        else:
                            row["Title"] = sev_val
                        row["Severity"] = real_sev

            # Treat skeleton files (no real data) as not existing
            has_data = bool(parsed["tables"] or parsed["lists"] or parsed["metadata"])
            return {
                "exists": has_data,
                "path": str(loc),
                "parsed": parsed if has_data else None,
                "modified": datetime.fromtimestamp(loc.stat().st_mtime).isoformat(),
                "anon_highlights": anon_highlights,
            }

    return {
        "exists": False,
        "path": None,
        "parsed": None,
    }


def parse_findings_md(content: str, notes_dir: Path | None = None) -> list[dict]:
    """Parse FINDINGS.md content into structured findings.

    Supports two formats:
    - Schema: ## [FINDING-XXX] Title (with metadata table)
    - Legacy: ### [SEVERITY] Title (with bullet-point fields)

    Args:
        content: Raw FINDINGS.md text

    Returns:
        List of finding dicts with severity, title, and extracted fields
    """
    import re
    if not content or not content.strip():
        return []

    findings = []
    severity_rank = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

    def _normalize_severity(value: str) -> str:
        text = str(value or "").strip().lower()
        if text in {"informational", "info"}:
            return "info"
        if text in severity_rank:
            return text
        return "unknown"

    def _normalize_cvss_rating(value: str) -> str:
        normalized = _normalize_severity(value)
        if normalized == "info":
            return "Informational"
        if normalized == "unknown":
            return ""
        return normalized.title()

    def _sanitize_display_path(value: str) -> str:
        text = str(value or "").strip().strip("'\"")
        if not text:
            return ""
        lowered = text.lower()
        if lowered.startswith("http://") or lowered.startswith("https://"):
            return text

        def _basename(path_text: str) -> str:
            normalized = path_text.rstrip("/").rstrip("\\")
            if not normalized:
                return path_text
            return Path(normalized).name or normalized.split("/")[-1]

        # Strip .bra/artifacts/ paths to filename only
        if ".bra/artifacts/" in text or text.startswith("artifacts/"):
            return _basename(text)

        def _is_notes_reqs_path(path_text: str) -> bool:
            normalized = path_text.replace("\\", "/").lower()
            if "layer3-engagement/notes/reqs/" in normalized:
                return True
            if normalized.startswith("notes/reqs/") or normalized.startswith("reqs/"):
                return True
            if "/notes/reqs/" in normalized:
                return True
            return False

        if _is_notes_reqs_path(text):
            return _basename(text)

        candidate = Path(text).expanduser()
        if candidate.is_absolute():
            anchors: list[Path] = []
            if notes_dir:
                anchors.extend([notes_dir.parent.parent, notes_dir.parent, notes_dir])
            for anchor in anchors:
                try:
                    rel = candidate.relative_to(anchor.resolve())
                    if _is_notes_reqs_path(rel.as_posix()):
                        return _basename(rel.as_posix())
                    return rel.as_posix()
                except Exception:
                    continue
            normalized = candidate.as_posix()
            marker = "/layer3-engagement/"
            marker_idx = normalized.find(marker)
            if marker_idx >= 0:
                relative_marker_path = normalized[marker_idx + 1:]
                if _is_notes_reqs_path(relative_marker_path):
                    return _basename(relative_marker_path)
                return relative_marker_path
        return text

    def _sanitize_inline_paths(text: str) -> str:
        def _replace(match: re.Match[str]) -> str:
            candidate = match.group(0)
            return _sanitize_display_path(candidate)

        return re.sub(r"/(?:Users|private|var|tmp)/[A-Za-z0-9._~:/\\-]+", _replace, text)

    def _clean_block(text: str) -> str:
        lines = [strip_markdown(line.rstrip()) for line in text.strip().splitlines()]
        cleaned_lines = [_sanitize_inline_paths(line).strip() for line in lines if line.strip()]
        return "\n".join(cleaned_lines).strip()

    def _extract_section(block: str, section: str) -> str:
        pattern = re.compile(
            rf'^###\s+{re.escape(section)}\s*\n([\s\S]*?)(?=^###\s+|^##\s+\[FINDING-|\Z)',
            re.MULTILINE | re.IGNORECASE,
        )
        match = pattern.search(block)
        return match.group(1).strip() if match else ""

    def _parse_first_table_map(text: str) -> dict[str, str]:
        table: dict[str, str] = {}
        in_table = False
        for line in text.splitlines():
            if line.lstrip().startswith("|"):
                in_table = True
                cells = parse_markdown_table_cells(line)
                if len(cells) < 2:
                    continue
                key = cells[0].strip()
                value = cells[1].strip()
                if not key or not value:
                    continue
                if key.lower() == "field" and value.lower() == "value":
                    continue
                if re.fullmatch(r"[-:\s|]+", key) or re.fullmatch(r"[-:\s|]+", value):
                    continue
                table.setdefault(key.lower(), value)
            elif in_table:
                break
        return table

    def _parse_markdown_table_rows(text: str) -> tuple[list[str], list[dict[str, str]]]:
        rows: list[str] = [line.strip() for line in text.splitlines() if line.strip().startswith("|")]
        if len(rows) < 2:
            return [], []
        headers = normalize_table_headers(parse_markdown_table_cells(rows[0]))
        parsed_rows: list[dict[str, str]] = []
        for row in rows[2:]:
            cells = parse_markdown_table_cells(row)
            if not any(cells):
                continue
            parsed: dict[str, str] = {}
            for idx, header in enumerate(headers):
                value = cells[idx] if idx < len(cells) else ""
                parsed[header] = _sanitize_inline_paths(value.strip())
            parsed_rows.append(parsed)
        return headers, parsed_rows

    def _resolve_notes_path(raw: str) -> Path | None:
        cleaned = strip_markdown(str(raw or "").strip()).strip("'\"")
        if not cleaned:
            return None
        lowered = cleaned.lower()
        if lowered.startswith("http://") or lowered.startswith("https://"):
            return None
        candidate = Path(cleaned).expanduser()
        if candidate.is_absolute():
            return candidate if candidate.exists() else None
        if not notes_dir:
            return None
        search_roots = [notes_dir, notes_dir.parent, notes_dir.parent.parent]
        for root in search_roots:
            resolved = (root / candidate).resolve()
            if resolved.exists():
                return resolved
        return None

    def _extract_source_marker(raw_text: str) -> str:
        if not raw_text:
            return ""
        marker_match = re.search(r"Source marker:\s*(.+)", raw_text, re.IGNORECASE)
        if marker_match:
            return marker_match.group(1).strip()
        finding_match = re.search(r"(\[FINDING\][^\n]+)", raw_text, re.IGNORECASE)
        return finding_match.group(1).strip() if finding_match else ""

    def _extract_source_marker_severity(marker_text: str) -> str:
        if not marker_text:
            return "unknown"
        pipe_match = re.search(
            r"\|\s*(critical|high|medium|low|info|informational)\s*(?:\||$)",
            marker_text,
            re.IGNORECASE,
        )
        if pipe_match:
            return _normalize_severity(pipe_match.group(1))
        prefix_match = re.search(
            r"\[FINDING\]\s*(critical|high|medium|low|info|informational)\s*:",
            marker_text,
            re.IGNORECASE,
        )
        if prefix_match:
            return _normalize_severity(prefix_match.group(1))
        return "unknown"

    def _extract_source_marker_impact(marker_text: str) -> str:
        if not marker_text:
            return ""
        parts = [part.strip() for part in marker_text.split("|")]
        if len(parts) >= 3:
            impact = parts[2]
            if impact and not impact.lower().startswith("source:"):
                return impact
        return ""

    def _normalize_artifact_location(raw: str) -> str:
        lines_out: list[str] = []
        for raw_line in raw.splitlines():
            line = strip_markdown(raw_line.rstrip()).strip()
            if not line or line == "**":
                continue
            bullet = ""
            if line.startswith("- "):
                bullet = "- "
                line = line[2:].strip()
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                if key.lower() in {"local", "original", "path", "artifact"}:
                    value = _sanitize_display_path(value)
                else:
                    value = _sanitize_inline_paths(value)
                lines_out.append(f"{bullet}{key}: {value}")
            else:
                lines_out.append(f"{bullet}{_sanitize_inline_paths(line)}")
        return "\n".join(lines_out).strip()

    def _normalize_reproduction(raw: str) -> str:
        if not raw:
            return ""
        without_fences = re.sub(
            r"```(?:\w+)?\n([\s\S]*?)```",
            lambda m: (m.group(1) or "").rstrip(),
            raw,
            flags=re.IGNORECASE,
        )
        return _clean_block(without_fences)

    def _extract_poc_display_content(raw: str) -> str:
        if not raw:
            return ""
        lines_out: list[str] = []
        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if re.match(r"^FINDING-\d+\s+PoC$", line, re.IGNORECASE):
                continue
            if re.match(r"^(Title|Severity|Source(?:\s*marker)?|Description|Note)\s*:", line, re.IGNORECASE):
                continue
            lines_out.append(raw_line.rstrip())
        rendered = "\n".join(lines_out).strip()
        return rendered if re.search(r"[A-Za-z0-9]", rendered) else ""

    # Pass 1: Schema format (## [FINDING-XXX] Title)
    schema_matches = list(
        re.finditer(r'^## \[(FINDING-\d+)\]\s*(.+)$', content, re.MULTILINE)
    )

    if schema_matches:
        for idx, match in enumerate(schema_matches):
            finding_id = match.group(1).upper()
            title = strip_markdown(match.group(2).strip()) or "Unknown Finding"
            start = match.start()
            end = schema_matches[idx + 1].start() if idx + 1 < len(schema_matches) else len(content)
            block = content[start:end].strip()

            metadata = _parse_first_table_map("\n".join(block.splitlines()[1:]))
            severity = _normalize_severity(metadata.get("severity", "unknown"))

            finding = {
                "_source": "markdown",
                "finding_id": finding_id,
                "severity": severity,
                "title": title,
            }

            cvss_text = metadata.get("cvss", "")
            if cvss_text:
                score_match = re.search(r'(\d+(?:\.\d+)?)', cvss_text)
                if score_match:
                    finding["cvss_score"] = score_match.group(1)
                rating_match = re.search(r'\((Critical|High|Medium|Low|Info(?:rmational)?)\)', cvss_text, re.IGNORECASE)
                if rating_match:
                    rating = _normalize_cvss_rating(rating_match.group(1))
                    if rating:
                        finding["cvss_rating"] = rating

            cwe_text = metadata.get("cwe", "")
            if cwe_text:
                finding["cwe"] = cwe_text
            status_text = metadata.get("status", "")
            if status_text:
                finding["status"] = status_text

            affected_section = _extract_section(block, "Affected Artifact")
            affected_table = _parse_first_table_map(affected_section)

            affected = affected_table.get("path") or affected_table.get("artifact")
            if not affected:
                affected_match = re.search(r'\*\*Artifact:\*\*\s*`?([^`\n]+)`?', affected_section)
                if affected_match:
                    affected = strip_markdown(affected_match.group(1).strip())
            if affected:
                finding["affected"] = _sanitize_display_path(affected)

            artifact_location = affected_table.get("artifact location")
            if not artifact_location:
                location_match = re.search(
                    r'\*\*Artifact Location:\*\*\s*([\s\S]+?)(?=\n\*\*Artifact Hash:\*\*|\n###|\Z)',
                    affected_section,
                    re.IGNORECASE,
                )
                if location_match:
                    artifact_location = location_match.group(1)
            if artifact_location:
                normalized_location = _normalize_artifact_location(artifact_location)
                if normalized_location:
                    finding["artifact_location"] = normalized_location

            artifact_hash = (
                affected_table.get("artifact hash (sha256)")
                or affected_table.get("artifact hash")
            )
            if not artifact_hash:
                hash_match = re.search(r'([0-9a-fA-F]{64})', affected_section or block)
                if hash_match:
                    artifact_hash = hash_match.group(1)
            if artifact_hash:
                hash_only = re.search(r'([0-9a-fA-F]{64})', artifact_hash)
                finding["artifact_hash"] = hash_only.group(1) if hash_only else artifact_hash

            description = _extract_section(block, "Description")
            if description:
                finding["description"] = _clean_block(description)

            impact = _extract_section(block, "Impact")
            if impact:
                finding["impact"] = _clean_block(impact)

            attack_vector = _extract_section(block, "Attack Vector")
            if attack_vector:
                finding["attack_vector"] = _clean_block(attack_vector)

            repro_section = _extract_section(block, "Reproduction Steps")
            if repro_section:
                normalized_repro = _normalize_reproduction(repro_section)
                if normalized_repro:
                    finding["reproduction"] = normalized_repro

            poc_section = _extract_section(block, "Proof of Concept")
            source_markers: list[str] = []
            if poc_section:
                poc_patterns = [
                    r'\*\*PoC File:\*\*\s*`([^`]+)`',
                    r'\*\*Location:\*\*\s*`([^`]+)`',
                    r'`([^`]*reqs/[^`]+)`',
                ]
                for pattern in poc_patterns:
                    poc_match = re.search(pattern, poc_section, re.IGNORECASE)
                    if poc_match:
                        poc_location = strip_markdown(poc_match.group(1).strip())
                        finding["poc"] = _sanitize_display_path(poc_location)
                        resolved_poc = _resolve_notes_path(poc_location)
                        if resolved_poc and resolved_poc.is_file():
                            raw_poc_content = resolved_poc.read_text(errors="replace").strip()
                            if raw_poc_content:
                                source_marker = _extract_source_marker(raw_poc_content)
                                if source_marker:
                                    source_markers.append(source_marker)
                                poc_display = _extract_poc_display_content(raw_poc_content)
                                if poc_display:
                                    finding["poc_content"] = poc_display
                        break
                if "poc" not in finding:
                    poc_text = _clean_block(poc_section)
                    if poc_text:
                        finding["poc"] = poc_text

            evidence = _extract_section(block, "Observed Evidence")
            if evidence:
                evidence_text = _clean_block(evidence)
                if evidence_text:
                    finding["evidence"] = evidence_text
                evidence_headers, evidence_rows = _parse_markdown_table_rows(evidence)
                if evidence_headers and evidence_rows:
                    finding["evidence_headers"] = evidence_headers
                    for row in evidence_rows:
                        for key in list(row.keys()):
                            if key.lower() in {"location", "path"}:
                                row[key + "_full"] = row.get(key, "")
                                row[key] = _sanitize_display_path(row.get(key, ""))
                    finding["evidence_rows"] = evidence_rows
                    for row in evidence_rows:
                        for key, value in row.items():
                            if key.lower() not in {"location", "path"}:
                                continue
                            resolved_evidence = _resolve_notes_path(value)
                            if resolved_evidence and resolved_evidence.is_file():
                                evidence_content = resolved_evidence.read_text(errors="replace")
                                source_marker = _extract_source_marker(evidence_content)
                                if source_marker:
                                    source_markers.append(source_marker)
                                break

            severity_section = _extract_section(block, "Severity")
            if severity_section:
                vector_match = re.search(r'CVSS[^:\n]*Vector:\s*`?([^`\n]+)`?', severity_section, re.IGNORECASE)
                if vector_match:
                    finding["cvss_vector"] = vector_match.group(1).strip()
                if "cvss_score" not in finding:
                    score_match = re.search(
                        r'(?:Base\s+Score|CVSS(?:\s+v?\d\.\d)?\s*Score|Score)\s*[:=]\s*\**\s*(\d+(?:\.\d+)?)',
                        severity_section,
                        re.IGNORECASE,
                    )
                    if score_match:
                        finding["cvss_score"] = score_match.group(1)
                if "cvss_rating" not in finding:
                    rating_match = re.search(r'\((Critical|High|Medium|Low|Info(?:rmational)?)\)', severity_section, re.IGNORECASE)
                    if rating_match:
                        rating = _normalize_cvss_rating(rating_match.group(1))
                        if rating:
                            finding["cvss_rating"] = rating

            likelihood = _extract_section(block, "Likelihood")
            if likelihood:
                likelihood_text = _clean_block(likelihood)
                finding["likelihood"] = likelihood_text

            remediation = _extract_section(block, "Remediation")
            if remediation:
                finding["remediation"] = _clean_block(remediation)

            # Source marker enrichment from reqs artifacts can correct stale
            # markdown severity/impact without mutating FINDINGS.md.
            marker_severity = "unknown"
            marker_impact = ""
            for source_marker in source_markers:
                parsed_severity = _extract_source_marker_severity(source_marker)
                if severity_rank.get(parsed_severity, 0) > severity_rank.get(marker_severity, 0):
                    marker_severity = parsed_severity
                if not marker_impact:
                    marker_impact = _extract_source_marker_impact(source_marker)

            current_severity = _normalize_severity(finding.get("severity", "unknown"))
            if severity_rank.get(marker_severity, 0) > severity_rank.get(current_severity, 0):
                finding["severity"] = marker_severity

            existing_impact = str(finding.get("impact", "") or "").strip()
            if marker_impact:
                if not existing_impact or existing_impact.lower().startswith("source:"):
                    finding["impact"] = marker_impact
            elif existing_impact.lower().startswith("source:"):
                fallback_impact = str(finding.get("description", "") or "").strip()
                if fallback_impact:
                    finding["impact"] = fallback_impact

            if "cvss_rating" not in finding and finding.get("severity"):
                fallback_rating = _normalize_cvss_rating(str(finding["severity"]))
                if fallback_rating:
                    finding["cvss_rating"] = fallback_rating

            findings.append(finding)
    else:
        # Pass 2: Legacy format (### [SEVERITY] Title)
        legacy_pattern = r'^### \[(\w+)\]\s*(.+?)(?=\n### \[|\n---|\Z)'
        for match in re.finditer(legacy_pattern, content, re.DOTALL | re.MULTILINE):
            severity = match.group(1).lower()
            block = match.group(2).strip()

            lines = block.split('\n')
            title = lines[0].strip() if lines else "Unknown Finding"

            finding = {
                "_source": "markdown",
                "severity": severity,
                "title": title,
            }

            # Legacy field extraction (bullet-point based)
            legacy_fields = {
                "affected": r'\*\*Affected artifact:\*\*\s*(.+)',
                "description": r'\*\*Short description:\*\*\s*(.+)',
                "impact": r'\*\*Impact:\*\*\s*([\s\S]+?)(?=\n\n|\n-\s*\*\*|\Z)',
                "attack_vector": r'\*\*Attack vector:\*\*\s*([\s\S]+?)(?=\n\n|\n-\s*\*\*|\Z)',
                "cvss": r'CVSS[^=]*=\s*([\d.]+)\s*\((\w+)\)',
                "likelihood": r'\*\*Likelihood:\*\*\s*(\w+)',
                "remediation": r'\*\*Remediation:\*\*\s*([\s\S]+?)(?=\n\n|\n-\s*\*\*)',
                "poc": r'\*\*Proof of Concept:\*\*\s*(.+)',
                "evidence": r'\*\*Observed evidence:\*\*\s*(.+)',
            }

            for field, pattern in legacy_fields.items():
                field_match = re.search(pattern, block)
                if field_match:
                    if field == "cvss":
                        finding["cvss_score"] = field_match.group(1)
                        finding["cvss_rating"] = field_match.group(2)
                    else:
                        finding[field] = field_match.group(1).strip()

            # Reproduction steps
            repro_match = re.search(r'\*\*Reproduction steps:\*\*\s*```(?:\w*)\n([\s\S]+?)```', block)
            if repro_match:
                finding["reproduction"] = repro_match.group(1).strip()
            else:
                repro_list = re.search(r'\*\*Reproduction steps:\*\*\s*\n((?:\s*\d+\..+\n?)+)', block)
                if repro_list:
                    finding["reproduction"] = strip_markdown(repro_list.group(1).strip())

            findings.append(finding)

    return findings


@app.get("/api/findings")
async def get_findings(_: bool = Depends(verify_token)):
    """List all findings."""
    import re

    findings = []
    pending_count = 0
    pending_queue: list[dict[str, object]] = []
    bra_root = get_bra_dir()
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

    def _normalize_finding_id(value: object) -> str:
        text = str(value or "").strip().upper()
        if not text:
            return ""
        if text.startswith("FINDING-"):
            return text
        if text.isdigit():
            return f"FINDING-{text.zfill(3)}"
        return text
    
    # Check multiple possible locations for JSON findings
    finding_locations = [
        get_bra_path("artifacts", "findings"),
        get_bra_path("findings"),
    ]
    
    for loc in finding_locations:
        if loc.exists():
            for f in loc.glob("*.json"):
                try:
                    data = json.loads(f.read_text())
                    data["_file"] = f.name
                    data["_source"] = "json"
                    findings.append(data)
                except (json.JSONDecodeError, IOError):
                    findings.append({
                        "_file": f.name,
                        "_source": "json",
                        "error": "Failed to parse",
                        "severity": "unknown"
                    })
    
    # Parse layer3-engagement/NOTES/FINDINGS.md for structured findings
    findings_enforcer = None
    findings_anon_highlights: list[dict] = []
    if bra_root:
        findings_md_locations = [
            _body_root(bra_root) / "layer3-engagement" / "NOTES" / "FINDINGS.md",
            _body_root(bra_root) / "NOTES" / "FINDINGS.md",
            _body_root(bra_root) / "layer3-engagement" / "FINDINGS.md",
        ]
        
        for findings_md in findings_md_locations:
            if findings_md.exists():
                content = findings_md.read_text()
                content, findings_anon_highlights = _anon_unmask_content(content)
                parsed = parse_findings_md(content, notes_dir=findings_md.parent)
                try:
                    from bra.core.finding_enforcer import FindingEnforcer
                    findings_enforcer = FindingEnforcer(findings_md.parent, get_bra_path())
                except Exception:
                    findings_enforcer = None
                for finding in parsed:
                    finding.setdefault("is_complete", None)
                    finding.setdefault("missing_fields", [])
                    finding.setdefault("validation_errors", [])
                    if findings_enforcer:
                        normalized_id = _normalize_finding_id(finding.get("finding_id") or finding.get("id"))
                        if normalized_id.startswith("FINDING-"):
                            raw_id = normalized_id.replace("FINDING-", "")
                            if raw_id.isdigit():
                                result = findings_enforcer.validate_finding_record(raw_id)
                                finding["is_complete"] = result.valid
                                finding["missing_fields"] = result.missing_fields
                                finding["validation_errors"] = result.errors
                    finding["_file"] = findings_md.name
                    findings.append(finding)
                break  # Only process first found FINDINGS.md

    # Self-heal stale queue entries so dashboard reflects current documentation
    # state even before a new agent turn runs.
    if findings_enforcer and findings_enforcer.pending_queue:
        findings_enforcer.check_and_dequeue_completed()

    # Include pending findings queue so operators can see gated items even
    # before FINDINGS.md entries are fully valid.
    existing_ids = {
        _normalize_finding_id(item.get("finding_id") or item.get("id"))
        for item in findings
        if isinstance(item, dict)
    }
    pending_file = get_bra_path("pending_findings.json")
    if pending_file.exists():
        try:
            pending_data = json.loads(pending_file.read_text())
        except (json.JSONDecodeError, IOError):
            pending_data = []
        if isinstance(pending_data, dict):
            pending_data = pending_data.get("pending", [])
        if isinstance(pending_data, list):
            for item in pending_data:
                if not isinstance(item, dict):
                    continue
                normalized_id = _normalize_finding_id(item.get("id"))
                if normalized_id and normalized_id in existing_ids:
                    # Keep queue visibility even when markdown has same ID.
                    pass
                severity = str(item.get("severity", "unknown") or "unknown").lower()
                if severity not in severity_order:
                    severity = "unknown"
                pending_entry = {
                    "finding_id": normalized_id or None,
                    "severity": severity,
                    "title": str(item.get("title", "") or "").strip() or "Pending finding documentation",
                    "queued_at": item.get("queued_at"),
                    "source_marker": item.get("source_marker"),
                }
                pending_queue.append(pending_entry)
                finding = {
                    "_source": "pending",
                    **pending_entry,
                    "description": "Documentation required to clear finding gate.",
                    "status": "pending_documentation",
                    "is_complete": False,
                    "missing_fields": ["Finding record not fully documented"],
                    "validation_errors": [],
                }
                # Avoid duplicate row only for findings list rendering.
                if not (normalized_id and normalized_id in existing_ids):
                    findings.append(finding)
                if normalized_id:
                    existing_ids.add(normalized_id)
            pending_count = len(pending_queue)

    # Fallback: surface findings from INTEL.md Vulns table when formal
    # FINDINGS.md records have not been written yet.
    def _finding_signature(item: dict) -> str:
        title = str(item.get("title", "") or "").strip().lower()
        severity = str(item.get("severity", "unknown") or "unknown").strip().lower()
        return f"{severity}|{title}" if title else ""

    existing_signatures = {
        _finding_signature(item)
        for item in findings
        if isinstance(item, dict)
    }
    existing_signatures.discard("")

    has_markdown_findings = any(
        isinstance(item, dict) and item.get("_source") == "markdown"
        for item in findings
    )

    if bra_root and not has_markdown_findings:
        intel_locations = [
            _body_root(bra_root) / "layer3-engagement" / "NOTES" / "INTEL.md",
            _body_root(bra_root) / "NOTES" / "INTEL.md",
            _body_root(bra_root) / "layer3-engagement" / "INTEL.md",
            _body_root(bra_root) / "INTEL.md",
        ]

        for intel_md in intel_locations:
            if not intel_md.exists():
                continue

            content = intel_md.read_text()
            vuln_match = re.search(
                r'##\s*(?:Vulns|Vulnerabilities)\s*\n+(\|.+)\n\|[-|\s]+\n((?:\|.+\n?)+)',
                content,
                re.IGNORECASE,
            )
            if not vuln_match:
                continue

            for row in vuln_match.group(2).strip().split("\n"):
                cells = parse_markdown_table_cells(row)
                if len(cells) < 2:
                    continue

                title = strip_markdown(cells[0]).strip()
                if not title:
                    continue

                severity = strip_markdown(cells[1]).strip().lower()
                if severity not in severity_order and len(cells) > 2:
                    alt_severity = strip_markdown(cells[2]).strip().lower()
                    if alt_severity in severity_order:
                        severity = alt_severity
                if severity not in severity_order:
                    severity = "unknown"

                description = strip_markdown(cells[2]).strip() if len(cells) > 2 else ""
                source = strip_markdown(cells[3]).strip() if len(cells) > 3 else ""

                signature = f"{severity}|{title.lower()}"
                if signature in existing_signatures:
                    continue

                findings.append(
                    {
                        "_source": "intel_vulns",
                        "_file": intel_md.name,
                        "severity": severity,
                        "title": title,
                        "description": description,
                        "evidence": source,
                    }
                )
                existing_signatures.add(signature)
            break

    # Sort by severity
    findings.sort(key=lambda x: severity_order.get(x.get("severity", "unknown"), 5))
    
    return {
        "findings": findings,
        "count": len(findings),
        "pending_count": pending_count,
        "pending_queue": pending_queue,
        "anon_highlights": findings_anon_highlights,
    }


@app.get("/api/health")
async def get_health(_: bool = Depends(verify_token)):
    """Get BRA health/precheck report."""
    import re
    
    precheck = get_bra_path("PRECHECK_REPORT.md")
    if not precheck.exists():
        return {
            "exists": False,
            "message": ""
        }
    
    content = precheck.read_text()
    
    # Parse the report
    parsed = {
        "raw": content,
        "generated": None,
        "status": None,
        "summary": {},
        "sections": []
    }
    
    # Extract metadata
    gen_match = re.search(r'\*\*Generated:\*\*\s*(.+)', content)
    if gen_match:
        parsed["generated"] = gen_match.group(1).strip()
    
    status_match = re.search(r'\*\*Overall Status:\*\*\s*(.+)', content)
    if status_match:
        parsed["status"] = status_match.group(1).strip()
    
    # Parse summary table
    summary_match = re.search(r'\| Result \| Count \|\n\|[-|\s]+\|\n((?:\|.+\n)+)', content)
    if summary_match:
        for line in summary_match.group(1).strip().split('\n'):
            cells = [c.strip() for c in line.split('|') if c.strip()]
            if len(cells) >= 2:
                parsed["summary"][cells[0]] = int(cells[1]) if cells[1].isdigit() else cells[1]
    
    # Parse check sections — split by ### headers, extract all check items
    # (handles sub-headers like #### and section names with special chars)
    for section_text in re.split(r'(?=### )', content):
        header_match = re.match(r'###\s+(.+)\n', section_text)
        if not header_match:
            continue
        section_name = header_match.group(1).strip()
        checks = []
        for line in section_text.split('\n'):
            check_match = re.match(r'- \[(.)\]\s*\*\*(.+?)\*\*:?\s*(.*)', line)
            if check_match:
                status_char = check_match.group(1)
                status = "pass" if status_char == "x" else "skip" if status_char == "-" else "fail"
                checks.append({
                    "name": check_match.group(2).strip(),
                    "detail": check_match.group(3).strip(),
                    "status": status
                })
        if checks:
            parsed["sections"].append({
                "name": section_name,
                "checks": checks
            })

    # Merge tool sub-category sections into one "PREINSTALLED TOOLS" section
    tool_names = {'Static Analysis', 'Reverse Engineering', 'Mobile Analysis',
                  'Firmware/Embedded', 'Network', 'Debugging', 'Fuzzing', 'Utilities'}
    tool_checks = []
    other_sections = []
    for section in parsed["sections"]:
        if section["name"] in tool_names:
            tool_checks.extend(section["checks"])
        else:
            other_sections.append(section)
    if tool_checks:
        # Insert after TEMPLATES & METHODOLOGIES if it exists
        insert_idx = next((i + 1 for i, s in enumerate(other_sections)
                           if s["name"] == "CAPABILITIES"), len(other_sections))
        other_sections.insert(insert_idx, {"name": "PREINSTALLED TOOLS", "checks": tool_checks})

    # Rename sections for cleaner display
    renames = {
        ".BRA/ SCHEMA VALIDATION": "SCHEMA VALIDATION",
        "TEMPLATES & METHODOLOGIES": "CAPABILITIES",
    }
    for section in other_sections:
        if section["name"] in renames:
            section["name"] = renames[section["name"]]

    parsed["sections"] = other_sections

    return {
        "exists": True,
        "path": str(precheck),
        "parsed": parsed,
        "modified": datetime.fromtimestamp(precheck.stat().st_mtime).isoformat()
    }


@app.get("/api/governance")
async def get_governance(_: bool = Depends(verify_token)):
    """Get governance status: kill switch, tokens, enforcement info."""
    import re
    bra_root = get_bra_dir()
    if not bra_root:
        return {"exists": False, "message": "No BRA directory configured."}
    try:
        _sync_2x4_governance_tokens(bra_root)
    except Exception as exc:
        logging.debug("Failed to sync 2x4 governance tokens during /api/governance: %s", exc)

    result = {
        "exists": True,
        "kill_switch": "UNKNOWN",
        "kill_switch_message": None,
        "tool_approval_enabled": True,
        # Seed with operational governance tokens that may not be listed
        # under "Approval Tokens" in CLAUDE.md.
        "tokens": {
            "BRA-DEBUG": {
                "required_for": "Enable per-module BRA debug logs",
                "source": "Governance token (operational)"
            },
            "BRA_VERBOSE": {
                "required_for": "Enable verbose runtime tracing and verbose.log capture",
                "source": "Governance token (operational)"
            },
            "NO-TOKEN-TRACKING": {
                "required_for": "Disable always-on SDK token usage and cost logging",
                "source": "Governance token (operational)"
            },
            "TOOL-APPROVAL": {
                "required_for": "Enable tool-by-tool approval prompts",
                "source": "Governance control (operational)"
            }
        },
        "enforcement": {
            "mechanical": [],
            "advisory": []
        }
    }

    # Check kill switch: mirrors killswitch.py logic
    # Source 1: .bra/STOP file
    stop_file = _body_root(bra_root) / ".bra" / "STOP"
    if stop_file.exists():
        result["kill_switch"] = "STOP"
        result["kill_switch_message"] = stop_file.read_text().strip().split('\n')[0]
    else:
        # Source 2: CLAUDE.md kill switch section (no STOP file + no CLAUDE.md = CLEAR)
        result["kill_switch"] = "CLEAR"

    # Parse CLAUDE.md for tokens and enforcement tables
    agents_locations = [_body_root(bra_root) / "CLAUDE.md"]

    for agents_file in agents_locations:
        if agents_file.exists():
            content = agents_file.read_text()

            # Override kill switch from CLAUDE.md if present
            ks_match = re.search(r'## Kill Switch\s*\n\s*```\s*\n(\w+)\s*\n```', content)
            if ks_match:
                result["kill_switch"] = ks_match.group(1).strip()

            ks_msg_match = re.search(r'\*\*Status:\*\*\s*(.+)', content)
            if ks_msg_match:
                result["kill_switch_message"] = ks_msg_match.group(1).strip()

            # Parse approval tokens table
            token_table = re.search(r'### Approval Tokens\s*\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
            if token_table:
                for line in token_table.group(1).strip().split('\n'):
                    cells = [c.strip() for c in line.split('|') if c.strip()]
                    if len(cells) >= 2:
                        token_name = cells[0].strip('`')
                        result["tokens"][token_name] = {
                            "required_for": cells[1] if len(cells) > 1 else "",
                            "source": cells[2] if len(cells) > 2 else ""
                        }

            # Parse mechanical enforcement table
            mech_table = re.search(r'### Mechanically Enforced Controls\s*\n.*?\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content, re.DOTALL)
            if mech_table:
                for line in mech_table.group(1).strip().split('\n'):
                    cells = [c.strip() for c in line.split('|') if c.strip()]
                    if len(cells) >= 2:
                        result["enforcement"]["mechanical"].append({
                            "control": cells[0],
                            "implementation": cells[1] if len(cells) > 1 else "",
                            "hook": cells[2] if len(cells) > 2 else "",
                            "exit_code": cells[3] if len(cells) > 3 else ""
                        })
            break

    # Check actual token files in .bra/approvals/
    # Token files are named like ACTIVE-TESTING-APPROVAL, DESTRUCTIVE-APPROVAL, etc.
    approvals_dir = _body_root(bra_root) / ".bra" / "approvals"
    if approvals_dir.exists():
        result["active_tokens"] = []
        for token_file in approvals_dir.iterdir():
            if token_file.is_file() and not token_file.name.startswith('.'):
                # Preserve filename casing for display; frontend normalizes for matching.
                token_name = token_file.name if token_file.name == "BRA_VERBOSE" else token_file.name.replace("_", "-")
                result["active_tokens"].append(token_name)

    # Tool approval is a governance control (env/file gated), not a token file.
    # Surface it in dashboard state so UI can render it consistently.
    tool_approval_disabled = (
        os.environ.get("BRA_TOOL_APPROVAL") == "0"
        or (_body_root(bra_root) / ".bra" / "TOOL_APPROVAL_DISABLED").exists()
    )
    result["tool_approval_enabled"] = not tool_approval_disabled

    return result


@app.post("/api/governance/token/{name}/toggle")
async def toggle_token(name: str, _=Depends(verify_token)):
    """Create or remove an approval token file in .bra/approvals/."""
    bra_root = get_bra_dir()
    if not bra_root:
        return {"error": "No BRA directory configured"}
    body_root = _body_root(bra_root)
    approvals_dir = body_root / ".bra" / "approvals"
    approvals_dir.mkdir(parents=True, exist_ok=True)
    token_name = _normalize_governance_token_filename(name)
    if not token_name:
        raise HTTPException(status_code=400, detail="Token name is required")
    token_file = approvals_dir / token_name
    if token_name == "TOOL-APPROVAL":
        disabled_file = body_root / ".bra" / "TOOL_APPROVAL_DISABLED"
        enabled = not (
            os.environ.get("BRA_TOOL_APPROVAL") == "0"
            or disabled_file.exists()
        )
        if enabled:
            if token_file.exists():
                token_file.unlink()
            disabled_file.touch()
            return {
                "token": token_name,
                "active": False,
                "warning": "TOOL-APPROVAL changes may require a restart to take effect.",
            }
        token_file.touch()
        if disabled_file.exists():
            disabled_file.unlink()
        return {
            "token": token_name,
            "active": True,
            "warning": "TOOL-APPROVAL changes may require a restart to take effect.",
        }
    if token_file.exists():
        token_file.unlink()
        return {"token": token_name, "active": False}
    token_file.touch()
    return {"token": token_name, "active": True}


@app.post("/api/governance/generated-token")
async def create_generated_token(request: GeneratedTokenRequest | dict[str, str], _=Depends(verify_token)):
    """Create a generated governance token in the correct approval store."""
    bra_root = get_bra_dir()
    if not bra_root:
        return {"error": "No BRA directory configured"}

    body_root = _body_root(bra_root)
    approvals_dir = body_root / ".bra" / "approvals"
    one_time_dir = body_root / ".bra" / "one-time-approvals"
    approvals_dir.mkdir(parents=True, exist_ok=True)
    one_time_dir.mkdir(parents=True, exist_ok=True)

    if isinstance(request, dict):
        request = GeneratedTokenRequest(**request)

    family = str(request.family or "").strip().lower()
    value = str(request.value or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="Token value is required")

    if family == "scope_grant":
        from bra.core.approval import ApprovalManager

        token_name = f"SCOPE-GRANT-{ApprovalManager._sanitize_target(value)}"
        token_file = one_time_dir / token_name
        token_file.write_text(value, encoding="utf-8")
        return {"token": token_name, "location": "one-time-approvals", "active": True}

    if family == "tool":
        token_name = f"TOOL-{value}"
        token_file = one_time_dir / token_name
        token_file.write_text(value, encoding="utf-8")
        return {"token": token_name, "location": "one-time-approvals", "active": True}

    if family == "script":
        from bra.core.approval import _get_approval_token_name

        token_name = _get_approval_token_name(value)
        token_file = approvals_dir / token_name
        token_file.write_text(f"Approved script: {value}\n", encoding="utf-8")
        return {"token": token_name, "location": "approvals", "active": True}

    raise HTTPException(status_code=400, detail=f"Unsupported generated token family: {request.family}")


# ---------------------------------------------------------------------------
# Anonymization endpoints
# ---------------------------------------------------------------------------

SCOPE_TOKENS = ["FRONTIER-SCOPE", "MICRO-SCOPE", "LOCAL-SCOPE", "DUMB-SCOPE", "NO-SCOPE"]
CHAT_TOKENS = ["MAP-SCAN", "ANON-SCAN", "LOCAL-SCAN", "NO-SCAN"]


def _anon_disabled(body_root: Path) -> bool:
    return (body_root / ".bra" / "approvals" / "ANON-DISABLE").exists()


def _get_active_chat_token() -> str:
    """Return the active chat token, defaulting to MAP-SCAN."""
    bra_root = get_bra_dir()
    if not bra_root:
        return "MAP-SCAN"
    body_root = _body_root(bra_root)
    approvals_dir = body_root / ".bra" / "approvals"
    for token in CHAT_TOKENS:
        if (approvals_dir / token).exists():
            return token
    return "MAP-SCAN"


def _anon_mask_chat(text: str) -> str:
    """Mask chat input based on active chat token. Returns text unchanged if no masking needed."""
    bra_root = get_bra_dir()
    if not bra_root:
        return text
    body_root = _body_root(bra_root)
    if _anon_disabled(body_root):
        return text

    chat_token = _get_active_chat_token()
    if chat_token == "NO-SCAN":
        return text
    api, err = _get_anon_api()
    if err or api is None:
        return text
    if chat_token in {"ANON-SCAN", "LOCAL-SCAN"}:
        detections = api.detect(text)
        if detections:
            api.add_mappings(detections, source="chat-input")
            api.save()
    return api.mask(text)


def _anon_unmask_response(text: str) -> str:
    """Unmask LLM response text, replacing anon words with real values."""
    bra_root = get_bra_dir()
    if not bra_root:
        return text
    body_root = _body_root(bra_root)
    if _anon_disabled(body_root):
        return text
    api, err = _get_anon_api()
    if err or api is None:
        return text
    return api.unmask(text)


def _anon_unmask_content(text: str) -> tuple[str, list[dict]]:
    """Unmask governed file content and return highlight metadata."""
    bra_root = get_bra_dir()
    if not bra_root:
        return text, []
    body_root = _body_root(bra_root)
    if _anon_disabled(body_root):
        return text, []
    api, err = _get_anon_api()
    if err or api is None:
        return text, []

    highlights = []
    unmasked = api.unmask(text)
    for mapping in api.all_mappings():
        if mapping["anon"] in text:
            highlights.append({"real": mapping["real"], "type": mapping["type"]})

    return unmasked, highlights


_NER_ENABLED = False


def _setup_ner():
    """Install transformers+torch if missing, preload the model."""
    global _NER_ENABLED
    import subprocess, sys
    os.environ.pop("BRA_NER_ENABLED", None)

    try:
        import transformers  # noqa: F401
    except ImportError:
        print("[NER] Installing transformers + torch (one-time)...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "transformers", "torch", "-q"],
            stdout=subprocess.DEVNULL,
        )
        print("[NER] Installed.")

    print("[NER] Loading model (first run downloads ~1.6GB)...")
    try:
        bra_root = get_bra_dir()
        body_root = _body_root(bra_root) if bra_root else Path(".")
        cache_dir = str(body_root / ".bra" / ".ner-cache")

        from bra.anon.ner_client import _load_local_pipeline, DEFAULT_MODEL

        pipeline = _load_local_pipeline(DEFAULT_MODEL, hf_cache=cache_dir)
        if pipeline:
            print(f"[NER] Model ready: {DEFAULT_MODEL}")
            _NER_ENABLED = True
            os.environ["BRA_NER_ENABLED"] = "1"
        else:
            print("[NER] Model failed to load — NER will be inactive.")
    except Exception as exc:
        print(f"[NER] Setup error: {exc} — NER will be inactive.")


def _get_anon_api() -> tuple[AnonAPI | None, str | None]:
    """Get AnonAPI instance, or (None, error_message) if BRA dir not configured."""
    bra_root = get_bra_dir()
    if not bra_root:
        return None, "No BRA directory configured"
    body_root = _body_root(bra_root)
    map_path = body_root / ".bra" / "anon_map.json"
    config = load_config()
    ner_endpoint = config.get("ner_endpoint", "")
    local_model = config.get("local_model_endpoint") or config.get("ner_local_model", "")
    from bra.anon.ner_client import DEFAULT_MODEL, NERConfig

    if _NER_ENABLED or ner_endpoint or local_model:
        ner_config = NERConfig(
            endpoint=ner_endpoint if ner_endpoint else None,
            local_model=local_model if local_model else DEFAULT_MODEL,
            hf_cache=str(body_root / ".bra" / ".ner-cache"),
        )
    else:
        ner_config = NERConfig()
    return AnonAPI(map_path=map_path, ner_config=ner_config), None


def _get_local_scope_detect_api() -> tuple[AnonAPI | None, str | None]:
    """Get a local-only AnonAPI for MICRO-SCOPE detection.

    This path must not consult configured external endpoints or local mask URLs.
    It is strictly regex + the local Python NER model gated by `--ner`.
    """
    bra_root = get_bra_dir()
    if not bra_root:
        return None, "No BRA directory configured"
    body_root = _body_root(bra_root)
    map_path = body_root / ".bra" / "anon_map.json"
    from bra.anon.ner_client import DEFAULT_MODEL, NERConfig

    ner_config = NERConfig(
        endpoint=None,
        local_model=DEFAULT_MODEL,
        hf_cache=str(body_root / ".bra" / ".ner-cache"),
    )
    return AnonAPI(map_path=map_path, ner_config=ner_config), None


@app.get("/api/anon/mappings")
async def get_anon_mappings(_=Depends(verify_token)):
    """List all current anonymization mappings."""
    api, err = _get_anon_api()
    if err:
        return {"error": err}
    summary = api.mapping_summary()
    return {
        "mappings": api.all_mappings(),
        "created": summary.get("created", ""),
        "total": summary.get("total", 0),
        "counts_by_type": summary.get("counts_by_type", {}),
    }


@app.post("/api/anon/mappings")
async def add_anon_mapping(request: Request, _=Depends(verify_token)):
    """Add a manual anonymization mapping."""
    api, err = _get_anon_api()
    if err:
        return {"error": err}
    body = await request.json()
    real = body.get("real", "").strip()
    type_ = body.get("type", "operator-flagged").strip()
    if not real:
        raise HTTPException(status_code=400, detail="'real' value is required")
    anon_word = api.add_manual(real, type_=type_)
    api.save()
    summary = api.mapping_summary()
    return {
        "real": real,
        "type": type_,
        "anon": anon_word,
        "created": summary.get("created", ""),
        "total": summary.get("total", 0),
        "counts_by_type": summary.get("counts_by_type", {}),
    }


@app.post("/api/anon/detect")
async def anon_detect(request: Request, _=Depends(verify_token)):
    """Run detection on text and return proposals."""
    body = await request.json()
    text = body.get("text", "")
    mode = str(body.get("mode", "") or "").strip()

    if mode == "regex-only":
        from bra.anon.detect import detect_regex

        proposals = detect_regex(text)
    elif mode == "regex-plus-local":
        if not _NER_ENABLED:
            return {
                "error": "MICRO-SCOPE requires boots to be started with --ner.",
                "proposals": [],
            }
        api, err = _get_local_scope_detect_api()
        if err:
            return {"error": err, "proposals": []}
        proposals = api.detect(text)
    else:
        api, err = _get_anon_api()
        if err:
            return {"error": err}
        proposals = api.detect(text)
    return {
        "proposals": [
            {"value": proposal.value, "type": proposal.type_, "span": list(proposal.span)}
            for proposal in proposals
        ]
    }


@app.post("/api/anon/apply")
async def anon_apply(request: Request, _=Depends(verify_token)):
    """Apply checked proposals to the anonymization map."""
    api, err = _get_anon_api()
    if err:
        return {"error": err}
    body = await request.json()
    proposals = body.get("proposals", [])
    source = body.get("source", "manual")
    from bra.anon.detect import Detection

    checked = [
        Detection(value=proposal["value"], type_=proposal["type"], span=tuple(proposal.get("span", (0, 0))))
        for proposal in proposals
        if proposal.get("checked", True)
    ]
    api.add_mappings(checked, source=source)
    api.save()
    return {"added": len(checked), "mappings": api.all_mappings()}


@app.get("/api/anon/config")
async def get_anon_config(_=Depends(verify_token)):
    """Get current scope and chat token settings."""
    bra_root = get_bra_dir()
    if not bra_root:
        return {"error": "No BRA directory configured"}
    body_root = _body_root(bra_root)
    approvals_dir = body_root / ".bra" / "approvals"
    approvals_dir.mkdir(parents=True, exist_ok=True)

    scope_token = "FRONTIER-SCOPE"
    for token in SCOPE_TOKENS:
        if (approvals_dir / token).exists():
            scope_token = token
            break

    chat_token = "MAP-SCAN"
    for token in CHAT_TOKENS:
        if (approvals_dir / token).exists():
            chat_token = token
            break

    return {"scope_token": scope_token, "chat_token": chat_token}


@app.post("/api/anon/config")
async def set_anon_config(request: Request, _=Depends(verify_token)):
    """Set scope and chat token settings."""
    bra_root = get_bra_dir()
    if not bra_root:
        return {"error": "No BRA directory configured"}
    body_root = _body_root(bra_root)
    approvals_dir = body_root / ".bra" / "approvals"
    approvals_dir.mkdir(parents=True, exist_ok=True)

    body = await request.json()

    scope_token = body.get("scope_token")
    if scope_token and scope_token in SCOPE_TOKENS:
        for token in SCOPE_TOKENS:
            token_file = approvals_dir / token
            if token_file.exists():
                token_file.unlink()
        (approvals_dir / scope_token).touch()

    chat_token = body.get("chat_token")
    if chat_token and chat_token in CHAT_TOKENS:
        for token in CHAT_TOKENS:
            token_file = approvals_dir / token
            if token_file.exists():
                token_file.unlink()
        (approvals_dir / chat_token).touch()

    map_path = body_root / ".bra" / "anon_map.json"
    if not map_path.exists():
        try:
            from bra.anon.mapping import AnonMap

            AnonMap(map_path).save()
        except Exception:
            pass

    return {"scope_token": scope_token, "chat_token": chat_token}


@app.get("/api/stats")
async def get_stats(_: bool = Depends(verify_token)):
    """Get engagement statistics from STATS.md."""
    bra_root = get_bra_dir()
    if not bra_root:
        return {"exists": False, "message": "No BRA directory configured."}

    stats_file = _body_root(bra_root) / "layer3-engagement" / "STATS.md"
    if not stats_file.exists():
        return {"exists": False, "message": "No STATS.md found. Run stats collection first."}

    parsed = parse_stats_markdown(stats_file.read_text())

    return {
        "exists": True,
        "path": str(stats_file),
        "parsed": parsed,
        "modified": datetime.fromtimestamp(stats_file.stat().st_mtime).isoformat()
    }


@app.get("/api/lessons")
async def get_lessons(_: bool = Depends(verify_token)):
    """Get lessons learned content."""
    import re
    bra_root = get_bra_dir()
    if not bra_root:
        return {"exists": False, "message": "No BRA directory configured."}

    lessons_file = _body_root(bra_root) / "layer3-engagement" / "LESSONS-LEARNED.md"
    if not lessons_file.exists():
        return {"exists": False, "message": "No LESSONS-LEARNED.md found. Run lessons-learned script first."}

    content = lessons_file.read_text()

    parsed = {
        "raw": content,
        "generated": None,
        "context": {},
        "kill_chain": [],
        "successful_techniques": [],
        "failed_attempts": [],
        "findings_summary": {},
        "recommendations": [],
        "data_sources": []
    }

    # Extract generated date
    gen_match = re.search(r'>\s*Generated:\s*(.+)', content)
    if gen_match:
        parsed["generated"] = gen_match.group(1).strip()

    # Parse kill chain table
    chain_match = re.search(r'### Kill Chain Progression\s*\n.*?\n\|[^\n]+\n\|[-| \t]+\n((?:\|[^\n]+\n)+)', content, re.DOTALL)
    if chain_match:
        for line in chain_match.group(1).strip().split('\n'):
            cells = [c.strip() for c in line.split('|') if c.strip()]
            if len(cells) >= 2:
                parsed["kill_chain"].append({
                    "phase": cells[0],
                    "status": cells[1],
                    "notes": cells[2] if len(cells) > 2 else ""
                })

    # Parse successful techniques
    success_pattern = r'### Successful Techniques\s*\n.*?\n((?:- [^\n]+\n)+)'
    success_match = re.search(success_pattern, content, re.DOTALL)
    if success_match:
        for line in success_match.group(1).strip().split('\n'):
            if line.startswith('- '):
                parsed["successful_techniques"].append(line[2:].strip())

    # Parse findings summary
    findings_match = re.search(r'### Findings Summary\s*\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
    if findings_match:
        for line in findings_match.group(1).strip().split('\n'):
            cells = [c.strip() for c in line.split('|') if c.strip()]
            if len(cells) >= 2 and not cells[0].startswith('-'):
                severity = cells[0].strip('*')
                count = cells[1].strip('*')
                if count.isdigit():
                    parsed["findings_summary"][severity] = int(count)

    # Parse future priorities
    priorities_match = re.search(r'### Future Priorities\s*\n\n((?:- .+\n)+)', content)
    if priorities_match:
        for line in priorities_match.group(1).strip().split('\n'):
            if line.startswith('- '):
                parsed["recommendations"].append(line[2:].strip())

    # Parse data sources
    sources_match = re.search(r'## Appendix: Data Sources\s*\n.*?\n\|[^\n]+\n\|[-| \t]+\n((?:\|[^\n]+\n)+)', content, re.DOTALL)
    if sources_match:
        for line in sources_match.group(1).strip().split('\n'):
            cells = [c.strip() for c in line.split('|') if c.strip()]
            if len(cells) >= 3:
                parsed["data_sources"].append({
                    "source": cells[0],
                    "status": cells[2]
                })

    return {
        "exists": True,
        "path": str(lessons_file),
        "parsed": parsed,
        "modified": datetime.fromtimestamp(lessons_file.stat().st_mtime).isoformat()
    }


@app.get("/api/roe")
async def get_roe(_: bool = Depends(verify_token)):
    """Get Rules of Engagement."""
    import re
    bra_root = get_bra_dir()
    if not bra_root:
        return {"exists": False, "message": "No BRA directory configured."}

    roe_locations = [
        _body_root(bra_root) / "layer3-engagement" / "ROE.md",
        _body_root(bra_root) / "layer1" / "rules" / "roe.md",
    ]

    for roe_file in roe_locations:
        if roe_file.exists():
            content = roe_file.read_text()

            parsed = {
                "raw": content,
                "engagement": None,
                "effective_date": None,
                "tokens": [],
                "network_constraints": None,
                "data_handling": None,
                "output_constraints": None
            }

            # Extract header info
            eng_match = re.search(r'\*\*Engagement:\*\*\s*(.+)', content)
            date_match = re.search(r'\*\*Effective Date:\*\*\s*(.+)', content)
            if eng_match:
                parsed["engagement"] = eng_match.group(1).strip()
            if date_match:
                parsed["effective_date"] = date_match.group(1).strip()

            # Parse active tokens table
            tokens_match = re.search(r'## Active Tokens\s*\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)', content)
            if tokens_match:
                for line in tokens_match.group(1).strip().split('\n'):
                    cells = [c.strip() for c in line.split('|') if c.strip()]
                    if len(cells) >= 2:
                        parsed["tokens"].append({
                            "token": cells[0],
                            "status": cells[1],
                            "notes": cells[2] if len(cells) > 2 else ""
                        })

            # Parse constraint sections
            network_match = re.search(r'## Network Constraints\s*\n\n((?:.+\n)+?)(?=\n---|\n##)', content)
            if network_match:
                parsed["network_constraints"] = network_match.group(1).strip()

            data_match = re.search(r'## Data Handling\s*\n\n((?:.+\n)+?)(?=\n---|\n##)', content)
            if data_match:
                parsed["data_handling"] = data_match.group(1).strip()

            output_match = re.search(r'## Output Constraints\s*\n\n((?:.+\n)+?)(?=\n---|\n##)', content)
            if output_match:
                parsed["output_constraints"] = output_match.group(1).strip()

            return {
                "exists": True,
                "path": str(roe_file),
                "parsed": parsed,
                "modified": datetime.fromtimestamp(roe_file.stat().st_mtime).isoformat()
            }

    return {
        "exists": False,
        "message": "No ROE.md found."
    }


# ============== Docs Auth ==============


@app.get("/api/docs/auth/status")
async def docs_auth_status(request: Request, _: bool = Depends(verify_token)):
    """Check if docs password is configured and if current session is authenticated."""
    return {
        "disabled": not DOCS_AUTH_ENABLED,
        "password_required": bool(DOCS_AUTH_ENABLED and DOCS_PASSWORD),
        "authenticated": verify_docs_session(request),
    }


@app.post("/api/docs/auth")
async def docs_auth_login(request: Request, _: bool = Depends(verify_token)):
    """Verify docs password and issue a session token."""
    if not DOCS_AUTH_ENABLED:
        return JSONResponse({"ok": True, "message": "Docs login disabled."})
    if not DOCS_PASSWORD:
        return JSONResponse({"ok": True, "message": "No docs password configured."})

    body = await request.json()
    password = body.get("password", "")

    if not hmac.compare_digest(password, DOCS_PASSWORD):
        raise HTTPException(status_code=403, detail="Incorrect docs password")

    session_token = secrets.token_urlsafe(32)
    _docs_session_tokens.add(session_token)
    response = JSONResponse({"ok": True, "docs_session": session_token})
    _set_persistent_cookie(response, DOCS_SESSION_COOKIE_NAME, session_token)
    return response


# ============== Debug Auth ==============


@app.get("/api/debug/auth/status")
async def debug_auth_status(request: Request, _: bool = Depends(verify_token)):
    """Check if current session has debug access."""
    return {
        "disabled": not DEBUG_AUTH_ENABLED,
        "password_required": bool(DEBUG_AUTH_ENABLED and DEBUG_PASSWORD),
        "authenticated": verify_debug_session(request),
    }


@app.post("/api/debug/auth")
async def debug_auth_login(request: Request, _: bool = Depends(verify_token)):
    """Verify debug password and issue a session token."""
    if not DEBUG_AUTH_ENABLED:
        return JSONResponse({"ok": True, "message": "Debug login disabled."})
    if not DEBUG_PASSWORD:
        return JSONResponse({"ok": True, "message": "No debug password configured."})

    body = await request.json()
    password = body.get("password", "")

    if not hmac.compare_digest(password, DEBUG_PASSWORD):
        raise HTTPException(status_code=403, detail="Incorrect debug password")

    session_token = secrets.token_urlsafe(32)
    _debug_session_tokens.add(session_token)
    response = JSONResponse({"ok": True, "debug_session": session_token})
    _set_persistent_cookie(response, DEBUG_SESSION_COOKIE_NAME, session_token)
    return response


@app.get("/api/debug/env")
async def get_debug_env(_: bool = Depends(require_debug_access)):
    """Return live process environment and runtime path resolution details."""
    return _collect_debug_env_snapshot()


@app.get("/api/debug/token-usage")
async def get_debug_token_usage(_: bool = Depends(require_debug_access)):
    """Return SDK token usage/cost summary for Debug/Diag."""
    bra_root = get_bra_dir()
    if not bra_root:
        return {"enabled": True, "exists": False, "message": "No BRA directory configured."}
    from bra.core.token_usage import summarize_token_usage
    return summarize_token_usage(_body_root(bra_root))


def extract_title(file_path: Path) -> str:
    """Extract title from first # heading in markdown file."""
    import re
    try:
        content = file_path.read_text()
        title_match = re.search(r'^#\s+(.+)', content, re.MULTILINE)
        if title_match:
            return title_match.group(1).strip()
    except:
        pass
    # Fallback to filename without extension
    return file_path.stem.replace("-", " ").title()


@app.get("/api/docs")
async def get_docs(request: Request, _: bool = Depends(require_docs_access)):
    """Get reference documentation tree and overview content."""
    bra_root = get_bra_dir()
    if not bra_root:
        return {"exists": False, "message": "No BRA directory configured."}

    reference_dir = _body_root(bra_root) / "layer2-templates" / "reference"
    if not reference_dir.exists():
        return {"exists": False, "message": "Reference docs directory not found."}

    result = {
        "exists": True,
        "overview": None,
        "categories": []
    }

    # Load overview file (00-BRA-OVERVIEW.md)
    overview_file = reference_dir / "00-BRA-OVERVIEW.md"
    if overview_file.exists():
        try:
            content = overview_file.read_text()
            result["overview"] = {
                "filename": overview_file.name,
                "title": extract_title(overview_file),
                "content": content
            }
        except:
            pass

    # Scan subdirectories for categories
    for subdir in sorted(reference_dir.iterdir()):
        if subdir.is_dir():
            category = {
                "name": subdir.name,
                "docs": []
            }

            # Scan markdown files in category
            for doc_file in sorted(subdir.glob("*.md")):
                if doc_file.name in DOCS_HIDDEN_FILENAMES:
                    continue
                category["docs"].append({
                    "filename": doc_file.name,
                    "title": extract_title(doc_file)
                })

            if category["docs"]:
                result["categories"].append(category)

    return result


@app.get("/api/docs/{category}/{filename}")
async def get_doc_content(category: str, filename: str, request: Request, _: bool = Depends(require_docs_access)):
    """Get content of a specific reference document."""
    bra_root = get_bra_dir()
    if not bra_root:
        raise HTTPException(status_code=400, detail="No BRA directory configured.")

    reference_dir = _body_root(bra_root) / "layer2-templates" / "reference"

    # Validate category and filename to prevent path traversal
    if ".." in category or ".." in filename or "/" in category or "/" in filename:
        raise HTTPException(status_code=403, detail="Invalid path")

    doc_path = reference_dir / category / filename

    # Ensure path is within reference directory
    try:
        doc_path.resolve().relative_to(reference_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Path traversal denied")

    if not doc_path.exists() or not doc_path.is_file():
        raise HTTPException(status_code=404, detail="Document not found")

    try:
        content = doc_path.read_text()
        return {
            "filename": filename,
            "category": category,
            "title": extract_title(doc_path),
            "content": content
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read document: {e}")


@app.get("/api/loadout")
async def get_loadout(_: bool = Depends(verify_token)):
    """Get loadout: skills, tools, methodologies, workflows."""
    import re
    bra_root = get_bra_dir()
    if not bra_root:
        return {"exists": False, "message": "No BRA directory configured."}

    result = {
        "exists": True,
        "skills": {"exists": False, "categories": []},
        "tools": {"exists": False, "categories": []},
        "methodologies": {"exists": False, "items": []},
        "workflows": {"exists": False, "items": []}
    }

    # Parse skillset.md (check layer3 first, fallback to layer2-templates)
    skillset_file = _body_root(bra_root) / "layer3-engagement" / "skillset.md"
    if not skillset_file.exists():
        skillset_file = _body_root(bra_root) / "layer2-templates" / "skillset.md"
    if skillset_file.exists():
        content = skillset_file.read_text()
        result["skills"]["exists"] = True
        result["skills"]["path"] = str(skillset_file)

        # Parse skill categories (## N. Category Name)
        category_pattern = r'## \d+\.\s+(.+?)\n((?:###.+?(?=\n## \d+\.|\n---|\Z))+)'
        for cat_match in re.finditer(category_pattern, content, re.DOTALL):
            category = {
                "name": cat_match.group(1).strip(),
                "subcategories": []
            }

            # Parse subcategories (### Subcategory)
            subcat_pattern = r'###\s+(.+?)\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)'
            for subcat_match in re.finditer(subcat_pattern, cat_match.group(2)):
                subcat = {
                    "name": subcat_match.group(1).strip(),
                    "skills": []
                }
                for line in subcat_match.group(2).strip().split('\n'):
                    cells = [c.strip() for c in line.split('|') if c.strip()]
                    if len(cells) >= 2:
                        subcat["skills"].append({
                            "skill": cells[0],
                            "description": cells[1],
                            "proficiency": cells[2] if len(cells) > 2 else ""
                        })
                category["subcategories"].append(subcat)

            if category["subcategories"]:
                result["skills"]["categories"].append(category)

    # Parse toolset.md (from layer2-templates)
    toolset_file = _body_root(bra_root) / "layer2-templates" / "toolset.md"
    if toolset_file.exists():
        content = toolset_file.read_text()
        result["tools"]["exists"] = True
        result["tools"]["path"] = str(toolset_file)

        # Parse tool categories (### Category Name)
        cat_pattern = r'###\s+(.+?)\n\n\|.+\n\|[-|\s]+\n((?:\|.+\n)+)'
        for cat_match in re.finditer(cat_pattern, content):
            category = {
                "name": cat_match.group(1).strip(),
                "tools": []
            }
            for line in cat_match.group(2).strip().split('\n'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) >= 2:
                    category["tools"].append({
                        "tool": cells[0].strip('`'),
                        "purpose": cells[1],
                        "platform": cells[2] if len(cells) > 2 else "",
                        "license": cells[3] if len(cells) > 3 else ""
                    })
            if category["tools"]:
                result["tools"]["categories"].append(category)

    # Parse methodologies from layer2-templates/methodologies/
    methodologies_dir = _body_root(bra_root) / "layer2-templates" / "methodologies"
    if methodologies_dir.exists():
        result["methodologies"]["exists"] = True
        result["methodologies"]["path"] = str(methodologies_dir)

        for method_file in sorted(methodologies_dir.glob("*.md")):
            if method_file.name == "METHODOLOGY-ROADMAP.md":
                continue
            content = method_file.read_text()

            # Extract title and target type
            title_match = re.search(r'^#\s+(.+)', content, re.MULTILINE)
            target_match = re.search(r'\*\*Target Type:\*\*\s*(.+)', content)

            result["methodologies"]["items"].append({
                "filename": method_file.name,
                "name": title_match.group(1).strip() if title_match else method_file.stem,
                "target_type": target_match.group(1).strip() if target_match else None,
                "path": str(method_file)
            })

    # Parse workflows from layer2-templates/workflows/
    workflows_dir = _body_root(bra_root) / "layer2-templates" / "workflows"
    if workflows_dir.exists():
        result["workflows"]["exists"] = True
        result["workflows"]["path"] = str(workflows_dir)

        for workflow_file in sorted(workflows_dir.glob("*.md")):
            content = workflow_file.read_text()

            # Extract title and purpose
            title_match = re.search(r'^#\s+(.+)', content, re.MULTILINE)
            purpose_match = re.search(r'\*\*Purpose:\*\*\s*(.+)', content)

            result["workflows"]["items"].append({
                "filename": workflow_file.name,
                "name": title_match.group(1).strip() if title_match else workflow_file.stem,
                "purpose": purpose_match.group(1).strip() if purpose_match else None,
                "path": str(workflow_file)
            })

    overrides = build_overrides_payload(Path(bra_root))
    result["overrides"] = {
        "exists": overrides.get("exists", False),
        "count": overrides.get("count", 0),
        "active_count": overrides.get("active_count", 0),
        "rules": overrides.get("rules", []),
    }

    return result


# === TELEMETRY START ===
@app.get("/api/telemetry")
async def get_telemetry(_: bool = Depends(verify_token)):
    """Layer 4 telemetry: live stats, cumulative stats, and battle card."""
    bra_root = get_bra_dir()
    if not bra_root:
        return {"exists": False}
    from boots.telemetry import compute_telemetry
    try:
        return {"exists": True, **compute_telemetry(_body_root(bra_root))}
    except Exception as e:
        return {"exists": False, "error": str(e)}
# === TELEMETRY END ===


def _default_manager_portfolio_payload() -> dict:
    """Return a stable default payload for manager portfolio data."""
    return {
        "schema_version": 1,
        "engagements": [],
        "live_fallbacks": {
            "current_bra": {
                "risk_level": "MEDIUM",
                "report_readiness": 55,
                "telemetry_score": 50,
                "manager_note": "Fallback values used when live fields are missing",
            }
        },
    }


@app.get("/api/manager/portfolio")
async def get_manager_portfolio(_: bool = Depends(verify_token)):
    """Read manager portfolio mock data from layer4-telemetry/manager_portfolio.json."""
    payload = _default_manager_portfolio_payload()
    bra_root = get_bra_dir()
    if not bra_root:
        return payload

    project_root = Path(bra_root)
    body_root = _body_root(project_root)
    file_path = body_root / "layer4-telemetry" / "manager_portfolio.json"
    if not file_path.exists() or not file_path.is_file():
        return payload

    try:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception:
        return payload

    if not isinstance(raw, dict):
        return payload

    # Keep response shape stable even with malformed file data.
    schema_version = raw.get("schema_version", 1)
    try:
        payload["schema_version"] = int(schema_version)
    except Exception:
        payload["schema_version"] = 1

    engagements = raw.get("engagements", [])
    if isinstance(engagements, list):
        payload["engagements"] = engagements

    live_fallbacks = raw.get("live_fallbacks", {})
    if isinstance(live_fallbacks, dict):
        current = live_fallbacks.get("current_bra")
        if isinstance(current, dict):
            payload["live_fallbacks"]["current_bra"].update(current)

    return payload


@app.get("/api/overrides")
async def get_overrides(_: bool = Depends(verify_token)):
    """Get current override rules and OVERRIDES.md decision history."""
    bra_root = require_bra_root_path()
    return build_overrides_payload(bra_root)


@app.post("/api/overrides/enable-all")
async def enable_all_overrides(_: bool = Depends(verify_token)):
    """Enable all existing override rules."""
    bra_root = require_bra_root_path()
    require_override_mutation_access(bra_root)
    _, rules = load_overrides_rules(bra_root)
    updated = 0
    for rule in rules:
        if not rule.get("enabled", True):
            rule["enabled"] = True
            updated += 1
    save_overrides_rules(bra_root, rules)
    append_override_history_entry(
        bra_root,
        decision_type="RULES",
        subtype="BULK",
        decision="ENABLED",
        context=f"Web GUI bulk enable (updated={updated})",
    )
    return {
        "status": "ok",
        "updated": updated,
        "message": f"Enabled {updated} override rule(s)",
    }


@app.post("/api/overrides/disable-all")
async def disable_all_overrides(_: bool = Depends(verify_token)):
    """Disable all existing override rules."""
    bra_root = require_bra_root_path()
    require_override_mutation_access(bra_root)
    _, rules = load_overrides_rules(bra_root)
    updated = 0
    for rule in rules:
        if rule.get("enabled", True):
            rule["enabled"] = False
            updated += 1
    save_overrides_rules(bra_root, rules)
    append_override_history_entry(
        bra_root,
        decision_type="RULES",
        subtype="BULK",
        decision="DISABLED",
        context=f"Web GUI bulk disable (updated={updated})",
    )
    return {
        "status": "ok",
        "updated": updated,
        "message": f"Disabled {updated} override rule(s)",
    }


@app.post("/api/overrides/{rule_id}/enable")
async def enable_override(rule_id: str, _: bool = Depends(verify_token)):
    """Enable a single override rule by ID."""
    bra_root = require_bra_root_path()
    require_override_mutation_access(bra_root)
    _, rules = load_overrides_rules(bra_root)
    found = False
    changed = False
    rule_type = "RULE"
    for rule in rules:
        if rule.get("id") == rule_id:
            was_enabled = bool(rule.get("enabled", True))
            rule["enabled"] = True
            found = True
            changed = not was_enabled
            rule_type = str(rule.get("type") or "RULE")
            break
    if not found:
        raise HTTPException(status_code=404, detail=f"Override rule not found: {rule_id}")
    save_overrides_rules(bra_root, rules)
    if changed:
        append_override_history_entry(
            bra_root,
            decision_type=rule_type,
            subtype=rule_id,
            decision="ENABLED",
            override_id=rule_id,
            context="Web GUI rule toggle",
        )
    message = f"Override {rule_id} enabled" if changed else f"Override {rule_id} already enabled"
    return {"status": "ok", "rule_id": rule_id, "enabled": True, "changed": changed, "message": message}


@app.post("/api/overrides/{rule_id}/disable")
async def disable_override(rule_id: str, _: bool = Depends(verify_token)):
    """Disable a single override rule by ID."""
    bra_root = require_bra_root_path()
    require_override_mutation_access(bra_root)
    _, rules = load_overrides_rules(bra_root)
    found = False
    changed = False
    rule_type = "RULE"
    for rule in rules:
        if rule.get("id") == rule_id:
            was_enabled = bool(rule.get("enabled", True))
            rule["enabled"] = False
            found = True
            changed = was_enabled
            rule_type = str(rule.get("type") or "RULE")
            break
    if not found:
        raise HTTPException(status_code=404, detail=f"Override rule not found: {rule_id}")
    save_overrides_rules(bra_root, rules)
    if changed:
        append_override_history_entry(
            bra_root,
            decision_type=rule_type,
            subtype=rule_id,
            decision="DISABLED",
            override_id=rule_id,
            context="Web GUI rule toggle",
        )
    message = f"Override {rule_id} disabled" if changed else f"Override {rule_id} already disabled"
    return {"status": "ok", "rule_id": rule_id, "enabled": False, "changed": changed, "message": message}


@app.post("/api/overrides")
async def add_override(body: dict, _: bool = Depends(verify_token)):
    """Add a new override rule."""
    bra_root = require_bra_root_path()
    require_override_mutation_access(bra_root)

    rule_type = body.get("rule_type", "").upper()
    match = body.get("match", {})
    action = body.get("action", "allow")
    layer = body.get("layer", "3")

    if rule_type not in ("TOKEN", "TOOL", "SCRIPT", "SCOPE_ADD", "SCOPE_UPGRADE"):
        raise HTTPException(status_code=400, detail=f"Invalid rule_type: {rule_type}")

    _, rules = load_overrides_rules(bra_root)

    # Generate next sequential ID
    existing_ids = [int(r["id"].split("-")[1]) for r in rules if r.get("id", "").startswith("so-")]
    next_num = max(existing_ids, default=0) + 1
    rule_id = f"so-{next_num:03d}"

    rules.append({
        "id": rule_id,
        "type": rule_type,
        "match": match,
        "action": action,
        "enabled": True,
        "layer": layer,
        "created_at": datetime.now().isoformat(),
        "created_by": "operator",
    })
    save_overrides_rules(bra_root, rules)
    return {"status": "ok", "rule_id": rule_id}


@app.delete("/api/overrides/{rule_id}")
async def remove_override(rule_id: str, _: bool = Depends(verify_token)):
    """Remove an override rule by ID."""
    bra_root = require_bra_root_path()
    require_override_mutation_access(bra_root)

    _, rules = load_overrides_rules(bra_root)
    new_rules = [r for r in rules if r.get("id") != rule_id]
    if len(new_rules) == len(rules):
        raise HTTPException(status_code=404, detail=f"Override rule not found: {rule_id}")
    save_overrides_rules(bra_root, new_rules)
    return {"status": "ok", "rule_id": rule_id}


@app.get("/api/artifacts")
async def get_artifacts(_: bool = Depends(verify_token)):
    """List artifacts tree."""
    artifacts_dir = get_bra_path("artifacts")
    
    def scan_dir(path: Path, prefix: str = "") -> list:
        items = []
        if not path.exists():
            return items
        
        for item in sorted(path.iterdir()):
            rel_path = f"{prefix}/{item.name}" if prefix else item.name
            if item.is_dir():
                items.append({
                    "name": item.name,
                    "path": rel_path,
                    "type": "directory",
                    "children": scan_dir(item, rel_path)
                })
            else:
                items.append({
                    "name": item.name,
                    "path": rel_path,
                    "type": "file",
                    "size": item.stat().st_size,
                    "modified": datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                })
        return items
    
    return {"artifacts": scan_dir(artifacts_dir)}


@app.get("/api/artifacts/{path:path}")
async def get_artifact(path: str, _: bool = Depends(verify_token)):
    """Serve artifact file with path traversal protection."""
    artifacts_dir = get_bra_path("artifacts")
    file_path = safe_path(artifacts_dir, path)
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")
    
    if file_path.is_dir():
        raise HTTPException(status_code=400, detail="Cannot download directory")
    
    return FileResponse(file_path, filename=file_path.name)


@app.get("/api/engagement-file/{path:path}")
async def get_engagement_file(path: str, _: bool = Depends(verify_token)):
    """Serve file from engagement workspace with fallback search."""
    bra_root = get_bra_dir()
    if not bra_root:
        raise HTTPException(status_code=404, detail="No BRA directory configured")

    engagement_dir = _body_root(bra_root) / "layer3-engagement"

    # Try exact path first, then NOTES/, then NOTES/reqs/
    candidates = [
        safe_path(engagement_dir, path),
        safe_path(engagement_dir, f"NOTES/{path}"),
        safe_path(engagement_dir, f"NOTES/reqs/{path}"),
    ]

    for file_path in candidates:
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path, filename=file_path.name)

    raise HTTPException(status_code=404, detail="File not found")


@app.get("/api/logs")
async def get_logs(_: bool = Depends(verify_token)):
    """List available log files."""
    logs_dir = get_bra_path("logs")
    if not logs_dir.exists():
        return {"logs": []}
    
    logs = []
    for f in sorted(logs_dir.iterdir()):
        if f.is_file():
            logs.append({
                "name": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
            })
    
    return {"logs": logs}


@app.get("/api/logs/{name}")
async def get_log_content(
    name: str,
    tail: int = Query(default=100, le=1000),
    _: bool = Depends(verify_token)
):
    """Get log file content (last N lines)."""
    logs_dir = get_bra_path("logs")
    file_path = safe_path(logs_dir, name)
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Read last N lines
    try:
        with open(file_path, "r", errors="replace") as f:
            lines = f.readlines()
            return {
                "name": name,
                "total_lines": len(lines),
                "lines": lines[-tail:],
                "truncated": len(lines) > tail
            }
    except IOError as e:
        raise HTTPException(status_code=500, detail=f"Failed to read log: {e}")


# ============== WebSocket Routes ==============

class ConnectionManager:
    """Manage WebSocket connections for log streaming."""
    
    def __init__(self):
        self.active_connections: list[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass


manager = ConnectionManager()


class Chat2x4Relay:
    """Single shared upstream Numbuh 2x4 connection broadcast to all browser clients."""

    def __init__(self) -> None:
        self.ws_clients: set = set()
        self._upstream = None
        self._reader_task: "asyncio.Task | None" = None
        self._pending: "dict[str, asyncio.Future]" = {}
        self.session_key: str = NUMBUH_2X4_DEFAULT_SESSION_KEY
        self._connected: bool = False
        self._lock = asyncio.Lock()

    async def broadcast(self, payload: dict) -> None:
        """Send payload to all connected browser clients."""
        dead: set = set()
        for ws in list(self.ws_clients):  # snapshot: prevents RuntimeError on concurrent add/remove
            try:
                await ws.send_text(json.dumps(payload))
            except Exception:
                dead.add(ws)
        self.ws_clients -= dead

    async def _upstream_request(
        self,
        method: str,
        params: dict,
        timeout: float = NUMBUH_2X4_REQUEST_TIMEOUT_SEC,
    ) -> dict:
        if self._upstream is None:
            raise RuntimeError("Upstream not connected")
        req_id = uuid.uuid4().hex
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self._pending[req_id] = future
        await self._upstream.send(
            json.dumps({"type": "req", "id": req_id, "method": method, "params": params})
        )
        try:
            response = await asyncio.wait_for(future, timeout=timeout)
            return response if isinstance(response, dict) else {}
        finally:
            self._pending.pop(req_id, None)

    async def _run_reader(self) -> None:
        """Background task: reads upstream events, routes to browser clients."""
        try:
            async for raw in self._upstream:
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                try:
                    parsed = json.loads(str(raw))
                except Exception:
                    continue

                frame_type = str(parsed.get("type") or "").strip().lower()

                if frame_type == "res":
                    frame_id = str(parsed.get("id") or "").strip()
                    if frame_id:
                        fut = self._pending.get(frame_id)
                        if fut and not fut.done():
                            fut.set_result(parsed)
                    continue

                if frame_type == "event":
                    event_name = str(parsed.get("event") or "").strip().lower()
                    if event_name == "connect.challenge":
                        continue  # only relevant during handshake
                    mapped = _map_numbuh_2x4_event_to_browser_messages(parsed)
                    for message in mapped:
                        if "delta" in message:
                            message["delta"] = _anon_unmask_response(message["delta"])
                        if "content" in message:
                            message["content"] = _anon_unmask_response(message["content"])
                        await self.broadcast(message)
                    continue

                if frame_type == "error":
                    error_msg = str(parsed.get("message") or "Numbuh 2x4 upstream error.")
                    await self.broadcast({"type": "error", "message": error_msg})
                    continue

        except Exception:
            pass
        finally:
            self._connected = False
            self._upstream = None
            self._reader_task = None
            for fut in list(self._pending.values()):
                if not fut.done():
                    fut.cancel()
            self._pending.clear()
            await self.broadcast({"type": "error", "message": "Numbuh 2x4 upstream disconnected."})

    async def ensure_upstream(self, ws_url: str, upstream_token: str) -> bool:
        """Connect to upstream if not already connected. Safe to call concurrently."""
        async with self._lock:
            if self._connected and self._reader_task and not self._reader_task.done():
                return True

            upstream_url = _build_numbuh_2x4_upstream_ws_url(ws_url, upstream_token)
            if not upstream_url:
                return False

            if websockets is None:
                return False

            try:
                upstream = await websockets.connect(
                    upstream_url,
                    open_timeout=10,
                    ping_interval=20,
                    ping_timeout=20,
                    max_size=2_000_000,
                )
            except Exception as exc:
                _debug("chat_relay_connect_failed", error=str(exc))
                return False

            # Handshake: wait for challenge then send connect request.
            # A temporary local reader handles both the challenge event and the
            # connect response so the main reader task can start cleanly after.
            loop = asyncio.get_running_loop()
            challenge_future: asyncio.Future = loop.create_future()

            async def _handshake_reader() -> None:
                async for raw in upstream:
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8", errors="replace")
                    try:
                        parsed = json.loads(str(raw))
                    except Exception:
                        continue
                    frame_type = str(parsed.get("type") or "").strip().lower()
                    if frame_type == "event":
                        event_name = str(parsed.get("event") or "").strip().lower()
                        if event_name == "connect.challenge":
                            payload = parsed.get("payload")
                            nonce = (
                                str(payload.get("nonce") or "").strip()
                                if isinstance(payload, dict)
                                else ""
                            )
                            if nonce and not challenge_future.done():
                                challenge_future.set_result(nonce)
                    if frame_type == "res":
                        frame_id = str(parsed.get("id") or "").strip()
                        if frame_id:
                            fut = self._pending.get(frame_id)
                            if fut and not fut.done():
                                fut.set_result(parsed)

            handshake_task = asyncio.create_task(_handshake_reader())
            try:
                connect_nonce = await asyncio.wait_for(
                    asyncio.shield(challenge_future),
                    timeout=NUMBUH_2X4_CONNECT_TIMEOUT_SEC,
                )
                self._upstream = upstream  # needed by _upstream_request
                connect_resp = await self._upstream_request(
                    "connect",
                    _build_numbuh_2x4_connect_params(upstream_token, connect_nonce),
                    timeout=NUMBUH_2X4_CONNECT_TIMEOUT_SEC,
                )
            except Exception as exc:
                _debug("chat_relay_handshake_failed", error=str(exc))
                handshake_task.cancel()
                await asyncio.gather(handshake_task, return_exceptions=True)
                try:
                    await upstream.close()
                except Exception:
                    pass
                self._upstream = None
                return False
            finally:
                handshake_task.cancel()
                await asyncio.gather(handshake_task, return_exceptions=True)

            if not connect_resp.get("ok"):
                err_obj = connect_resp.get("error")
                err_msg = (
                    str(err_obj.get("message"))
                    if isinstance(err_obj, dict) and err_obj.get("message")
                    else "Upstream connect failed."
                )
                _debug("chat_relay_connect_rejected", error=err_msg)
                try:
                    await upstream.close()
                except Exception:
                    pass
                self._upstream = None
                return False

            hello_payload = connect_resp.get("payload")
            if isinstance(hello_payload, dict):
                self.session_key = _resolve_numbuh_2x4_session_key(hello_payload)

            self._connected = True
            self._reader_task = asyncio.create_task(self._run_reader())
            _debug("chat_relay_upstream_ready", session_key=self.session_key)
            return True

    async def send_chat(self, content: str, run_id: str, session_key: str) -> dict:
        return await self._upstream_request(
            "chat.send",
            {"sessionKey": session_key, "message": content, "idempotencyKey": run_id},
        )


_chat_2x4_relay = Chat2x4Relay()


@app.websocket("/ws/logs")
async def websocket_logs(
    websocket: WebSocket,
    token: str = Query(default=""),
    log: str = Query(default="track.log")
):
    """WebSocket endpoint for live log streaming."""
    ws_id = uuid.uuid4().hex[:12]
    resolved_token = _resolve_websocket_auth_token(websocket, token)
    _debug("ws_logs_connect_attempt", ws_id=ws_id, log=log, token_valid=(not AUTH_TOKEN or resolved_token == AUTH_TOKEN), bra_root=BRA_DIR or "")
    # Verify token
    if AUTH_TOKEN and resolved_token != AUTH_TOKEN:
        await websocket.close(code=4001, reason="Invalid token")
        _debug("ws_logs_rejected_auth", ws_id=ws_id, bra_root=BRA_DIR or "")
        return
    
    await manager.connect(websocket)
    
    # Get log file path
    logs_dir = get_bra_path("logs")
    try:
        log_path = safe_path(logs_dir, log)
    except HTTPException:
        await websocket.close(code=4002, reason="Invalid log path")
        _debug("ws_logs_rejected_path", ws_id=ws_id, log=log, bra_root=BRA_DIR or "")
        return
    
    if not log_path.exists():
        await websocket.send_text(json.dumps({"error": f"Log file not found: {log}"}))
        await websocket.close()
        _debug("ws_logs_missing_file", ws_id=ws_id, log_path=str(log_path), bra_root=BRA_DIR or "")
        return
    
    try:
        _debug("ws_logs_connected", ws_id=ws_id, log_path=str(log_path), bra_root=BRA_DIR or "")
        # Send initial tail
        with open(log_path, "r", errors="replace") as f:
            lines = f.readlines()
            await websocket.send_text(json.dumps({
                "type": "initial",
                "lines": lines[-50:]
            }))
            last_pos = f.tell()
        
        # Poll for updates
        while True:
            await asyncio.sleep(1)  # Poll every second
            
            try:
                with open(log_path, "r", errors="replace") as f:
                    f.seek(0, 2)  # End of file
                    current_pos = f.tell()
                    
                    if current_pos > last_pos:
                        f.seek(last_pos)
                        new_content = f.read()
                        if new_content:
                            await websocket.send_text(json.dumps({
                                "type": "append",
                                "content": new_content
                            }))
                        last_pos = current_pos
                    elif current_pos < last_pos:
                        # File was truncated/rotated
                        f.seek(0)
                        content = f.read()
                        await websocket.send_text(json.dumps({
                            "type": "reset",
                            "content": content
                        }))
                        last_pos = current_pos
            except IOError:
                pass
            
            # Check for client messages (like ping)
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=0.01)
                if msg == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                pass
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        _debug("ws_logs_disconnected", ws_id=ws_id, bra_root=BRA_DIR or "")
    except Exception as e:
        await websocket.send_text(json.dumps({"type": "error", "message": str(e)}))
        manager.disconnect(websocket)
        _debug("ws_logs_error", ws_id=ws_id, error=str(e), bra_root=BRA_DIR or "")


@app.websocket("/ws/chat/numbuh_2x4")
async def websocket_chat_numbuh_2x4(websocket: WebSocket, token: str = Query("")):
    """Relay browser chat traffic via shared Numbuh 2x4 upstream connection.

    All connected browser clients share one upstream WebSocket so every viewer
    sees the same conversation in real time.
    """
    ws_id = uuid.uuid4().hex[:12]
    resolved_token = _resolve_websocket_auth_token(websocket, token)
    _debug(
        "ws_chat_numbuh_connect_attempt",
        ws_id=ws_id,
        token_valid=(not AUTH_TOKEN or resolved_token == AUTH_TOKEN),
        bra_root=BRA_DIR or "",
    )
    if AUTH_TOKEN and resolved_token != AUTH_TOKEN:
        await websocket.close(code=4001, reason="Invalid token")
        _debug("ws_chat_numbuh_rejected_auth", ws_id=ws_id, bra_root=BRA_DIR or "")
        return

    await websocket.accept()
    config = load_config()
    get_takeover_controller().configure_relay_settings(config)
    agent_provider = _normalize_2x4_agent_provider(config.get("numbuh_2x4_agent_provider"))
    enabled, ws_url, upstream_token = _resolve_numbuh_2x4_settings(config)

    hermes_base_url = str(config.get("numbuh_2x4_hermes_base_url") or "").strip()
    if agent_provider == NUMBUH_2X4_AGENT_PROVIDER_HERMES:
        if not enabled or not hermes_base_url:
            await websocket.send_json(
                {"type": "error", "message": "Hermes 2x4 relay is not fully configured."}
            )
            await websocket.close(code=4400, reason="Relay not configured")
            _debug(
                "ws_chat_numbuh_rejected_config",
                ws_id=ws_id,
                provider=agent_provider,
                enabled=enabled,
                has_hermes_base_url=bool(hermes_base_url),
                bra_root=BRA_DIR or "",
            )
            return
    elif not enabled or not ws_url or not upstream_token:
        await websocket.send_json(
            {"type": "error", "message": "Numbuh 2x4 relay is not fully configured."}
        )
        await websocket.close(code=4400, reason="Relay not configured")
        _debug(
            "ws_chat_numbuh_rejected_config",
            ws_id=ws_id,
            provider=agent_provider,
            enabled=enabled,
            has_ws_url=bool(ws_url),
            has_token=bool(upstream_token),
            bra_root=BRA_DIR or "",
        )
        return

    if agent_provider == NUMBUH_2X4_AGENT_PROVIDER_OPENCLAW and websockets is None:
        await websocket.send_json(
            {"type": "error", "message": "Relay dependency missing: websockets."}
        )
        await websocket.close(code=1011)
        _debug("ws_chat_numbuh_missing_dependency", ws_id=ws_id, bra_root=BRA_DIR or "")
        return

    if agent_provider == NUMBUH_2X4_AGENT_PROVIDER_OPENCLAW and not await _chat_2x4_relay.ensure_upstream(ws_url, upstream_token):
        await websocket.send_json(
            {"type": "error", "message": "Numbuh 2x4 upstream connection failed."}
        )
        await websocket.close(code=1011)
        _debug("ws_chat_numbuh_upstream_failed", ws_id=ws_id, bra_root=BRA_DIR or "")
        return

    if agent_provider == NUMBUH_2X4_AGENT_PROVIDER_OPENCLAW:
        _chat_2x4_relay.ws_clients.add(websocket)
    _debug("ws_chat_numbuh_connected", ws_id=ws_id, provider=agent_provider, bra_root=BRA_DIR or "")

    async def _send_browser(payload: dict) -> None:
        await websocket.send_text(json.dumps(payload))

    try:
        while True:
            try:
                raw = await websocket.receive_text()
            except WebSocketDisconnect:
                break

            if raw == "ping":
                await _send_browser({"type": "pong"})
                continue

            try:
                payload = json.loads(raw)
            except Exception:
                await _send_browser({"type": "error", "message": "Invalid relay payload JSON."})
                continue

            ok, reason = _validate_numbuh_2x4_client_payload(payload)
            if not ok:
                await _send_browser({"type": "error", "message": reason})
                continue

            content = str(payload.get("content") or "").strip()
            if await _maybe_intercept_takeover_control_message(
                content,
                get_takeover_controller(),
                _send_browser,
            ):
                continue

            run_id = str(payload.get("id") or "").strip() or uuid.uuid4().hex
            session_key = (
                str(payload.get("sessionKey") or "").strip()
                or _chat_2x4_relay.session_key
            )

            if agent_provider == NUMBUH_2X4_AGENT_PROVIDER_HERMES:
                if await _maybe_intercept_2x4_debug_command(content, run_id, _send_browser):
                    continue

            content = _anon_mask_chat(content)

            if agent_provider == NUMBUH_2X4_AGENT_PROVIDER_HERMES:
                try:
                    response_text = await _query_2x4_chat_via_hermes(config, content, session_key)
                except Exception as exc:
                    await _send_browser({"type": "error", "message": f"Hermes chat failed: {exc}"})
                    continue
                await _send_browser(
                    {
                        "type": "assistant.message",
                        "id": run_id,
                        "role": "assistant",
                        "content": _anon_unmask_response(response_text),
                        "done": True,
                    }
                )
            else:
                try:
                    chat_response = await _chat_2x4_relay.send_chat(content, run_id, session_key)
                except Exception as exc:
                    await _send_browser({"type": "error", "message": f"chat.send failed: {exc}"})
                    continue

                if not chat_response.get("ok"):
                    err_obj = chat_response.get("error")
                    err_msg = (
                        str(err_obj.get("message"))
                        if isinstance(err_obj, dict) and err_obj.get("message")
                        else "chat.send failed"
                    )
                    await _send_browser({"type": "error", "message": err_msg})

    except WebSocketDisconnect:
        _debug("ws_chat_numbuh_client_disconnected", ws_id=ws_id, bra_root=BRA_DIR or "")
    except Exception as exc:
        _debug("ws_chat_numbuh_error", ws_id=ws_id, error=str(exc), bra_root=BRA_DIR or "")
        try:
            await websocket.send_json(
                {"type": "error", "message": f"Numbuh 2x4 relay error: {exc}"}
            )
        except Exception:
            pass
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
    finally:
        if agent_provider == NUMBUH_2X4_AGENT_PROVIDER_OPENCLAW:
            _chat_2x4_relay.ws_clients.discard(websocket)
        _debug("ws_chat_numbuh_removed", ws_id=ws_id, bra_root=BRA_DIR or "")


# ============== Engage WebSocket ==============
from boots.engage import EngageManager, route_message

_engage_manager = EngageManager()
_engage_manager.set_takeover_query_fn(_query_2x4_structured_action_via_gateway)


@app.websocket("/ws/engage")
async def websocket_engage(websocket: WebSocket, token: str = Query("")):
    """WebSocket endpoint for agent interaction."""
    import traceback as _tb
    ws_id = uuid.uuid4().hex[:12]
    resolved_token = _resolve_websocket_auth_token(websocket, token)
    print(f"[ws/engage] connection attempt, token={'valid' if resolved_token == AUTH_TOKEN else 'invalid'}", flush=True)
    _debug("ws_engage_connect_attempt", ws_id=ws_id, token_valid=(not AUTH_TOKEN or resolved_token == AUTH_TOKEN), bra_root=BRA_DIR or "")
    if AUTH_TOKEN and resolved_token != AUTH_TOKEN:
        await websocket.close(code=4001)
        _debug("ws_engage_rejected_auth", ws_id=ws_id, bra_root=BRA_DIR or "")
        return

    await websocket.accept()
    print("[ws/engage] accepted", flush=True)
    _debug("ws_engage_connected", ws_id=ws_id, bra_root=BRA_DIR or "")
    _engage_manager.ws_clients.add(websocket)

    try:
        # Send current state for reconnection
        state = _engage_manager.get_state()
        print(f"[ws/engage] sending state: {state}", flush=True)
        _debug("ws_engage_send_state", ws_id=ws_id, state=state, bra_root=BRA_DIR or "")
        await websocket.send_json({"type": "state", **state})

        # Replay history — skip approval events (covered by state snapshot),
        # transient error events, and wizard setup script messages.
        _skip_on_replay = {
            "approval_scope_add", "approval_scope_upgrade",
            "approval_tool", "approval_token", "approval_script",
            "error",
        }
        _wizard_setup_scripts = {"precheck.py", "dry-run.py", "overrides.json", "agentic-handler.py"}
        def _should_replay(e: dict) -> bool:
            if e.get("type") in _skip_on_replay:
                return False
            if e.get("type") in ("script_output", "script_done") and e.get("script") in _wizard_setup_scripts:
                return False
            return True
        replay_events = [e for e in _engage_manager.history if _should_replay(e)]
        print(f"[ws/engage] replaying {len(replay_events)} history events (skipped {len(_engage_manager.history) - len(replay_events)} approval events)", flush=True)
        _debug("ws_engage_replay_history", ws_id=ws_id, count=len(replay_events), bra_root=BRA_DIR or "")
        for event in replay_events:
            await websocket.send_json(event)
        await websocket.send_json({"type": "history_replayed"})

        print("[ws/engage] entering message loop", flush=True)
        while True:
            data = await websocket.receive_json()
            msg_type = data.get('type', '?')
            # Keepalive pings are handled inside route_message with no logging
            bra_root = get_bra_dir()
            if msg_type != 'ping':
                print(f"[ws/engage] received: {msg_type}", flush=True)
                _debug("ws_engage_message", ws_id=ws_id, msg_type=msg_type, bra_root=bra_root or "")
            if not bra_root:
                await websocket.send_json({"type": "error", "message": "BRA directory not configured"})
                _debug("ws_engage_missing_bra_root", ws_id=ws_id, bra_root="")
                continue
            try:
                await route_message(_engage_manager, data, bra_root, websocket)
                if msg_type != 'ping':
                    print(f"[ws/engage] routed: {msg_type}", flush=True)
                    _debug("ws_engage_routed", ws_id=ws_id, msg_type=msg_type, bra_root=bra_root)
            except Exception as route_err:
                print(f"[ws/engage] route error ({msg_type}): {route_err}", flush=True)
                _tb.print_exc()
                await websocket.send_json({"type": "error", "message": str(route_err)})
                _debug("ws_engage_route_error", ws_id=ws_id, msg_type=msg_type, error=str(route_err), bra_root=bra_root)
    except WebSocketDisconnect:
        print("[ws/engage] client disconnected", flush=True)
        _engage_manager.ws_clients.discard(websocket)
        _debug("ws_engage_disconnected", ws_id=ws_id, bra_root=BRA_DIR or "")
    except Exception as e:
        print(f"[ws/engage] ERROR: {e}", flush=True)
        _tb.print_exc()
        _engage_manager.ws_clients.discard(websocket)
        _debug("ws_engage_error", ws_id=ws_id, error=str(e), bra_root=BRA_DIR or "")


@app.get("/api/engage/state")
async def get_engage_state(_=Depends(verify_token)):
    """Get current engagement state."""
    return _engage_manager.get_state()


@app.get("/api/2x4/summary")
async def get_2x4_summary(_=Depends(verify_2x4_service_token)):
    """Return bounded summary payload for 2x4 standby assistance."""
    controller = _resolve_2x4_controller_from_config()
    engage_state = _engage_manager.get_state()
    return {
        "engage": engage_state,
        "takeover": {
            "state": controller.state,
            "active": controller.active,
            "busy": controller.busy,
            "session_id": controller.session_id,
            "call_active": controller.call_active,
            "call_id": controller.call_id,
            "pending_expires_at": controller.pending_expires_at,
            "active_expires_at": controller.active_expires_at,
        },
        "files_allowlist": sorted(NUMBUH_2X4_FILE_ALLOWLIST.keys()),
        "logs_allowlist": sorted(NUMBUH_2X4_LOG_ALLOWLIST.keys()),
    }


@app.get("/api/2x4/file")
async def get_2x4_file(
    name: str = Query(...),
    _: bool = Depends(verify_2x4_service_token),
):
    """Return allowlisted engagement file content for 2x4."""
    file_id = str(name or "").strip().lower()
    relative = NUMBUH_2X4_FILE_ALLOWLIST.get(file_id)
    if not relative:
        raise HTTPException(status_code=403, detail="file id not allowlisted")
    bra_root = get_bra_dir()
    if not bra_root:
        raise HTTPException(status_code=400, detail="BRA directory not configured")
    file_path = safe_path(_body_root(bra_root), relative)
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="file not found")
    content = file_path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    if len(lines) > 400:
        lines = lines[:400]
    limited_content = "\n".join(lines)
    return {
        "name": file_id,
        "path": str(file_path),
        "content": limited_content,
        "truncated": len(content.splitlines()) > len(lines),
    }


@app.get("/api/2x4/log")
async def get_2x4_log(
    name: str = Query(...),
    tail: int = Query(default=120, ge=1, le=400),
    _: bool = Depends(verify_2x4_service_token),
):
    """Return allowlisted log tail content for 2x4."""
    log_id = str(name or "").strip().lower()
    log_name = NUMBUH_2X4_LOG_ALLOWLIST.get(log_id)
    if not log_name:
        raise HTTPException(status_code=403, detail="log id not allowlisted")
    logs_dir = get_bra_path("logs")
    file_path = safe_path(logs_dir, log_name)
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="log not found")
    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        lines = handle.readlines()
    return {
        "name": log_id,
        "path": str(file_path),
        "total_lines": len(lines),
        "lines": lines[-tail:],
        "truncated": len(lines) > tail,
    }


@app.get("/api/2x4/engage-status")
async def get_2x4_engage_status(request: Request, _: bool = Depends(verify_2x4_service_token)):
    """Return engage state only when an active takeover lease is present."""
    controller = _resolve_2x4_controller_from_config()
    _require_active_2x4_lease(request, controller)
    return {
        "engage": _engage_manager.get_state(),
        "takeover": {
            "state": controller.state,
            "lease_id": controller.takeover_lease_id,
            "active_expires_at": controller.active_expires_at,
        },
    }


async def _dispatch_2x4_call_message(
    request: Request,
    controller: TakeoverController,
    message: dict[str, Any],
) -> dict[str, Any]:
    _require_active_2x4_lease(request, controller)
    bra_root = get_bra_dir()
    if not bra_root:
        raise HTTPException(status_code=400, detail="BRA directory not configured")
    await route_message(_engage_manager, message, bra_root)
    return {
        "dispatched": True,
        "type": message.get("type"),
        "call_id": message.get("call_id"),
        "state": controller.state,
        "active": controller.active,
        "call_active": controller.call_active,
    }


@app.post("/api/2x4/engage-action")
async def post_2x4_engage_action(
    request: Request,
    payload: dict,
    _: bool = Depends(verify_2x4_service_token),
):
    """Dispatch a bounded structured action into Engage routing when lease is active."""
    controller = _resolve_2x4_controller_from_config()
    _require_active_2x4_lease(request, controller)

    bra_root = get_bra_dir()
    if not bra_root:
        raise HTTPException(status_code=400, detail="BRA directory not configured")

    async def _dispatch(msg: dict[str, Any]) -> None:
        await route_message(_engage_manager, msg, bra_root)

    async def _notify(event: dict[str, Any]) -> None:
        await _engage_manager.broadcast(event)

    dispatched = await controller.dispatch_action_to_engage(
        payload,
        dispatch_fn=_dispatch,
        notify_fn=_notify,
    )
    return {
        "dispatched": bool(dispatched),
        "action": payload,
        "state": controller.state,
    }


@app.post("/api/2x4/call/continue")
async def post_2x4_call_continue(
    request: Request,
    payload: dict,
    _: bool = Depends(verify_2x4_service_token),
):
    """Continue an active takeover call via Engage routing (lease required)."""
    controller = _resolve_2x4_controller_from_config()
    call_id = str(payload.get("call_id") or payload.get("callId") or controller.call_id or "").strip()
    message = str(payload.get("message") or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="message required")
    msg: dict[str, Any] = {"type": "takeover_call_continue", "message": message}
    if call_id:
        msg["call_id"] = call_id
    return await _dispatch_2x4_call_message(request, controller, msg)


@app.post("/api/2x4/call/speak")
async def post_2x4_call_speak(
    request: Request,
    payload: dict,
    _: bool = Depends(verify_2x4_service_token),
):
    """Send speech to an active takeover call via Engage routing (lease required)."""
    controller = _resolve_2x4_controller_from_config()
    call_id = str(payload.get("call_id") or payload.get("callId") or controller.call_id or "").strip()
    message = str(payload.get("message") or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="message required")
    msg: dict[str, Any] = {"type": "takeover_call_speak", "message": message}
    if call_id:
        msg["call_id"] = call_id
    return await _dispatch_2x4_call_message(request, controller, msg)


@app.get("/api/2x4/call/status")
async def get_2x4_call_status(
    request: Request,
    call_id: str | None = Query(default=None),
    include_history: bool = Query(default=False),
    includeHistory: bool = Query(default=False),
    _: bool = Depends(verify_2x4_service_token),
):
    """Query takeover call status through Engage routing (lease required)."""
    controller = _resolve_2x4_controller_from_config()
    resolved_call_id = str(call_id or controller.call_id or "").strip()
    msg: dict[str, Any] = {"type": "takeover_call_status"}
    if resolved_call_id:
        msg["call_id"] = resolved_call_id
    if include_history or includeHistory:
        msg["includeHistory"] = True
    return await _dispatch_2x4_call_message(request, controller, msg)


@app.post("/api/2x4/call/stop")
async def post_2x4_call_stop(
    request: Request,
    payload: dict,
    _: bool = Depends(verify_2x4_service_token),
):
    """Stop an active takeover call through Engage routing (lease required)."""
    controller = _resolve_2x4_controller_from_config()
    call_id = str(payload.get("call_id") or payload.get("callId") or controller.call_id or "").strip()
    msg: dict[str, Any] = {"type": "takeover_call_stop"}
    if call_id:
        msg["call_id"] = call_id
    return await _dispatch_2x4_call_message(request, controller, msg)


@app.post("/api/2x4/takeover-confirm")
async def post_2x4_takeover_confirm(payload: dict, _: bool = Depends(verify_2x4_service_token)):
    """Confirm pending takeover request (exact Yes) and activate lease."""
    controller = _resolve_2x4_controller_from_config()
    confirmation = str(payload.get("confirmation") or payload.get("message") or "").strip()
    confirmed = controller.confirm_takeover(confirmation)
    if not confirmed:
        raise HTTPException(status_code=400, detail="takeover confirmation rejected")
    await _engage_manager.broadcast(
        {
            "type": "takeover_confirmation_received",
            "active": True,
            "message": "2x4 takeover active for 30 seconds.",
            "lease_id": controller.takeover_lease_id,
        }
    )
    await _engage_manager.broadcast(
        {
            "type": "takeover_status",
            "active": True,
            "message": "2x4 takeover active.",
        }
    )
    return {
        "ok": True,
        "state": controller.state,
        "active": controller.active,
        "takeover_lease_id": controller.takeover_lease_id,
        "active_expires_at": controller.active_expires_at,
    }


@app.post("/api/2x4/stand-down")
async def post_2x4_stand_down(_: bool = Depends(verify_2x4_service_token)):
    """Force standby mode and invalidate any active takeover lease."""
    controller = _resolve_2x4_controller_from_config()
    controller.disable_takeover()
    await _engage_manager.broadcast(
        {
            "type": "takeover_stand_down",
            "active": False,
            "message": "2x4 takeover inactive.",
        }
    )
    await _engage_manager.broadcast(
        {
            "type": "takeover_status",
            "active": False,
            "message": "2x4 takeover inactive.",
        }
    )
    return {"ok": True, "state": controller.state, "active": controller.active}


# ============== Process Management API ==============


def _list_bra_processes() -> list[dict]:
    """List all BRA-related processes: agent subprocesses, ttyd, tmux, boots server."""
    try:
        output = subprocess.check_output(
            ["ps", "-Ao", "pid=,ppid=,stat=,command="],
            text=True,
        )
    except Exception:
        return []

    server_pid = os.getpid()
    parent_by_pid: dict[int, int] = {}
    stat_by_pid: dict[int, str] = {}
    command_by_pid: dict[int, str] = {}

    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        pid_text, ppid_text, stat_text = parts[0], parts[1], parts[2]
        if not (pid_text.isdigit() and ppid_text.isdigit()):
            continue
        pid = int(pid_text)
        ppid = int(ppid_text)
        command = parts[3] if len(parts) > 3 else ""
        parent_by_pid[pid] = ppid
        stat_by_pid[pid] = stat_text
        command_by_pid[pid] = command

    def _is_descendant_of(pid: int, ancestor: int) -> bool:
        visited: set[int] = set()
        current = pid
        while current not in visited:
            visited.add(current)
            parent = parent_by_pid.get(current)
            if parent is None:
                return False
            if parent == ancestor:
                return True
            if parent <= 1:
                return False
            current = parent
        return False

    processes: list[dict] = []

    # Boots server itself
    if server_pid in command_by_pid:
        processes.append({
            "pid": server_pid,
            "category": "server",
            "label": "Boots Server",
            "command": command_by_pid.get(server_pid, "")[:120],
            "status": stat_by_pid.get(server_pid, "?"),
            "killable": False,
        })

    # ttyd process
    if ttyd_process and ttyd_process.poll() is None:
        ttyd_pid = ttyd_process.pid
        processes.append({
            "pid": ttyd_pid,
            "category": "ttyd",
            "label": "ttyd Terminal",
            "command": command_by_pid.get(ttyd_pid, "ttyd")[:120],
            "status": stat_by_pid.get(ttyd_pid, "?"),
            "killable": True,
        })

    # Tmux sessions
    try:
        tmux_out = subprocess.check_output(
            ["tmux", "list-sessions", "-F", "#{session_name}:#{session_id}:#{pane_pid}"],
            text=True, stderr=subprocess.DEVNULL,
        )
        for line in tmux_out.strip().splitlines():
            parts = line.split(":", 2)
            if len(parts) >= 3 and parts[2].isdigit():
                processes.append({
                    "pid": int(parts[2]),
                    "category": "tmux",
                    "label": f"tmux: {parts[0]}",
                    "command": command_by_pid.get(int(parts[2]), f"tmux session {parts[0]}")[:120],
                    "status": stat_by_pid.get(int(parts[2]), "?"),
                    "killable": True,
                })
    except Exception:
        pass

    # OpenClaw gateway/operator processes
    for pid, command in command_by_pid.items():
        lowered = command.lower()
        if "openclaw" not in lowered:
            continue
        processes.append({
            "pid": pid,
            "category": "openclaw",
            "label": "OpenClaw Gateway",
            "command": command[:120],
            "status": stat_by_pid.get(pid, "?"),
            "killable": True,
        })

    # Cloudflared tunnel processes (managed + external)
    for pid, command in command_by_pid.items():
        lowered = command.lower()
        if "cloudflared" not in lowered:
            continue
        tunnel_name = ""
        match = re.search(r"\btunnel\s+run\s+([^\s]+)", command, flags=re.IGNORECASE)
        if match:
            tunnel_name = match.group(1).strip().strip("\"'")
        label = f"Cloudflared Tunnel ({tunnel_name})" if tunnel_name else "Cloudflared Tunnel"
        processes.append({
            "pid": pid,
            "category": "cloudflared",
            "label": label,
            "tunnel_name": tunnel_name,
            "command": command[:120],
            "status": stat_by_pid.get(pid, "?"),
            "killable": True,
        })

    # Proxy sidecar (LiteLLM)
    for pid, command in command_by_pid.items():
        if "litellm" in command.lower() and "--config" in command.lower():
            processes.append({
                "pid": pid,
                "category": "proxy_sidecar",
                "label": "Proxy (LiteLLM)",
                "command": command[:120],
                "status": stat_by_pid.get(pid, "?"),
                "killable": True,
            })

    # Agent subprocesses (Claude SDK)
    for pid, command in command_by_pid.items():
        if "claude_agent_sdk/_bundled/claude" in command.lower():
            if _is_descendant_of(pid, server_pid):
                processes.append({
                    "pid": pid,
                    "category": "agent",
                    "label": "Agent (Claude SDK)",
                    "command": command[:120],
                    "status": stat_by_pid.get(pid, "?"),
                    "killable": True,
                })

    # Agent child processes (children of agent PIDs)
    agent_pids = {p["pid"] for p in processes if p["category"] == "agent"}
    for pid, command in command_by_pid.items():
        if pid in agent_pids or pid == server_pid:
            continue
        for agent_pid in agent_pids:
            if _is_descendant_of(pid, agent_pid):
                processes.append({
                    "pid": pid,
                    "category": "agent_child",
                    "label": "Agent Subprocess",
                    "command": command[:120],
                    "status": stat_by_pid.get(pid, "?"),
                    "killable": True,
                })
                break

    return sorted(processes, key=lambda p: (p["category"], p["pid"]))


@app.get("/api/processes")
async def list_processes(_=Depends(verify_token)):
    """List all BRA-related processes."""
    return {"processes": _list_bra_processes()}


@app.post("/api/processes/{pid}/kill")
async def kill_process(pid: int, _=Depends(verify_token)):
    """Kill a specific BRA process by PID. Uses SIGTERM then SIGKILL."""
    procs = _list_bra_processes()
    target = next((p for p in procs if p["pid"] == pid), None)
    if not target:
        raise HTTPException(404, "Process not found or not a BRA process")
    if not target["killable"]:
        raise HTTPException(403, "Cannot kill this process")
    try:
        os.kill(pid, signal.SIGTERM)
        await asyncio.sleep(0.75)
        try:
            os.kill(pid, 0)
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    except ProcessLookupError:
        raise HTTPException(404, "Process already terminated")
    except Exception as e:
        raise HTTPException(500, f"Failed to kill process: {e}")
    _debug("diag_process_killed", pid=pid, category=target["category"], label=target["label"])
    return {"status": "ok", "pid": pid, "label": target["label"]}


@app.post("/api/processes/kill-all-agents")
async def kill_all_agents(_=Depends(verify_token)):
    """Kill all agent subprocesses via the engage manager's termination method."""
    terminated = await _engage_manager._terminate_all_agent_subprocesses(reason="diag_kill_all")
    _debug("diag_kill_all_agents", count=len(terminated), pids=terminated)
    return {"status": "ok", "terminated": terminated, "count": len(terminated)}


@app.get("/api/cloudflared/tunnel/status")
async def cloudflared_tunnel_status(_=Depends(verify_token)):
    """Get cloudflared quick-tunnel state for Debug/Diag controls."""
    return _cloudflared_status_payload()


@app.post("/api/cloudflared/tunnel/start")
async def cloudflared_tunnel_start(request: dict | None = None, _=Depends(verify_token)):
    """Start cloudflared tunnel (named mode when configured, quick mode fallback)."""
    target_url = CLOUDFLARED_DEFAULT_TARGET_URL
    tunnel_name = ""
    config_path = ""
    try:
        config = load_config()
    except Exception:
        config = {}
    tunnel_name, config_path = _resolve_cloudflared_named_tunnel_config(config)
    if isinstance(request, dict):
        target_url = str(request.get("target_url", "") or "").strip() or CLOUDFLARED_DEFAULT_TARGET_URL
        tunnel_name = str(request.get("tunnel_name", "") or "").strip() or tunnel_name
        config_path = str(request.get("config_path", "") or "").strip() or config_path
    result = _start_cloudflared_tunnel(
        target_url,
        tunnel_name=tunnel_name,
        config_path=config_path,
    )
    config_updated = False
    webhook_url = str(result.get("webhook_url", "") or "").strip()
    if webhook_url:
        try:
            config_updated = _persist_voice_call_public_url(webhook_url)
        except Exception as exc:
            _debug("diag_cloudflared_start_config_sync_error", error=str(exc), webhook_url=webhook_url)
            existing_error = str(result.get("last_error", "") or "").strip()
            config_error = f"Config sync failed: {exc}"
            result["last_error"] = f"{existing_error}; {config_error}" if existing_error else config_error
    result["config_voice_call_public_url_updated"] = config_updated
    _debug(
        "diag_cloudflared_start",
        running=result.get("running"),
        managed=result.get("managed"),
        mode=result.get("mode"),
        tunnel_name=result.get("tunnel_name"),
        pid=result.get("pid"),
        target_url=result.get("target_url"),
        public_url=result.get("public_url"),
    )
    return result


@app.post("/api/cloudflared/tunnel/stop")
async def cloudflared_tunnel_stop(_=Depends(verify_token)):
    """Stop cloudflared quick tunnel (managed preferred, external fallback)."""
    result = _stop_cloudflared_tunnel()
    _debug(
        "diag_cloudflared_stop",
        stopped=result.get("stopped"),
        source=result.get("source"),
        pid=result.get("pid"),
    )
    return result


@app.get("/api/engage/download/{filename}")
async def download_packup(filename: str, _=Depends(verify_token)):
    """Download a packup archive."""
    bra_root = get_bra_dir()
    if not bra_root:
        raise HTTPException(400, "BRA directory not configured")

    body_root = _body_root(bra_root)
    file_path = safe_path(body_root, filename)
    if not file_path or not Path(file_path).exists():
        raise HTTPException(404, "Archive not found")

    if not filename.startswith("packup_") or not filename.endswith(".tar.gz"):
        raise HTTPException(400, "Invalid archive filename")

    return FileResponse(file_path, filename=filename,
                        media_type="application/gzip")


# ============== Harness Explorer API ==============


@app.get("/api/harness")
async def list_harnesses(_: bool = Depends(require_debug_access)):
    """List all registered harnesses."""
    return [h.to_dict() for h in get_registry()]


@app.get("/api/harness/{name}/prompt")
async def get_harness_prompt(name: str, request: Request, _: bool = Depends(require_debug_access)):
    """Build and return the prompt for a harness (preview only)."""
    h = get_harness(name)
    if not h:
        raise HTTPException(status_code=404, detail=f"Harness '{name}' not found")
    bra_dir = get_bra_dir()
    if not bra_dir:
        raise HTTPException(status_code=400, detail="BRA directory not configured")
    bra_root = _body_root(bra_dir)
    params = dict(request.query_params)
    try:
        result = h.build_prompt(params, bra_root)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return result.to_dict()


@app.post("/api/harness/{name}/run")
async def run_harness(name: str, body: dict, _: bool = Depends(require_debug_access)):
    """Execute a harness with SSE streaming."""
    h = get_harness(name)
    if not h:
        raise HTTPException(status_code=404, detail=f"Harness '{name}' not found")
    if not h.executable:
        raise HTTPException(status_code=404, detail=f"Harness '{name}' does not support execution")
    bra_dir = get_bra_dir()
    if not bra_dir:
        raise HTTPException(status_code=400, detail="BRA directory not configured")
    bra_root = _body_root(bra_dir)
    params = body.get("params", {})

    async def event_stream():
        try:
            async for chunk in h.execute(params, bra_root):
                yield f"data: {chunk}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {e}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ============== Static Files & Frontend ==============



@app.get("/preview", response_class=HTMLResponse)
async def serve_preview():
    """Serve the color preview page when available."""
    static_dir = Path(__file__).parent / "static"
    preview_file = static_dir / "preview.html"
    if preview_file.exists():
        return HTMLResponse(preview_file.read_text())
    return HTMLResponse("<h1>Preview not found</h1>")


@app.get("/manager", response_class=HTMLResponse)
async def serve_manager_frontend():
    """Serve the standalone manager dashboard page."""
    static_dir = Path(__file__).parent / "static"
    manager_file = static_dir / "manager.html"
    if manager_file.exists():
        return HTMLResponse(manager_file.read_text())
    return HTMLResponse("<h1>Manager Dashboard</h1><p>Frontend not found. Check static/manager.html</p>")


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the main frontend page."""
    static_dir = Path(__file__).parent / "static"
    index_file = static_dir / "index.html"
    if index_file.exists():
        return HTMLResponse(index_file.read_text())
    return HTMLResponse("<h1>BRA Web GUI</h1><p>Frontend not found. Check static/index.html</p>")


# Mount static files
static_path = Path(__file__).parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# ============== Startup ==============

def print_startup_banner(host: str, port: int, token: str):
    """Print startup information."""
    print("\n" + "=" * 60)
    print("  BRA Web GUI - Battle Ready Armor Dashboard")
    print("=" * 60)
    print(f"\n  URL:   http://{host}:{port}")
    print(f"  Token: {token}")
    print(f"  2x4 Service Token: {NUMBUH_2X4_SERVICE_TOKEN if NUMBUH_2X4_SERVICE_TOKEN else '(unset)'}")
    docs_pw_status = "SET" if (DOCS_AUTH_ENABLED and DOCS_PASSWORD) else "DISABLED"
    debug_pw_status = "SET" if (DEBUG_AUTH_ENABLED and DEBUG_PASSWORD) else "DISABLED"
    print(f"  Docs Password: {docs_pw_status}")
    print(f"  Debug Password: {debug_pw_status}")
    print(f"\n  BRA Directory: {BRA_DIR}")
    print(f"\n  API Docs: http://{host}:{port}/docs")
    print("=" * 60 + "\n")
    _debug("startup_banner", host=host, port=port, token_present=bool(token and token != "(disabled)"), bra_root=BRA_DIR or "")


def main():
    """Main entry point."""
    global BRA_DIR, AUTH_TOKEN, NUMBUH_2X4_SERVICE_TOKEN, DOCS_PASSWORD, DEBUG_PASSWORD
    
    import argparse
    parser = argparse.ArgumentParser(description="BRA Web GUI Server")
    parser.add_argument("--bra-dir", "-d", default=".", help="BRA project directory (contains .bra/)")
    parser.add_argument("--host", default=os.environ.get("BRA_GUI_HOST", "127.0.0.1"), help="Bind host (default: BRA_GUI_HOST or 127.0.0.1)")
    parser.add_argument("--port", "-p", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    parser.add_argument("--no-auth", action="store_true", help="Disable token authentication")
    parser.add_argument("--ner", action="store_true", help="Enable NER model (installs transformers+torch into venv if needed)")
    args = parser.parse_args()
    _debug("main_args", host=args.host, port=args.port, bra_dir=args.bra_dir, no_auth=args.no_auth)
    
    # Set BRA directory
    resolved = _resolve_bra_body_and_project_roots(args.bra_dir)
    BRA_DIR = str(resolved[1]) if resolved else os.path.abspath(args.bra_dir)  # project root
    _debug("main_bra_dir_resolved", bra_root=BRA_DIR)

    # Export focus variables so the debug panel always shows resolved values
    os.environ["BRA_DIR"] = BRA_DIR
    os.environ["BRA_ROOT"] = BRA_DIR
    try:
        from bra.config.settings import get_runtime_config
        _rt = get_runtime_config()
        if _rt.get("model"):
            os.environ.setdefault("BRA_MODEL", str(_rt["model"]))
        if _rt.get("ui_profile"):
            os.environ.setdefault("BRA_UI_PROFILE", str(_rt["ui_profile"]))
        if _rt.get("ui_pack"):
            os.environ.setdefault("BRA_UI_PACK", str(_rt["ui_pack"]))
    except Exception as exc:
        _debug("main_focus_env_error", error=str(exc))

    # Verify .bra directory exists
    bra_path = _body_root(BRA_DIR) / ".bra"
    if not bra_path.exists():
        print(f"Warning: .bra directory not found at {bra_path}")
        print("The GUI will show limited information.")
        _debug("main_missing_bra_state", bra_root=BRA_DIR, bra_path=str(bra_path))
    
    # Setup auth
    if not args.no_auth:
        AUTH_TOKEN = get_or_create_token()
        _debug("main_auth_enabled", bra_root=BRA_DIR, token_present=bool(AUTH_TOKEN))
    else:
        _debug("main_auth_disabled", bra_root=BRA_DIR)
    NUMBUH_2X4_SERVICE_TOKEN = get_or_create_2x4_service_token()

    if args.ner:
        _setup_ner()

    # Load docs and debug passwords
    DOCS_PASSWORD = _load_docs_password()
    DEBUG_PASSWORD = _load_debug_password()
    
    # Print banner
    print_startup_banner(args.host, args.port, AUTH_TOKEN if AUTH_TOKEN else "(disabled)")
    
    # Run server
    import uvicorn
    _debug("uvicorn_start", host=args.host, port=args.port, bra_root=BRA_DIR)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
