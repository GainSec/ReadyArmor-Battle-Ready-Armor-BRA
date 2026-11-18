from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
import asyncio
import json

from starlette.requests import Request


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

boots_main = importlib.import_module("boots.main")


def _request_with_headers(*headers: tuple[bytes, bytes]) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/config",
        "headers": list(headers),
    }
    return Request(scope)


class BootsAuthTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_docs_password = boots_main.DOCS_PASSWORD
        self._orig_debug_password = boots_main.DEBUG_PASSWORD
        self._orig_docs_tokens = set(boots_main._docs_session_tokens)
        self._orig_debug_tokens = set(boots_main._debug_session_tokens)
        self.addCleanup(self._restore_state)

    def _restore_state(self) -> None:
        boots_main.DOCS_PASSWORD = self._orig_docs_password
        boots_main.DEBUG_PASSWORD = self._orig_debug_password
        boots_main._docs_session_tokens.clear()
        boots_main._docs_session_tokens.update(self._orig_docs_tokens)
        boots_main._debug_session_tokens.clear()
        boots_main._debug_session_tokens.update(self._orig_debug_tokens)

    def test_resolve_request_auth_token_accepts_session_cookie(self) -> None:
        request = _request_with_headers(
            (b"cookie", f"{boots_main.AUTH_COOKIE_NAME}=cookie-secret".encode("utf-8")),
        )

        token = boots_main._resolve_request_auth_token(request, credentials=None)

        self.assertEqual(token, "cookie-secret")

    def test_resolve_request_auth_token_prefers_bearer_header(self) -> None:
        request = _request_with_headers(
            (b"authorization", b"Bearer header-secret"),
            (b"cookie", f"{boots_main.AUTH_COOKIE_NAME}=cookie-secret".encode("utf-8")),
        )

        token = boots_main._resolve_request_auth_token(request, credentials=None)

        self.assertEqual(token, "header-secret")

    def test_resolve_websocket_auth_token_accepts_cookie_before_query(self) -> None:
        websocket = SimpleNamespace(
            headers={},
            cookies={boots_main.AUTH_COOKIE_NAME: "cookie-secret"},
        )

        token = boots_main._resolve_websocket_auth_token(websocket, query_token="query-secret")

        self.assertEqual(token, "cookie-secret")

    def test_docs_auth_is_disabled_even_when_password_is_configured(self) -> None:
        boots_main.DOCS_PASSWORD = "docs-pass"

        status_request = _request_with_headers()
        status = asyncio.run(boots_main.docs_auth_status(status_request, True))

        self.assertFalse(status["password_required"])
        self.assertTrue(status["authenticated"])
        self.assertTrue(status["disabled"])

        self.assertTrue(boots_main.verify_docs_session(status_request))

        login_request = _request_with_json("/api/docs/auth", {"password": "wrong"})
        response = asyncio.run(boots_main.docs_auth_login(login_request, True))

        self.assertEqual(response.status_code, 200)
        self.assertIn("Docs login disabled", response.body.decode("utf-8"))
        cookie_header = response.headers.get("set-cookie", "")
        self.assertNotIn("docs_session=", cookie_header)

    def test_debug_auth_is_disabled_even_when_password_is_configured(self) -> None:
        boots_main.DEBUG_PASSWORD = "debug-pass"

        status_request = _request_with_headers()
        status = asyncio.run(boots_main.debug_auth_status(status_request, True))

        self.assertFalse(status["password_required"])
        self.assertTrue(status["authenticated"])
        self.assertTrue(status["disabled"])

        self.assertTrue(boots_main.verify_debug_session(status_request))

        login_request = _request_with_json("/api/debug/auth", {"password": "wrong"})
        response = asyncio.run(boots_main.debug_auth_login(login_request, True))

        self.assertEqual(response.status_code, 200)
        self.assertIn("Debug login disabled", response.body.decode("utf-8"))
        cookie_header = response.headers.get("set-cookie", "")
        self.assertNotIn("debug_session=", cookie_header)


def _request_with_json(path: str, payload: dict) -> Request:
    body = json.dumps(payload).encode("utf-8")
    async def receive():
        nonlocal body
        chunk = body
        body = b""
        return {"type": "http.request", "body": chunk, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [(b"content-type", b"application/json")],
    }
    return Request(scope, receive=receive)


if __name__ == "__main__":
    unittest.main()
