"""Tests for proxy sidecar lifecycle during engagement."""
from unittest.mock import patch, AsyncMock, MagicMock
import asyncio


def test_engagement_starts_proxy_when_enabled():
    from boots.engage import EngageManager

    mock_sidecar = MagicMock()
    mock_sidecar.start = AsyncMock(return_value=MagicMock(ok=True, port=4000))
    mock_sidecar.is_running = True

    with patch("boots.engage.get_proxy_config", return_value={
        "proxy_enabled": True,
        "proxy_port": 4000,
        "proxy_backend_url": "http://localhost:11434",
        "proxy_backend_api_key": "",
        "proxy_model_map": {"claude-sonnet-4-6": "ollama/llama3.1"},
    }), patch("boots.engage.ProxySidecar", return_value=mock_sidecar), \
         patch("boots.engage.build_litellm_config", return_value="model_list: []"):
        mgr = EngageManager.__new__(EngageManager)
        mgr._proxy_sidecar = None
        mgr._active_body_root = MagicMock()
        mgr._active_body_root.__truediv__ = MagicMock(return_value=MagicMock(__str__=lambda s: "/tmp/.bra"))
        mgr.broadcast = AsyncMock()
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(mgr._ensure_proxy_running())
        finally:
            loop.close()
        mock_sidecar.start.assert_awaited_once()


def test_engagement_skips_proxy_when_disabled():
    from boots.engage import EngageManager

    with patch("boots.engage.get_proxy_config", return_value={
        "proxy_enabled": False,
        "proxy_port": 4000,
        "proxy_backend_url": "",
        "proxy_backend_api_key": "",
        "proxy_model_map": {},
    }):
        mgr = EngageManager.__new__(EngageManager)
        mgr._proxy_sidecar = None
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(mgr._ensure_proxy_running())
        finally:
            loop.close()
        assert mgr._proxy_sidecar is None
