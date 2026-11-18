"""Tests for ANTHROPIC_BASE_URL injection into agent subprocess env."""
import os
from pathlib import Path
from unittest.mock import patch
from bra.core.agent import _build_claude_runtime_env


@patch.dict(os.environ, {}, clear=False)
@patch("bra.core.agent.get_proxy_config", return_value={
    "proxy_enabled": False,
    "proxy_port": 4000,
    "proxy_backend_url": "",
    "proxy_backend_api_key": "",
    "proxy_model_map": {},
})
def test_no_base_url_when_proxy_disabled(mock_cfg, tmp_path):
    body = tmp_path / "body"
    body.mkdir()
    env = _build_claude_runtime_env(body)
    assert "ANTHROPIC_BASE_URL" not in env


@patch.dict(os.environ, {}, clear=False)
@patch("bra.core.agent.get_proxy_config", return_value={
    "proxy_enabled": True,
    "proxy_port": 4001,
    "proxy_backend_url": "http://localhost:11434",
    "proxy_backend_api_key": "",
    "proxy_model_map": {},
})
def test_base_url_set_when_proxy_enabled(mock_cfg, tmp_path):
    body = tmp_path / "body"
    body.mkdir()
    env = _build_claude_runtime_env(body)
    assert env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:4001"
