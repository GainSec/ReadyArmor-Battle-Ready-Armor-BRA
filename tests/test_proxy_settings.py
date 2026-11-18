"""Tests for proxy-related runtime config fields."""
import os
from unittest.mock import patch
from bra.config.settings import (
    get_proxy_config,
    set_runtime_config,
)


@patch.dict(
    os.environ,
    {
        "BRA_PROXY_BACKEND_URL": "",
        "BRA_PROXY_BACKEND_API_KEY": "",
        "BRA_PROXY_PORT": "",
        "BRA_PROXY_CONTEXT_WINDOW": "",
        "BRA_PROXY_MAX_COMPLETION_TOKENS": "",
    },
    clear=False,
)
@patch("bra.config.settings._load_config", return_value={})
def test_get_proxy_config_defaults(_mock_load_config):
    cfg = get_proxy_config()
    assert cfg["proxy_enabled"] is False
    assert cfg["proxy_port"] == 4000
    assert cfg["proxy_backend_url"] == ""
    assert cfg["proxy_backend_api_key"] == ""
    assert cfg["proxy_model_map"] == {}
    assert cfg["proxy_context_window"] == 32768
    assert cfg["proxy_max_completion_tokens"] == 8192


@patch.dict(os.environ, {"BRA_PROXY_BACKEND_URL": "http://localhost:11434"}, clear=False)
@patch("bra.config.settings._load_config", return_value={})
def test_get_proxy_config_from_env(_mock_load_config):
    cfg = get_proxy_config()
    assert cfg["proxy_backend_url"] == "http://localhost:11434"
    assert cfg["proxy_enabled"] is True  # env URL auto-enables


@patch.dict(os.environ, {"BRA_PROXY_PORT": "4001"}, clear=False)
@patch("bra.config.settings._load_config", return_value={})
def test_get_proxy_config_port_from_env(_mock_load_config):
    cfg = get_proxy_config()
    assert cfg["proxy_port"] == 4001


@patch.dict(
    os.environ,
    {
        "BRA_PROXY_CONTEXT_WINDOW": "65536",
        "BRA_PROXY_MAX_COMPLETION_TOKENS": "4096",
    },
    clear=False,
)
@patch("bra.config.settings._load_config", return_value={})
def test_get_proxy_config_budget_from_env(_mock_load_config):
    cfg = get_proxy_config()
    assert cfg["proxy_context_window"] == 65536
    assert cfg["proxy_max_completion_tokens"] == 4096
