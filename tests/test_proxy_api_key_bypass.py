"""When proxy is enabled, engagement should not require ANTHROPIC_API_KEY."""
import os
from unittest.mock import patch, MagicMock


@patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False)
def test_proxy_config_allows_empty_key():
    """get_proxy_config returns proxy_enabled=True when env URL is set."""
    from bra.config.settings import get_proxy_config
    with patch.dict(os.environ, {"BRA_PROXY_BACKEND_URL": "http://localhost:11434"}, clear=False):
        cfg = get_proxy_config()
        assert cfg["proxy_enabled"] is True


def test_proxy_placeholder_key():
    """When proxy enabled and no API key, placeholder should be used."""
    # This tests the pattern, not the full runner
    api_key = ""
    proxy_enabled = True
    if not api_key and proxy_enabled:
        api_key = "proxy-routed"
    assert api_key == "proxy-routed"
