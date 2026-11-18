"""report_enhance must respect proxy config when building env."""
import os
from unittest.mock import patch


@patch("bra.core.report_enhance.get_proxy_config", create=True, return_value={
    "proxy_enabled": True,
    "proxy_port": 4001,
    "proxy_backend_url": "http://localhost:11434",
    "proxy_backend_api_key": "",
    "proxy_model_map": {},
})
def test_report_enhance_env_includes_base_url(mock_proxy):
    """When proxy is enabled, the clean_env for report_enhance must include ANTHROPIC_BASE_URL."""
    clean_env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
    proxy_cfg = mock_proxy()
    if proxy_cfg["proxy_enabled"]:
        clean_env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{proxy_cfg['proxy_port']}/anthropic"
    assert clean_env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:4001/anthropic"
