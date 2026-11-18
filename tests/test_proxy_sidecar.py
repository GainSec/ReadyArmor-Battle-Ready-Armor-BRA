"""Tests for LiteLLM proxy sidecar process management."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, mock_open, patch
from bra.proxy.litellm_sidecar import ProxySidecar


def test_sidecar_not_running_initially():
    sidecar = ProxySidecar(port=4111)
    assert not sidecar.is_running


def test_sidecar_config_path(tmp_path):
    sidecar = ProxySidecar(port=4111, config_dir=str(tmp_path))
    assert sidecar.config_path.parent == tmp_path
    assert sidecar.config_path.name == "litellm_config.yaml"


def test_sidecar_config_path_default():
    sidecar = ProxySidecar(port=4111)
    from pathlib import Path
    assert sidecar.config_path.parent == Path.home() / ".bra"


def test_sidecar_base_url():
    sidecar = ProxySidecar(port=4001)
    assert sidecar.base_url == "http://127.0.0.1:4001"


@patch("shutil.which", return_value=None)
def test_start_fails_if_litellm_not_installed(mock_which):
    sidecar = ProxySidecar(port=4111)
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(sidecar.start("model_list: []"))
        assert not result.ok
        assert "not installed" in result.error.lower()
    finally:
        loop.close()


def test_stop_when_not_running():
    sidecar = ProxySidecar(port=4111)
    sidecar.stop()
    assert not sidecar.is_running


def test_start_returns_ok_if_already_running():
    sidecar = ProxySidecar(port=4111)
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    sidecar._process = mock_proc
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(sidecar.start("model_list: []"))
        assert result.ok
        assert result.port == 4111
    finally:
        loop.close()


@patch("bra.proxy.litellm_sidecar.open", new_callable=mock_open)
@patch("bra.proxy.litellm_sidecar.subprocess.Popen")
@patch("bra.proxy.litellm_sidecar.ProxySidecar._health_check", new_callable=AsyncMock, return_value=True)
@patch("bra.proxy.litellm_sidecar.ProxySidecar._clear_port")
@patch("shutil.which", return_value="/usr/bin/litellm")
def test_start_sets_chat_completions_env_flag(
    mock_which,
    mock_clear_port,
    mock_health_check,
    mock_popen,
    mock_file,
    tmp_path,
):
    sidecar = ProxySidecar(port=4111, config_dir=str(tmp_path))
    litellm_proc = MagicMock()
    litellm_proc.poll.return_value = None
    clamp_proc = MagicMock()
    clamp_proc.poll.return_value = None
    mock_popen.side_effect = [litellm_proc, clamp_proc]

    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(sidecar.start("model_list: []", max_completion_tokens=8192))
    finally:
        loop.close()

    assert result.ok
    env = mock_popen.call_args_list[0].kwargs["env"]
    assert env["LITELLM_USE_CHAT_COMPLETIONS_URL_FOR_ANTHROPIC_MESSAGES"] == "true"
    assert "LITELLM_USE_RESPONSES_API" not in env
    litellm_cmd = mock_popen.call_args_list[0].args[0]
    clamp_cmd = mock_popen.call_args_list[1].args[0]
    assert "--port" in litellm_cmd
    assert "5111" in litellm_cmd
    assert "-m" in clamp_cmd
    assert "bra.proxy.clamp_proxy" in clamp_cmd
    assert "--listen-port" in clamp_cmd
    assert "4111" in clamp_cmd
    assert "--upstream-base-url" in clamp_cmd
    assert "http://127.0.0.1:5111" in clamp_cmd
