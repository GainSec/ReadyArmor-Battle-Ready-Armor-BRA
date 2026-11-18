"""Tests for LiteLLM proxy config generation."""
import yaml
from bra.proxy.config import build_litellm_config


def test_build_config_minimal():
    cfg = build_litellm_config(
        backend_url="http://localhost:11434",
        backend_api_key="ollama",
        model_map={"claude-sonnet-4-6": "ollama/llama3.1"},
    )
    parsed = yaml.safe_load(cfg)
    assert parsed["model_list"][0]["litellm_params"]["model"] == "ollama/llama3.1"
    assert parsed["model_list"][0]["litellm_params"]["api_base"] == "http://localhost:11434"
    assert parsed["model_list"][0]["model_name"] == "claude-sonnet-4-6"


def test_build_config_no_map_uses_passthrough():
    cfg = build_litellm_config(
        backend_url="http://localhost:8000/v1",
        backend_api_key="token-abc",
    )
    parsed = yaml.safe_load(cfg)
    assert parsed["model_list"][0]["model_name"] == "claude-sonnet-4-6"
    assert parsed["model_list"][0]["litellm_params"]["model"] == "openai/claude-sonnet-4-6"


def test_build_config_multiple_models():
    cfg = build_litellm_config(
        backend_url="https://openrouter.ai/api/v1",
        backend_api_key="or-key",
        model_map={
            "claude-sonnet-4-6": "openrouter/anthropic/claude-sonnet-4-6",
            "claude-haiku-4-5": "openrouter/anthropic/claude-haiku-4-5",
        },
    )
    parsed = yaml.safe_load(cfg)
    assert len(parsed["model_list"]) == 2


def test_build_config_can_target_nvidia_nim_directly():
    cfg = build_litellm_config(
        backend_url="http://spark:8000/v1",
        backend_api_key="nim-key",
        model_map={
            "claude-sonnet-4-6": "openai/nvidia/llama-3.3-nemotron-super-49b-v1.5",
        },
    )
    parsed = yaml.safe_load(cfg)
    entry = parsed["model_list"][0]["litellm_params"]
    assert entry["model"] == "openai/nvidia/llama-3.3-nemotron-super-49b-v1.5"
    assert entry["api_base"] == "http://spark:8000/v1"
    assert entry["api_key"] == "nim-key"


def test_build_config_no_api_key():
    cfg = build_litellm_config(
        backend_url="http://localhost:11434",
        model_map={"claude-sonnet-4-6": "ollama_chat/qwen3.5:32b"},
    )
    parsed = yaml.safe_load(cfg)
    assert "api_key" not in parsed["model_list"][0]["litellm_params"]


def test_drop_params_enabled():
    cfg = build_litellm_config(backend_url="http://localhost:11434")
    parsed = yaml.safe_load(cfg)
    assert parsed["litellm_settings"]["drop_params"] is True


def test_config_does_not_emit_force_chat_completions():
    cfg = build_litellm_config(backend_url="http://localhost:11434")
    parsed = yaml.safe_load(cfg)
    assert "force_chat_completions" not in parsed["litellm_settings"]


def test_build_config_emits_static_completion_cap_and_model_info():
    cfg = build_litellm_config(
        backend_url="http://spark:8000/v1",
        model_map={"claude-sonnet-4-6": "openai/qwen3"},
        context_window=32768,
        max_completion_tokens=8192,
    )
    parsed = yaml.safe_load(cfg)
    entry = parsed["model_list"][0]
    assert entry["litellm_params"]["max_tokens"] == 8192
    assert entry["model_info"]["max_tokens"] == 32768
    assert entry["model_info"]["max_output_tokens"] == 8192
