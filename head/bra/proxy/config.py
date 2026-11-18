"""Generate LiteLLM proxy YAML configuration from BRA runtime config."""
from __future__ import annotations

import yaml

_DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"


def build_litellm_config(
    backend_url: str,
    backend_api_key: str = "",
    model_map: dict[str, str] | None = None,
    port: int = 4000,
    context_window: int = 32768,
    max_completion_tokens: int = 8192,
) -> str:
    """Return a LiteLLM proxy config YAML string.

    Args:
        backend_url: Base URL of the OpenAI-compatible backend.
        backend_api_key: API key for the backend (may be empty for local).
        model_map: Mapping of Anthropic model names to backend model names.
                   If None, creates a passthrough for the default model.
        port: Port for the proxy (informational, not embedded in YAML).
    """
    if not model_map:
        model_map = {
            _DEFAULT_ANTHROPIC_MODEL: f"openai/{_DEFAULT_ANTHROPIC_MODEL}",
        }

    model_list = []
    for anthropic_name, backend_name in model_map.items():
        entry: dict = {
            "model_name": anthropic_name,
            "litellm_params": {
                "model": backend_name,
                "api_base": backend_url,
                "max_tokens": max_completion_tokens,
            },
            "model_info": {
                "max_tokens": context_window,
                "max_output_tokens": max_completion_tokens,
            },
        }
        if backend_api_key:
            entry["litellm_params"]["api_key"] = backend_api_key
        model_list.append(entry)

    config = {
        "model_list": model_list,
        "litellm_settings": {
            "drop_params": True,
            "set_verbose": False,
        },
    }
    return yaml.dump(config, default_flow_style=False, sort_keys=False)
