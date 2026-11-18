"""Tests for Anthropic token-budget clamping before LiteLLM forwarding."""

from bra.proxy.token_budget import clamp_anthropic_messages_payload


def test_clamp_reduces_excessive_max_tokens():
    payload = {"model": "claude-sonnet-4-6", "max_tokens": 32000}

    clamped = clamp_anthropic_messages_payload(payload, max_completion_tokens=8192)

    assert clamped["max_tokens"] == 8192
    assert payload["max_tokens"] == 32000


def test_clamp_leaves_smaller_max_tokens_unchanged():
    payload = {"model": "claude-sonnet-4-6", "max_tokens": 1024}

    clamped = clamp_anthropic_messages_payload(payload, max_completion_tokens=8192)

    assert clamped["max_tokens"] == 1024


def test_clamp_updates_max_completion_tokens_field_too():
    payload = {"model": "claude-sonnet-4-6", "max_completion_tokens": 12000}

    clamped = clamp_anthropic_messages_payload(payload, max_completion_tokens=8192)

    assert clamped["max_completion_tokens"] == 8192

