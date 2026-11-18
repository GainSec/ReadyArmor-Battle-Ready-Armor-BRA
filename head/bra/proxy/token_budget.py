"""Helpers for enforcing token-budget limits on proxied Anthropic requests."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def clamp_anthropic_messages_payload(
    payload: dict[str, Any],
    *,
    max_completion_tokens: int,
) -> dict[str, Any]:
    """Return a copy of an Anthropic payload with completion budget clamped."""
    clamped = deepcopy(payload)

    for key in ("max_tokens", "max_completion_tokens"):
        value = clamped.get(key)
        if isinstance(value, int) and value > max_completion_tokens:
            clamped[key] = max_completion_tokens

    return clamped
