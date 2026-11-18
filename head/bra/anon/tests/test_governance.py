"""Tests that anon governance is wired correctly."""
import sys
from pathlib import Path

import pytest

# Ensure body/ is importable (layer1 lives under body/)
_body = Path(__file__).resolve().parents[4] / "body"
if str(_body) not in sys.path:
    sys.path.insert(0, str(_body))


def test_anon_tokens_in_known_tokens():
    from layer1.lib.tokens import KNOWN_TOKENS
    anon_tokens = [
        "FRONTIER-SCOPE", "MICRO-SCOPE", "LOCAL-SCOPE", "DUMB-SCOPE", "NO-SCOPE",
        "MAP-SCAN", "ANON-SCAN", "LOCAL-SCAN", "NO-SCAN", "ANON-DISABLE",
    ]
    for t in anon_tokens:
        assert t in KNOWN_TOKENS, f"Token {t} not in KNOWN_TOKENS"


def test_anon_map_in_bra_schema():
    from bra.core.bra_schema import BRA_SCHEMA, resolve_access
    assert "anon_map.json" in BRA_SCHEMA
    assert resolve_access("anon_map.json") == "operator-only"
