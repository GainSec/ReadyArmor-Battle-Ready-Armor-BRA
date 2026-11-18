from __future__ import annotations

from pathlib import Path


def test_main_exposes_token_usage_endpoint_source() -> None:
    source = (Path(__file__).resolve().parents[1] / "boots" / "main.py").read_text(
        encoding="utf-8"
    )

    assert '@app.get("/api/debug/token-usage")' in source
    assert "summarize_token_usage" in source
