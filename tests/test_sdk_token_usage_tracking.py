from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))

from bra.core.token_usage import log_sdk_token_usage, summarize_token_usage


def test_logs_result_message_usage_to_jsonl(tmp_path: Path) -> None:
    body = tmp_path / "body"
    message = SimpleNamespace(
        session_id="sess-1",
        subtype="success",
        is_error=False,
        num_turns=2,
        duration_ms=1000,
        duration_api_ms=800,
        total_cost_usd=0.0123,
        usage={
            "input_tokens": 100,
            "output_tokens": 25,
            "cache_read_input_tokens": 10,
            "cache_creation_input_tokens": 5,
        },
        model_usage={
            "claude-test": {
                "inputTokens": 100,
                "outputTokens": 25,
                "costUSD": 0.0123,
            }
        },
    )

    assert log_sdk_token_usage(message, body_root=body, source="agent_sdk") is True

    log_path = body / ".bra" / "logs" / "token_usage.jsonl"
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert rows[0]["session_id"] == "sess-1"
    assert rows[0]["usage"]["input_tokens"] == 100
    assert rows[0]["usage"]["output_tokens"] == 25
    assert rows[0]["usage"]["total_tokens"] == 125
    assert rows[0]["usage"]["cache_read_input_tokens"] == 10
    assert rows[0]["usage"]["cache_creation_input_tokens"] == 5
    assert rows[0]["total_cost_usd"] == 0.0123


def test_no_token_tracking_token_disables_logging(tmp_path: Path) -> None:
    body = tmp_path / "body"
    (body / ".bra" / "approvals").mkdir(parents=True)
    (body / ".bra" / "approvals" / "NO-TOKEN-TRACKING").touch()

    message = SimpleNamespace(session_id="sess-1", total_cost_usd=1, usage={})

    assert log_sdk_token_usage(message, body_root=body, source="agent_sdk") is False
    assert not (body / ".bra" / "logs" / "token_usage.jsonl").exists()


def test_summarize_token_usage_totals(tmp_path: Path) -> None:
    body = tmp_path / "body"
    log_sdk_token_usage(
        SimpleNamespace(
            session_id="a",
            total_cost_usd=0.1,
            usage={
                "input_tokens": 10,
                "output_tokens": 3,
                "cache_read_input_tokens": 2,
            },
        ),
        body_root=body,
    )
    log_sdk_token_usage(
        SimpleNamespace(
            session_id="b",
            total_cost_usd=0.2,
            usage={
                "input_tokens": 20,
                "output_tokens": 7,
                "cache_creation_input_tokens": 4,
            },
        ),
        body_root=body,
    )

    summary = summarize_token_usage(body)

    assert summary["enabled"] is True
    assert summary["count"] == 2
    assert summary["totals"]["input_tokens"] == 30
    assert summary["totals"]["output_tokens"] == 10
    assert summary["totals"]["total_tokens"] == 40
    assert summary["totals"]["cache_read_input_tokens"] == 2
    assert summary["totals"]["cache_creation_input_tokens"] == 4
    assert summary["totals"]["total_cost_usd"] == 0.3
    assert summary["recent"][0]["usage"]["input_tokens"] == 20
