"""SDK token usage logging for Claude Agent SDK result messages."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TOKEN_USAGE_LOG = "token_usage.jsonl"
DISABLE_TOKEN = "NO-TOKEN-TRACKING"


def is_token_usage_tracking_enabled(body_root: Path) -> bool:
    """Return False when the operator has disabled token tracking."""
    return not (Path(body_root) / ".bra" / "approvals" / DISABLE_TOKEN).exists()


def _jsonable(value: Any) -> Any:
    """Convert SDK/dataclass objects to JSON-safe values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if hasattr(value, "__dict__"):
        return _jsonable(vars(value))
    return str(value)


def _get_attr(message: Any, name: str, default: Any = None) -> Any:
    if isinstance(message, dict):
        return message.get(name, default)
    return getattr(message, name, default)


def _int_value(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _float_value(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _usage_dict(message: Any) -> dict[str, Any]:
    usage = _jsonable(_get_attr(message, "usage", {}) or {})
    if not isinstance(usage, dict):
        usage = {}
    input_tokens = _int_value(usage.get("input_tokens", usage.get("inputTokens")))
    output_tokens = _int_value(usage.get("output_tokens", usage.get("outputTokens")))
    usage["input_tokens"] = input_tokens
    usage["output_tokens"] = output_tokens
    usage["total_tokens"] = _int_value(usage.get("total_tokens", usage.get("totalTokens"))) or (
        input_tokens + output_tokens
    )
    usage["cache_creation_input_tokens"] = _int_value(
        usage.get("cache_creation_input_tokens", usage.get("cacheCreationInputTokens"))
    )
    usage["cache_read_input_tokens"] = _int_value(
        usage.get("cache_read_input_tokens", usage.get("cacheReadInputTokens"))
    )
    return usage


def log_sdk_token_usage(
    message: Any,
    *,
    body_root: Path,
    source: str = "agent_sdk",
) -> bool:
    """Append one SDK ResultMessage token usage row to token_usage.jsonl."""
    root = Path(body_root)
    if not is_token_usage_tracking_enabled(root):
        return False

    usage = _usage_dict(message)
    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "session_id": _get_attr(message, "session_id", ""),
        "subtype": _get_attr(message, "subtype", ""),
        "is_error": bool(_get_attr(message, "is_error", False)),
        "num_turns": _int_value(_get_attr(message, "num_turns", 0)),
        "duration_ms": _int_value(_get_attr(message, "duration_ms", 0)),
        "duration_api_ms": _int_value(_get_attr(message, "duration_api_ms", 0)),
        "total_cost_usd": _float_value(_get_attr(message, "total_cost_usd", 0.0)),
        "usage": usage,
        "model_usage": _jsonable(_get_attr(message, "model_usage", {}) or {}),
    }

    log_path = root / ".bra" / "logs" / TOKEN_USAGE_LOG
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
    return True


def summarize_token_usage(body_root: Path, limit: int = 25) -> dict[str, Any]:
    """Return aggregate and recent SDK token usage rows."""
    root = Path(body_root)
    log_path = root / ".bra" / "logs" / TOKEN_USAGE_LOG
    totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "total_tokens": 0,
        "total_cost_usd": 0.0,
    }
    rows: list[dict[str, Any]] = []

    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            usage = row.get("usage") if isinstance(row.get("usage"), dict) else {}
            input_tokens = _int_value(usage.get("input_tokens"))
            output_tokens = _int_value(usage.get("output_tokens"))
            total_tokens = _int_value(usage.get("total_tokens")) or (input_tokens + output_tokens)
            cache_creation = _int_value(usage.get("cache_creation_input_tokens"))
            cache_read = _int_value(usage.get("cache_read_input_tokens"))
            cost = _float_value(row.get("total_cost_usd"))

            usage["input_tokens"] = input_tokens
            usage["output_tokens"] = output_tokens
            usage["total_tokens"] = total_tokens
            usage["cache_creation_input_tokens"] = cache_creation
            usage["cache_read_input_tokens"] = cache_read
            row["usage"] = usage

            totals["input_tokens"] += input_tokens
            totals["output_tokens"] += output_tokens
            totals["total_tokens"] += total_tokens
            totals["cache_creation_input_tokens"] += cache_creation
            totals["cache_read_input_tokens"] += cache_read
            totals["total_cost_usd"] += cost
            rows.append(row)

    totals["total_cost_usd"] = round(totals["total_cost_usd"], 10)
    return {
        "enabled": is_token_usage_tracking_enabled(root),
        "exists": log_path.exists(),
        "log_path": str(log_path),
        "count": len(rows),
        "totals": totals,
        "recent": list(reversed(rows[-limit:])),
    }
