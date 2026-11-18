"""Canonical marker event ledger utilities."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CANONICAL_EVENT_FIELDS = (
    "timestamp",
    "category",
    "marker_type",
    "capture_id",
    "source_kind",
    "source",
    "artifact_path",
    "line_start",
    "line_end",
    "excerpt_sha256",
    "match_type",
    "title",
    "finding_id",
    "severity",
    "cvss",
    "cwe",
    "attack_surface",
    "status",
    "risk",
    "priority",
    "state",
    "endpoint",
    "method",
    "port",
    "service",
    "version",
    "credential",
    "raw_fields",
    "fields",
)


def _marker_events_path(bra_state_dir: Path) -> Path:
    return Path(bra_state_dir) / "logs" / "marker_events.jsonl"


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_optional_int(value: Any) -> int | None:
    text = _as_text(value)
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _as_fields(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, str] = {}
    for key, raw in value.items():
        k = _as_text(key).lower()
        if not k:
            continue
        normalized[k] = _as_text(raw)
    return normalized


def _as_raw_fields(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_as_text(item) for item in value if _as_text(item)]
    text = _as_text(value)
    if not text:
        return []
    return [text]


def normalize_marker_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize event payload into canonical marker-event schema."""
    if not isinstance(event, dict):
        raise TypeError("event must be a dict")

    fields = _as_fields(event.get("fields"))
    capture_id = _as_text(event.get("capture_id")) or fields.get("capture_id", "")
    source_kind = _as_text(event.get("source_kind")) or fields.get("source_kind", "") or "tool_capture"
    source = _as_text(event.get("source")) or fields.get("source", "")
    artifact_path = _as_text(event.get("artifact_path")) or fields.get("artifact_path", "") or source

    normalized = {
        "timestamp": _as_text(event.get("timestamp")) or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "category": _as_text(event.get("category")).upper() or "UNKNOWN",
        "marker_type": _as_text(event.get("marker_type")).lower() or "unknown",
        "capture_id": capture_id,
        "source_kind": source_kind,
        "source": source,
        "artifact_path": artifact_path,
        "line_start": _as_optional_int(event.get("line_start", fields.get("line_start"))),
        "line_end": _as_optional_int(event.get("line_end", fields.get("line_end"))),
        "excerpt_sha256": _as_text(event.get("excerpt_sha256")) or fields.get("excerpt_sha256", "") or fields.get("sha256", ""),
        "match_type": _as_text(event.get("match_type")) or fields.get("match_type", "") or "unresolved",
        "title": _as_text(event.get("title")) or fields.get("title", ""),
        "finding_id": _as_text(event.get("finding_id")) or fields.get("finding_id", ""),
        "severity": _as_text(event.get("severity")) or fields.get("severity", ""),
        "cvss": _as_text(event.get("cvss")) or fields.get("cvss", ""),
        "cwe": _as_text(event.get("cwe")) or fields.get("cwe", ""),
        "attack_surface": _as_text(event.get("attack_surface")) or fields.get("attack_surface", ""),
        "status": _as_text(event.get("status")) or fields.get("status", ""),
        "risk": _as_text(event.get("risk")) or fields.get("risk", ""),
        "priority": _as_text(event.get("priority")) or fields.get("priority", ""),
        "state": _as_text(event.get("state")) or fields.get("state", ""),
        "endpoint": _as_text(event.get("endpoint")) or fields.get("endpoint", ""),
        "method": _as_text(event.get("method")) or fields.get("method", ""),
        "port": _as_text(event.get("port")) or fields.get("port", ""),
        "service": _as_text(event.get("service")) or fields.get("service", ""),
        "version": _as_text(event.get("version")) or fields.get("version", ""),
        "credential": _as_text(event.get("credential")) or fields.get("credential", ""),
        "raw_fields": _as_raw_fields(event.get("raw_fields")),
        "fields": fields,
    }
    return normalized


def append_marker_event(bra_state_dir: Path, event: dict[str, Any]) -> dict[str, Any]:
    """Append one normalized marker event to marker_events.jsonl."""
    row = normalize_marker_event(event)
    path = _marker_events_path(Path(bra_state_dir))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=True) + "\n")
    return row
