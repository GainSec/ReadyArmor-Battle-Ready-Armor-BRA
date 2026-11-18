"""Scriptable materialization of NOTES files from marker_events.jsonl."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from bra.core.capture_provenance import extract_capture_candidates, find_recent_capture, resolve_capture, resolve_capture_hint
from bra.core.intel_writer import IntelWriter


def _events_path(bra_state_dir: Path) -> Path:
    return Path(bra_state_dir) / "logs" / "marker_events.jsonl"


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _event_fields(event: dict[str, Any]) -> dict[str, str]:
    fields = event.get("fields")
    if not isinstance(fields, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in fields.items():
        k = _safe_text(key).lower()
        if not k:
            continue
        out[k] = _safe_text(value)
    return out


def _event_raw_fields(event: dict[str, Any]) -> list[str]:
    raw = event.get("raw_fields")
    if not isinstance(raw, list):
        return []
    return [_safe_text(item) for item in raw if _safe_text(item)]


def _event_value(event: dict[str, Any], fields: dict[str, str], key: str, *aliases: str) -> str:
    candidates = (key,) + aliases
    for name in candidates:
        value = _safe_text(event.get(name))
        if value:
            return value
        if name.lower() in fields and fields[name.lower()]:
            return fields[name.lower()]
    return ""


def _iter_events(events_path: Path) -> list[dict[str, Any]]:
    if not events_path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _infer_capture_id_from_text(text: str) -> str:
    value = _safe_text(text)
    if not value:
        return ""
    candidates = extract_capture_candidates(value)
    if candidates:
        return candidates[0]
    return ""


def _resolve_capture_id(
    *,
    event: dict[str, Any],
    fields: dict[str, str],
    raw: list[str],
    source: str,
    bra_state_dir: Path,
) -> str | None:
    capture_id = _event_value(event, fields, "capture_id") or None
    if capture_id == "provided_info":
        capture_id = None
    if capture_id and resolve_capture(capture_id, Path(bra_state_dir)):
        return capture_id

    hints = [
        source,
        _event_value(event, fields, "title", "description"),
        _event_value(event, fields, "endpoint", "path"),
        " ".join(raw),
    ]
    for hint in hints:
        resolved = resolve_capture_hint(Path(bra_state_dir), hint)
        if resolved:
            return resolved
    for hint in hints:
        inferred = _infer_capture_id_from_text(hint)
        if inferred:
            if resolve_capture(inferred, Path(bra_state_dir)):
                return inferred

    hint_blob = " ".join(part for part in hints if part)
    fuzzy = find_recent_capture(Path(bra_state_dir), hint_blob) if hint_blob else ""
    if fuzzy:
        return fuzzy

    sidecar = Path(bra_state_dir) / "last_capture.json"
    if sidecar.exists():
        try:
            payload = json.loads(sidecar.read_text(encoding="utf-8", errors="replace"))
            sidecar_id = _safe_text(payload.get("capture_id"))
            if sidecar_id:
                return sidecar_id
        except Exception:
            return None
    return None


def replay_marker_events_to_notes(notes_dir: Path, bra_state_dir: Path) -> dict[str, int]:
    """Replay marker events into INTEL.md and LEADS.md using IntelWriter."""
    writer = IntelWriter(Path(notes_dir), bra_dir=Path(bra_state_dir))
    applied = {"intel": 0, "leads": 0}
    last_resolved_capture_id: str | None = None
    for event in _iter_events(_events_path(Path(bra_state_dir))):
        category = _safe_text(event.get("category")).upper()
        marker_type = _safe_text(event.get("marker_type")).lower()
        fields = _event_fields(event)
        raw = _event_raw_fields(event)
        source = _event_value(event, fields, "source", "artifact_path")
        capture_id = _resolve_capture_id(
            event=event,
            fields=fields,
            raw=raw,
            source=source,
            bra_state_dir=Path(bra_state_dir),
        )
        # Propagate the last resolved capture only for lead-like events with
        # no artifact/source hints of their own. Marker rows with their own
        # source should never inherit stale prior provenance.
        if capture_id:
            last_resolved_capture_id = capture_id
        elif (
            last_resolved_capture_id
            and not source
            and category in ("LEAD", "SUGGESTION")
        ):
            capture_id = last_resolved_capture_id
        source_kind = _event_value(event, fields, "source_kind") or None
        if source_kind == "provided_info":
            source_kind = None
        if not source_kind and capture_id:
            source_kind = "tool_capture"

        if category in ("LEAD", "SUGGESTION") or marker_type in ("lead", "suggestion"):
            description = _event_value(event, fields, "title", "description") or (raw[0] if raw else "")
            if not description:
                continue
            priority = _event_value(event, fields, "priority") or "Medium"
            rationale = _event_value(event, fields, "rationale") or (raw[2] if len(raw) > 2 else "")
            writer.append_suggestion(
                description,
                priority,
                rationale,
                source=source,
                capture_id=capture_id,
                source_kind=source_kind,
            )
            applied["leads"] += 1
            continue

        if category == "FINDING" or marker_type == "finding":
            severity = _event_value(event, fields, "severity") or "INFO"
            title = _event_value(event, fields, "title", "description") or (raw[0] if raw else "")
            if not title:
                continue
            cvss = _event_value(event, fields, "cvss") or None
            writer.append_finding(
                severity,
                title,
                cvss=cvss,
                source=source,
                capture_id=capture_id,
                source_kind=source_kind,
            )
            applied["intel"] += 1
            continue

        if category == "SERVICE" or marker_type == "service":
            port = _event_value(event, fields, "port") or (raw[0] if len(raw) > 0 else "")
            state = _event_value(event, fields, "state") or (raw[1] if len(raw) > 3 else "") or "open"
            service = _event_value(event, fields, "service") or (
                raw[2] if len(raw) > 3 else (raw[1] if len(raw) > 1 else "")
            )
            version = _event_value(event, fields, "version") or (
                raw[3] if len(raw) > 3 else (raw[2] if len(raw) > 2 else "")
            )
            if not any((port, service, version)):
                continue
            writer.append_service(
                port,
                state,
                service,
                version,
                source=source,
                capture_id=capture_id,
                source_kind=source_kind,
            )
            applied["intel"] += 1
            continue

        if category == "ENDPOINT" or marker_type == "endpoint":
            path = _event_value(event, fields, "endpoint", "path") or (raw[0] if len(raw) > 0 else "")
            method = _event_value(event, fields, "method") or (raw[1] if len(raw) > 1 else "")
            function = _event_value(event, fields, "function") or (raw[2] if len(raw) > 2 else "")
            risk = _event_value(event, fields, "risk") or "Unknown"
            status = _event_value(event, fields, "status") or "Untested"
            if not any((path, method, function)):
                continue
            writer.append_endpoint(
                path,
                method,
                function,
                risk,
                status,
                source=source,
                capture_id=capture_id,
                source_kind=source_kind,
            )
            applied["intel"] += 1
            continue

        if category == "TARGET" or marker_type == "target":
            prop = _event_value(event, fields, "property") or (raw[0] if len(raw) > 0 else "")
            value = _event_value(event, fields, "value") or (raw[1] if len(raw) > 1 else "")
            if not any((prop, value)):
                continue
            writer.append_target(
                prop,
                value,
                source=source,
                capture_id=capture_id,
                source_kind=source_kind,
            )
            applied["intel"] += 1
            continue

        if category == "CREDENTIAL" or marker_type == "credential":
            credential = _event_value(event, fields, "credential") or (raw[0] if len(raw) > 0 else "")
            description = _event_value(event, fields, "description") or (raw[1] if len(raw) > 1 else "")
            detail = _event_value(event, fields, "detail") or (raw[2] if len(raw) > 2 else "")
            if not any((credential, description, detail)):
                continue
            writer.append_entry(
                "CREDENTIAL",
                [credential, description, detail],
                source=source,
                capture_id=capture_id,
                source_kind=source_kind,
            )
            applied["intel"] += 1
            continue

        if raw:
            writer.append_entry(
                category or "UNKNOWN",
                raw,
                source=source,
                capture_id=capture_id,
                source_kind=source_kind,
            )
            applied["intel"] += 1

    return applied
