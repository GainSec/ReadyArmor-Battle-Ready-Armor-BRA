"""Scriptable FINDINGS materialization from marker events."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from bra.core.capture_provenance import extract_capture_candidates, find_recent_capture, resolve_capture, resolve_capture_hint
from bra.core.finding_enforcer import FindingEnforcer


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
    for name in (key,) + aliases:
        direct = _safe_text(event.get(name))
        if direct:
            return direct
        lowered = name.lower()
        if lowered in fields and fields[lowered]:
            return fields[lowered]
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
) -> str:
    capture_id = _event_value(event, fields, "capture_id")
    if capture_id == "provided_info":
        capture_id = ""
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
            return ""
    return ""


def _normalize_finding_id(raw_id: str, enforcer: FindingEnforcer) -> str:
    text = _safe_text(raw_id)
    if not text:
        return f"{enforcer.next_finding_id():03d}"

    if text.upper().startswith("FINDING-"):
        text = text.split("-", 1)[1]
    match = re.search(r"\d+", text)
    if not match:
        return f"{enforcer.next_finding_id():03d}"
    return f"{int(match.group(0)):03d}"


def _build_finding_marker(
    *,
    severity: str,
    title: str,
    source: str,
    capture_id: str,
    source_kind: str,
    cvss: str,
    cwe: str,
    attack_surface: str,
    status: str,
) -> str:
    marker = f"[FINDING] {severity}: {title}"
    if source:
        marker += f" | source: {source}"
    if capture_id:
        marker += f" | capture_id: {capture_id}"
    if source_kind:
        marker += f" | source_kind: {source_kind}"
    if cvss:
        marker += f" | cvss: {cvss}"
    if cwe:
        marker += f" | cwe: {cwe}"
    if attack_surface:
        marker += f" | attack_surface: {attack_surface}"
    if status:
        marker += f" | status: {status}"
    return marker


def materialize_findings_from_events(notes_dir: Path, bra_state_dir: Path) -> dict[str, int]:
    """Replay finding marker events into FINDINGS scaffolds + system-managed sections."""
    enforcer = FindingEnforcer(Path(notes_dir), Path(bra_state_dir))
    applied = {"findings": 0}

    for event in _iter_events(_events_path(Path(bra_state_dir))):
        category = _safe_text(event.get("category")).upper()
        marker_type = _safe_text(event.get("marker_type")).lower()
        if category != "FINDING" and marker_type != "finding":
            continue

        fields = _event_fields(event)
        raw = _event_raw_fields(event)
        severity = _event_value(event, fields, "severity") or (raw[0].upper() if raw else "") or "INFO"
        title = _event_value(event, fields, "title", "description")
        if not title:
            title = raw[1] if len(raw) > 1 else (raw[0] if raw else "")
        if not title:
            continue

        source = _event_value(event, fields, "source", "artifact_path")
        capture_id = _resolve_capture_id(
            event=event,
            fields=fields,
            raw=raw,
            source=source,
            bra_state_dir=Path(bra_state_dir),
        )
        source_kind = _event_value(event, fields, "source_kind") or "tool_capture"
        if source_kind == "provided_info":
            source_kind = "tool_capture"
        cvss = _event_value(event, fields, "cvss")
        cwe = _event_value(event, fields, "cwe")
        attack_surface = _event_value(event, fields, "attack_surface")
        status = _event_value(event, fields, "status")
        finding_id = _normalize_finding_id(
            _event_value(event, fields, "finding_id", "id"),
            enforcer,
        )
        marker_line = _build_finding_marker(
            severity=severity,
            title=title,
            source=source,
            capture_id=capture_id,
            source_kind=source_kind,
            cvss=cvss,
            cwe=cwe,
            attack_surface=attack_surface,
            status=status,
        )
        enforcer.materialize_finding_from_marker(
            finding_id=finding_id,
            severity=severity,
            title=title,
            source_marker=marker_line,
        )
        applied["findings"] += 1

    return applied
