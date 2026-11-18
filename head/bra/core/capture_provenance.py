"""Canonical capture provenance index utilities."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


INDEX_FIELDS = (
    "capture_id",
    "session_id",
    "tool_use_id",
    "tool_name",
    "action",
    "target",
    "artifact_path",
    "artifact_sha256",
    "source_kind",
    "created_at",
)


def _index_path(bra_state_dir: Path) -> Path:
    return Path(bra_state_dir) / "logs" / "evidence_index.jsonl"


def _iter_records(bra_state_dir: Path) -> list[dict[str, Any]]:
    index_path = _index_path(Path(bra_state_dir))
    if not index_path.exists():
        return []

    rows: list[dict[str, Any]] = []
    for line in index_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def extract_capture_candidates(text: str) -> list[str]:
    value = str(text or "").strip()
    if not value:
        return []

    candidates: list[str] = []
    explicit = re.findall(
        r"capture_id:\s*((?:anon_\d{8}_\d{6}_\d+)|(?:toolu_[A-Za-z0-9]+)|(?:cap_[A-Za-z0-9._-]+))",
        value,
        re.IGNORECASE,
    )
    for candidate in explicit:
        normalized = str(candidate).strip()
        if normalized and normalized not in candidates:
            candidates.append(normalized)

    tokens = re.findall(
        r"(?<![A-Za-z0-9])((?:anon_\d{8}_\d{6}_\d+)|(?:toolu_[A-Za-z0-9]+)|(?:cap_[A-Za-z0-9._-]+))(?![A-Za-z0-9])",
        value,
        re.IGNORECASE,
    )
    for candidate in tokens:
        normalized = str(candidate).strip()
        if normalized and normalized not in candidates:
            candidates.append(normalized)
    return candidates


def resolve_capture_hint(bra_state_dir: Path, hint_text: str) -> str:
    """Resolve a capture ID from explicit tokens or artifact-path hints."""
    hint = str(hint_text or "").strip()
    if not hint:
        return ""

    for candidate in extract_capture_candidates(hint):
        if resolve_capture(candidate, bra_state_dir):
            return candidate

    artifact_hints = re.findall(r"((?:\.bra|/)[^\s|]+)", hint)
    basenames = {Path(raw).name.lower() for raw in artifact_hints if str(raw).strip()}
    suffixes = {str(raw).strip().lower() for raw in artifact_hints if str(raw).strip()}

    best_id = ""
    best_score = 0
    for row in _iter_records(Path(bra_state_dir)):
        capture_id = str(row.get("capture_id", "")).strip()
        if not capture_id:
            continue
        artifact_path = str(row.get("artifact_path", "") or "").strip()
        artifact_lower = artifact_path.lower()
        artifact_name = Path(artifact_path).name.lower() if artifact_path else ""

        score = 0
        if artifact_lower and any(artifact_lower.endswith(suffix) for suffix in suffixes):
            score = max(score, 100)
        if artifact_name and artifact_name in basenames:
            score = max(score, 90)
        if not score:
            continue
        if score >= best_score:
            best_score = score
            best_id = capture_id

    if best_id:
        return best_id

    return find_recent_capture(Path(bra_state_dir), hint)


def append_record(bra_state_dir: Path, record: dict[str, Any]) -> None:
    """Append one capture provenance record to the canonical index."""
    if not isinstance(record, dict):
        raise TypeError("record must be a dict")

    index_path = _index_path(Path(bra_state_dir))
    index_path.parent.mkdir(parents=True, exist_ok=True)

    missing = [field for field in INDEX_FIELDS if field not in record]
    if missing:
        raise ValueError(f"record missing required fields: {', '.join(missing)}")

    with index_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")


def find_recent_capture(bra_state_dir: Path, hint_text: str) -> str:
    """Find the most recent capture_id whose target/url/command matches keywords in hint_text.

    Scans the evidence index for records whose target, url, host, or command
    fields share tokens with the hint text.  Returns the capture_id of the
    best (most recent) match, or "" if nothing matches.
    """
    index_path = _index_path(Path(bra_state_dir))
    if not index_path.exists() or not hint_text:
        return ""

    # Extract meaningful tokens from the hint (IPs, hostnames, ports, tool names, paths)
    tokens = set(re.findall(r'[\w./-]{3,}', hint_text.lower()))
    if not tokens:
        return ""

    best_id = ""
    best_score = 0
    for row in _iter_records(Path(bra_state_dir)):
        # Build searchable text from the record
        searchable = " ".join(
            str(row.get(k, "")).lower()
            for k in ("target", "url", "host", "command", "endpoint", "artifact_path")
        )
        score = sum(1 for t in tokens if t in searchable)
        # Prefer higher score, and among equal scores prefer more recent (last wins)
        if score > 0 and score >= best_score:
            best_score = score
            best_id = str(row.get("capture_id", ""))
    return best_id


def resolve_capture(capture_id: str, bra_state_dir: Path) -> dict[str, Any] | None:
    """Resolve the latest capture provenance record for a capture id."""
    index_path = _index_path(Path(bra_state_dir))
    if not index_path.exists() or not capture_id:
        return None

    resolved: dict[str, Any] | None = None
    for row in _iter_records(Path(bra_state_dir)):
        if isinstance(row, dict) and row.get("capture_id", "").lower() == capture_id.lower():
            resolved = row
    return resolved
