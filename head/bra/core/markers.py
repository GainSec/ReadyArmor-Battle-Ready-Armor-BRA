"""Marker parsing for mechanical discovery capture.

Parses structured markers from agent text output:
- [FINDING] SEVERITY: description | key: value
- [SERVICE] port | service | version
- [ENDPOINT] path | method | function | key: value
- [TARGET] property: value
- [LEAD] description | key: value
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class MarkerType(Enum):
    """Types of markers that can be parsed."""
    FINDING = "finding"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    TARGET = "target"
    LEAD = "lead"


@dataclass
class ParsedMarker:
    """Result of parsing a marker line."""
    type: MarkerType
    raw_line: str
    fields: dict[str, str] = field(default_factory=dict)
    category: str = ""  # Raw category string (e.g., "SERVICE", "USB_DEVICE")
    raw_fields: list[str] = field(default_factory=list)  # Pipe-separated positional parts

    # Type-specific fields (set based on marker type)
    severity: Optional[str] = None  # FINDING
    description: Optional[str] = None  # FINDING, LEAD
    port: Optional[str] = None  # SERVICE
    service: Optional[str] = None  # SERVICE
    version: Optional[str] = None  # SERVICE
    path: Optional[str] = None  # ENDPOINT
    method: Optional[str] = None  # ENDPOINT
    function: Optional[str] = None  # ENDPOINT
    property: Optional[str] = None  # TARGET
    value: Optional[str] = None  # TARGET


# Regex patterns for marker detection — allow underscores and digits
MARKER_PATTERN = re.compile(r'^\[([A-Z][A-Z0-9_]*)\]\s*(.+)$')
SEVERITY_PATTERN = re.compile(r'^(CRITICAL|HIGH|MEDIUM|LOW|INFO):\s*(.+)$', re.IGNORECASE)


def _is_valid_cvss(value: str) -> bool:
    """Return True when value is a numeric CVSS score in [0.0, 10.0]."""
    text = str(value or "").strip()
    if not text:
        return False
    try:
        score = float(text)
    except ValueError:
        return False
    return 0.0 <= score <= 10.0


def _is_valid_capture_id(value: str) -> bool:
    """Return True when value looks like a real tool_use_id (toolu_...) or capture provenance ID."""
    text = str(value or "").strip()
    if not text:
        return False
    # Real tool_use_ids start with "toolu_" followed by alphanumeric chars
    if re.match(r'^toolu_[A-Za-z0-9]{10,}$', text):
        return True
    # Fallback capture IDs from post_hook.py: cap_<session>_<timestamp>
    if re.match(r'^cap_[A-Za-z0-9_]+$', text):
        return True
    # Anon-intercept capture IDs from bash-guard.py: anon_<timestamp>
    if re.match(r'^anon_[A-Za-z0-9_]+$', text):
        return True
    return False


def _parse_pipe_separated(content: str) -> tuple[list[str], dict[str, str]]:
    """Parse pipe-separated content into parts and key:value fields.

    Args:
        content: String like "value1 | value2 | key: value3"

    Returns:
        Tuple of (positional_parts, key_value_fields)
    """
    parts = [p.strip() for p in content.split('|')]
    positional = []
    fields = {}

    for part in parts:
        if ':' in part:
            # Check if it's a key:value pair (key should be single word)
            potential_key = part.split(':', 1)[0].strip()
            normalized_key = potential_key.lower().replace("-", "_")
            if ' ' not in potential_key and normalized_key in (
                'endpoint', 'cvss', 'risk', 'status', 'priority', 'state', 'source',
                'capture_id', 'source_kind', 'attack_surface'
            ):
                key, value = part.split(':', 1)
                fields[normalized_key] = value.strip()
            else:
                positional.append(part)
        else:
            positional.append(part)

    return positional, fields


def parse_marker(line: str) -> Optional[ParsedMarker]:
    """Parse a line for marker content.

    Args:
        line: Text line to parse

    Returns:
        ParsedMarker if line contains a valid marker, None otherwise
    """
    line = line.strip()

    # Try to match marker pattern
    match = MARKER_PATTERN.match(line)
    if not match:
        return None

    marker_type_str = match.group(1).upper()
    content = match.group(2).strip()

    # Enforce strict marker set: only LEAD/FINDING plus core intel markers.
    if marker_type_str == "SUGGESTION":
        return None

    # Map marker type.
    type_map = {
        'FINDING': MarkerType.FINDING,
        'SERVICE': MarkerType.SERVICE,
        'ENDPOINT': MarkerType.ENDPOINT,
        'TARGET': MarkerType.TARGET,
        'LEAD': MarkerType.LEAD,
    }

    if marker_type_str not in type_map:
        # Dynamic/unknown category — parse generically
        parts, fields = _parse_pipe_separated(content)
        return ParsedMarker(
            type=MarkerType.SERVICE,  # Placeholder type for dynamic categories
            raw_line=line,
            category=marker_type_str,
            raw_fields=parts,
            fields=fields,
        )

    marker_type = type_map[marker_type_str]

    # Parse based on type — each parser sets type-specific fields
    if marker_type == MarkerType.FINDING:
        result = _parse_finding(content, line)
        if result is None:
            return None
    elif marker_type == MarkerType.SERVICE:
        result = _parse_service(content, line)
    elif marker_type == MarkerType.ENDPOINT:
        result = _parse_endpoint(content, line)
    elif marker_type == MarkerType.TARGET:
        result = _parse_target(content, line)
    elif marker_type == MarkerType.LEAD:
        result = _parse_lead(content, line)
    else:
        return None

    # Set category and raw_fields on all known types too
    result.category = marker_type_str
    parts, _ = _parse_pipe_separated(content)
    result.raw_fields = parts

    return result


def _parse_finding(content: str, raw_line: str) -> Optional[ParsedMarker]:
    """Parse a FINDING marker.

    Required format:
      [FINDING] SEVERITY: title | cvss: <0.0-10.0> | attack_surface: <category> | ...
    """
    # Enforce explicit "SEVERITY: ..." prefix.
    sev_match = SEVERITY_PATTERN.match(content)
    if not sev_match:
        return None
    severity = sev_match.group(1).upper()
    rest = sev_match.group(2)
    parts, fields = _parse_pipe_separated(rest)
    description = parts[0] if parts else rest
    if not description:
        return None

    # Enforce required finding metadata at marker time.
    cvss_value = fields.get("cvss", "")
    if not _is_valid_cvss(cvss_value):
        return None

    attack_surface = str(fields.get("attack_surface", "")).strip()
    if not attack_surface:
        return None

    # capture_id is optional at parse time — the runner's _effective_provenance
    # will resolve it from the latest tool use if not provided in the marker.
    # If the agent writes a bogus capture_id (e.g. "FIND-001"), discard it
    # silently and let the runner resolve provenance automatically.
    capture_id = str(fields.get("capture_id", "")).strip()
    if capture_id and not _is_valid_capture_id(capture_id):
        fields.pop("capture_id", None)
        capture_id = ""

    return ParsedMarker(
        type=MarkerType.FINDING,
        raw_line=raw_line,
        severity=severity,
        description=description,
        fields=fields,
    )


def _parse_service(content: str, raw_line: str) -> ParsedMarker:
    """Parse a SERVICE marker."""
    parts, fields = _parse_pipe_separated(content)
    port = parts[0] if len(parts) > 0 else ""
    service = ""
    version = ""

    # Accept both:
    #   1) port | service | version
    #   2) port | state | service | version
    if len(parts) >= 4:
        state = parts[1]
        service = parts[2]
        version = parts[3]
        if state and "state" not in fields:
            fields["state"] = state
    else:
        service = parts[1] if len(parts) > 1 else ""
        version = parts[2] if len(parts) > 2 else ""

    return ParsedMarker(
        type=MarkerType.SERVICE,
        raw_line=raw_line,
        port=port,
        service=service,
        version=version,
        fields=fields,
    )


def _parse_endpoint(content: str, raw_line: str) -> ParsedMarker:
    """Parse an ENDPOINT marker."""
    parts, fields = _parse_pipe_separated(content)

    return ParsedMarker(
        type=MarkerType.ENDPOINT,
        raw_line=raw_line,
        path=parts[0] if len(parts) > 0 else "",
        method=parts[1] if len(parts) > 1 else "",
        function=parts[2] if len(parts) > 2 else "",
        fields=fields,
    )


def _parse_target(content: str, raw_line: str) -> ParsedMarker:
    """Parse a TARGET marker."""
    # Handle pipe-separated content (e.g., "Platform: Linux | source: path")
    parts, fields = _parse_pipe_separated(content)
    first = parts[0] if parts else content

    if ':' in first:
        prop, val = first.split(':', 1)
        return ParsedMarker(
            type=MarkerType.TARGET,
            raw_line=raw_line,
            property=prop.strip(),
            value=val.strip(),
            fields=fields,
        )
    else:
        return ParsedMarker(
            type=MarkerType.TARGET,
            raw_line=raw_line,
            property="Unknown",
            value=first,
            fields=fields,
        )


def _parse_lead(content: str, raw_line: str) -> ParsedMarker:
    """Parse a LEAD marker."""
    parts, fields = _parse_pipe_separated(content)
    description = parts[0] if parts else content

    return ParsedMarker(
        type=MarkerType.LEAD,
        raw_line=raw_line,
        description=description,
        fields=fields,
    )
