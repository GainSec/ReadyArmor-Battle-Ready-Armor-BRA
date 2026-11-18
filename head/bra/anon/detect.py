"""Regex-based detection of identifiable data in text.

Detects: IPv4, CIDRs, MACs, long hex strings (API keys),
password-like values near password keywords.

Does NOT flag: version strings, short hex (CSS colors), CWEs, CVEs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Detection:
    """A detected piece of identifiable data."""
    value: str
    type_: str  # ip, cidr, mac, credential, operator-flagged
    span: tuple[int, int]
    confidence: str = "high"  # high (regex), low (ner-only)
    source: str = "regex"     # regex, ner, both


# IPv4 address. Allow sentence-final punctuation while avoiding embedded dotted tokens.
_IPV4 = re.compile(
    r"(?<![\w.])"
    r"((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?:/\d{1,2})?"  # optional CIDR
    r"(?=$|[^\w.]|(?:\.(?:\s|$)))"
)

# MAC address (colon or dash separated)
_MAC = re.compile(
    r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}"
)

# Long hex string (>= 16 chars, likely an API key/hash)
_HEX_LONG = re.compile(
    r"(?<![0-9A-Fa-f])[0-9a-fA-F]{16,}(?![0-9A-Fa-f])"
)

# Password-like value near a password keyword
_PASSWORD = re.compile(
    r"(?:password|passwd|pass|pwd)\s*(?:is|=|:)\s*(\S+?)(?=[.,;:!?\s]|$)",
    re.IGNORECASE,
)


def detect_regex(text: str) -> list[Detection]:
    """Scan text for identifiable data using regex patterns.
    Returns deduplicated list of detections.
    """
    seen: set[str] = set()
    results: list[Detection] = []

    def _add(value: str, type_: str, span: tuple[int, int]) -> None:
        if value not in seen:
            seen.add(value)
            results.append(Detection(value=value, type_=type_, span=span))

    # IPs and CIDRs
    for m in _IPV4.finditer(text):
        val = m.group(0)
        type_ = "cidr" if "/" in val else "ip"
        _add(val, type_, m.span())

    # MACs
    for m in _MAC.finditer(text):
        _add(m.group(0), "mac", m.span())

    # Long hex (skip if already matched as IP)
    for m in _HEX_LONG.finditer(text):
        val = m.group(0)
        if val not in seen:
            _add(val, "credential", m.span())

    # Passwords
    for m in _PASSWORD.finditer(text):
        val = m.group(1)
        if val not in seen:
            _add(val, "credential", m.span())

    return results
