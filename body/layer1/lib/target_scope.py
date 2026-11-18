#!/usr/bin/env python3
"""Runtime target scope validation library.

Purpose: Validate discovered targets against approved scope
Invariant: No action against unapproved targets

Usage:
    from target_scope import (
        get_inscope_targets,          # Parse SCOPE.md for original targets
        is_target_approved,           # Check if target is in approved list
        get_target_scope_level,       # Returns: FULL, LIMITED, NONE, CUSTOM
        add_approved_target,          # Add to runtime list
        is_operation_allowed,         # Check if operation allowed for scope level
        extract_target_from_command,  # Extract IP/domain from command string
    )

Scope Levels:
    FULL    - All testing allowed (port scan, fuzz, exploit)
    LIMITED - Passive only (download, ping, DNS lookup)
    NONE    - Do not interact (document only)
    CUSTOM  - Only operations specified in allowed list

Files:
    - layer3-engagement/SCOPE.md     - Original scope definition
    - .bra/approved_targets.json     - Runtime approved targets

Referenced By:
    - layer1/hooks/bash-guard.py
    - layer1/scripts/approve-target.py
    - .claude/commands/agentic.md
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCOPE_FULL = "FULL"
SCOPE_LIMITED = "LIMITED"
SCOPE_NONE = "NONE"
SCOPE_CUSTOM = "CUSTOM"

_BLOCKED_FOR_LIMITED: tuple[str, ...] = (
    r"\bnmap\b",
    r"\bmasscan\b",
    r"\brustscan\b",
    r"\bffuf\b",
    r"\bwfuzz\b",
    r"\bgobuster\b",
    r"\bferoxbuster\b",
    r"\bdirsearch\b",
    r"\bsqlmap\b",
    r"\bmsfconsole\b",
    r"\bmetasploit\b",
    r"\bnuclei\b",
    r"\bnikto\b",
    r"\bhydra\b",
    r"\bmedusa\b",
    r"\bburp\b",
    r"curl.*-X\s*(POST|PUT|DELETE)",
    r"curl.*(-d|--data)\s",
)

_ALLOWED_FOR_LIMITED: tuple[str, ...] = (
    r"curl\s+-o",
    r"curl.*--output",
    r"curl\s+-O",
    r"wget\s",
    r"^ping6?\s",
    r"^dig\s",
    r"^nslookup\s",
    r"^host\s",
    r"^whois\s",
    r"curl\s+-G",
    r"curl.*--get",
    r"curl\s+https?://",
    r"openssl\s+s_client",
    r"sslscan\s",
    r"theHarvester",
    r"amass.*-passive",
    r"^(cat|head|tail|less|more|file|ls|echo)\b",
)

_ALLOWED_DOMAIN_TLDS: set[str] = {
    # Country-code TLDs
    "com", "net", "org", "io", "dev", "app", "co",
    "us", "uk", "ca", "au", "de", "fr", "jp", "cn", "kr", "ru", "br", "in",
    "mx", "za", "nz", "se", "no", "fi", "nl", "be", "at", "ch", "es", "it",
    "pt", "pl", "cz", "hu", "ro", "bg", "hr", "si", "sk", "lt", "lv", "ee",
    "ie", "dk", "is", "lu", "mt", "cy", "gr", "tr", "il", "ae", "sa", "qa",
    "kw", "bh", "om", "eg", "ng", "ke", "gh", "tz", "ug", "rw", "ma", "tn",
    "dz", "ly", "et",
    # Institutional TLDs
    "edu", "gov", "mil", "int",
    # Generic TLDs
    "info", "biz", "name", "pro", "tel", "mobi", "asia", "cat", "coop",
    "museum", "aero", "jobs", "travel",
    # New gTLDs (common subset)
    "xyz", "top", "site", "online", "store", "tech", "space", "fun", "icu",
    "club", "vip", "work", "ltd", "buzz", "guru", "ninja", "life", "live",
    "world", "today", "zone", "link", "click", "host", "press", "news",
    "blog", "cloud", "digital", "network", "systems", "solutions", "services",
    "agency", "group", "global", "team", "email", "center", "support", "media",
    "marketing", "design", "studio", "consulting", "management", "company",
    "enterprises", "ventures", "partners", "holdings", "capital", "finance",
    "exchange", "trading", "investments", "fund", "money", "cash", "pay",
    "bank", "credit", "insurance", "loans", "mortgage", "tax", "legal", "law",
    "healthcare", "health", "medical", "dental", "fitness", "yoga", "diet",
    "food", "restaurant", "cafe", "bar", "beer", "wine", "pizza", "recipes",
    "cooking", "kitchen", "garden", "flowers", "pet", "dog", "cat", "horse",
    "fish", "vet", "farm", "organic", "green", "eco", "solar", "energy",
    "power", "auto", "car", "cars", "moto", "bike", "taxi", "flights",
    "hotel", "resort", "vacation", "tours", "cruise", "camp", "ski", "surf",
    "game", "games", "play", "bet", "casino", "poker", "lotto", "dating",
    "love", "wedding", "baby", "kids", "toys", "gift", "gifts", "art",
    "gallery", "photo", "photos", "video", "music", "band", "dance",
    "theater", "movie", "film", "tv", "radio", "podcast", "book", "read",
    "library", "school", "university", "academy", "college", "institute",
    "training", "courses", "degree", "mba", "science", "engineering", "code",
    "software", "web", "website", "page", "forum", "chat", "social",
    "community", "wiki", "how", "tips", "guide", "review", "best", "new",
    "now", "express", "direct", "fast", "quick", "easy", "simple", "smart",
    "super", "ultra", "mega", "max", "pro", "plus", "prime", "elite",
    "premium", "gold", "platinum", "diamond", "star", "royal", "king",
    "queen", "prince", "boss", "master", "expert", "genius", "hero", "magic",
    "awesome", "cool", "hot", "big", "great", "grand", "noble", "luxury",
    "rich", "free", "discount", "cheap", "deal", "sale", "offer", "promo",
    "win", "success", "secure", "safe", "trust", "reliable", "quality",
    "perfect", "ideal", "dream", "happy", "lucky", "good", "nice", "fine",
    "fair", "pure", "real", "true", "one", "first", "alpha", "beta", "omega",
    "zero", "null",
    # Private/reserved TLDs relevant to pentesting
    "local", "lan", "internal", "intranet", "localdomain", "home", "corp",
    "private", "test", "example", "invalid", "localhost",
    # Darknet TLDs
    "onion", "i2p",
}

_PACKAGE_HOSTS: set[str] = {
    "github.com",
    "gitlab.com",
    "pypi.org",
    "npmjs.com",
    "rubygems.org",
    "crates.io",
    "brew.sh",
}

_PACKAGE_HOST_PREFIXES: tuple[str, ...] = (
    "apt.",
)


def _detect_body_root() -> Path:
    script = Path(__file__).resolve()
    for parent in script.parents:
        if parent.name == "body":
            return parent
    cwd = Path.cwd().resolve()
    for parent in (cwd, *cwd.parents):
        if parent.name == "body":
            return parent
    return cwd


def _scope_md_file(body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    return root / "layer3-engagement" / "SCOPE.md"


def target_scope_file_path(body_root: Path | None = None) -> Path:
    """Return approved-target JSON path."""
    root = _detect_body_root() if body_root is None else body_root
    return root / ".bra" / "approved_targets.json"


def _init_targets_file(body_root: Path | None = None) -> Path:
    """Ensure approved-target JSON exists and return path."""
    path = target_scope_file_path(body_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.is_file():
        payload = {"original": [], "discovered": []}
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _load_targets(body_root: Path | None = None) -> dict[str, Any]:
    path = _init_targets_file(body_root)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {"original": [], "discovered": []}
    if not isinstance(payload, dict):
        payload = {"original": [], "discovered": []}
    payload.setdefault("original", [])
    payload.setdefault("discovered", [])
    if not isinstance(payload["original"], list):
        payload["original"] = []
    if not isinstance(payload["discovered"], list):
        payload["discovered"] = []
    return payload


def _save_targets(payload: dict[str, Any], body_root: Path | None = None) -> None:
    path = _init_targets_file(body_root)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _is_blocked_for_limited(command: str) -> bool:
    """Return ``True`` when command is too active for LIMITED scope."""
    return any(re.search(pattern, command, re.IGNORECASE) for pattern in _BLOCKED_FOR_LIMITED)


def _is_allowed_for_limited(command: str) -> bool:
    """Return ``True`` when command is acceptable for LIMITED scope."""
    return any(re.search(pattern, command, re.IGNORECASE) for pattern in _ALLOWED_FOR_LIMITED)


def classify_target_type(target: str) -> str:
    """Classify target as ``network`` or ``local``."""
    if not target:
        return "network"

    if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$", target):
        return "network"
    if ":" in target and re.match(r"^[0-9a-fA-F:]+$", target):
        return "network"
    if target.startswith(("http://", "https://")):
        return "network"
    if re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", target) or target.startswith(("BT-", "BT_")):
        return "local"
    if target.startswith(("/", "./")):
        return "local"
    if target.startswith(("/dev/", "usb:")):
        return "local"
    if "." in target:
        return "network"
    return "network"


def _normalize_candidate(host: str) -> str:
    return host.strip().lower().rstrip(".,;:")


def _is_likely_domain(host: str) -> bool:
    if "." not in host:
        return False
    tld = host.rsplit(".", 1)[-1].lower()
    return tld in _ALLOWED_DOMAIN_TLDS


def _is_package_host(host: str) -> bool:
    """Return True if host is a known package registry / non-target."""
    if host in _PACKAGE_HOSTS:
        return True
    return any(host.startswith(prefix) for prefix in _PACKAGE_HOST_PREFIXES)


def extract_target_from_command(command: str) -> str | None:
    """Extract likely target host/IP/CIDR from a command line."""
    if not command.strip():
        return None

    cidr_match = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}", command)
    if cidr_match:
        return cidr_match.group(0)

    for ip_match in re.finditer(r"([0-9]{1,3}\.){3}[0-9]{1,3}", command):
        candidate = ip_match.group(0)
        if candidate not in {"127.0.0.1", "0.0.0.0"} and not candidate.startswith("127.0.0."):
            return candidate

    url_match = re.search(r"https?://([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)", command)
    if url_match:
        host = _normalize_candidate(url_match.group(1))
        if not _is_package_host(host):
            return host

    for token in command.split():
        candidate = _normalize_candidate(token)
        if _is_package_host(candidate):
            continue
        if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$", candidate) and _is_likely_domain(candidate):
            return candidate

    return None


def _target_in_file(target: str, file_path: str | Path) -> bool:
    """Boundary-aware check for target literal presence in text file."""
    path = Path(file_path)
    if not target or not path.is_file():
        return False

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False

    escaped = re.escape(target)
    pattern = rf"(^|[^a-zA-Z0-9._/-]){escaped}([^a-zA-Z0-9._/-]|$)"
    return re.search(pattern, text) is not None


def _ip_to_int(ip: str) -> int:
    """Convert IPv4 literal to integer value."""
    return int(ipaddress.IPv4Address(ip))


def _ip_in_cidr(ip_or_cidr: str, cidr: str) -> bool:
    """Return whether IP/CIDR belongs to CIDR network."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if "/" in ip_or_cidr:
            return ipaddress.ip_network(ip_or_cidr, strict=False).subnet_of(network)
        return ipaddress.ip_address(ip_or_cidr) in network
    except ValueError:
        return False


def get_inscope_targets(body_root: Path | None = None) -> list[str]:
    """Return scope targets as `target|level` lines."""
    root = _detect_body_root() if body_root is None else body_root
    output: list[str] = []

    scope_md = _scope_md_file(root)
    if scope_md.is_file():
        text = scope_md.read_text(encoding="utf-8", errors="ignore")
        for cidr in re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}", text):
            output.append(f"{cidr}|FULL")
        for ip in re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", text):
            output.append(f"{ip}|FULL")
        for host in re.findall(r"https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)", text):
            output.append(f"{host}|FULL")

    targets = _load_targets(root)
    output.extend(f"{target}|FULL" for target in targets.get("original", []) if isinstance(target, str))
    for entry in targets.get("discovered", []):
        if isinstance(entry, dict) and isinstance(entry.get("target"), str):
            output.append(f"{entry['target']}|{str(entry.get('level', 'FULL')).upper()}")

    return sorted(dict.fromkeys(output))


def _scope_text(body_root: Path | None = None) -> str:
    scope = _scope_md_file(body_root)
    if not scope.is_file():
        return ""
    return scope.read_text(encoding="utf-8", errors="ignore")


def is_target_approved(target: str, body_root: Path | None = None) -> bool:
    """Return whether target is currently in approved/original/discovered scope."""
    if not target:
        return False

    root = _detect_body_root() if body_root is None else body_root
    payload = _load_targets(root)

    if target in payload.get("original", []):
        return True

    for entry in payload.get("discovered", []):
        if isinstance(entry, dict) and str(entry.get("target", "")) == target:
            return True

    text = _scope_text(root)
    if text and _target_in_file(target, _scope_md_file(root)):
        return True

    cidrs = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}", text)
    if any(_ip_in_cidr(target, cidr) for cidr in cidrs):
        return True

    for entry in payload.get("discovered", []):
        if isinstance(entry, dict):
            discovered_target = str(entry.get("target", ""))
            if "/" in discovered_target and _ip_in_cidr(target, discovered_target):
                return True

    return False


def get_target_scope_level(target: str, body_root: Path | None = None) -> str:
    """Return scope level (`FULL`/`LIMITED`/`NONE`/`CUSTOM`) for approved target."""
    if not target:
        return ""

    root = _detect_body_root() if body_root is None else body_root
    payload = _load_targets(root)

    if target in payload.get("original", []):
        return SCOPE_FULL

    if _target_in_file(target, _scope_md_file(root)):
        return SCOPE_FULL

    scope_text = _scope_text(root)
    for cidr in re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}", scope_text):
        if _ip_in_cidr(target, cidr):
            return SCOPE_FULL

    for entry in payload.get("discovered", []):
        if not isinstance(entry, dict):
            continue
        discovered_target = str(entry.get("target", ""))
        level = str(entry.get("level", SCOPE_FULL)).upper()
        if discovered_target == target:
            return level
        if "/" in discovered_target and _ip_in_cidr(target, discovered_target):
            return level

    return ""


def add_approved_target(
    target: str,
    level: str = SCOPE_FULL,
    source: str = "runtime",
    allowed: list[str] | None = None,
    body_root: Path | None = None,
) -> dict[str, Any]:
    """Add/merge discovered target entry and return resulting record."""
    if not target:
        raise ValueError("target is required")

    root = _detect_body_root() if body_root is None else body_root
    payload = _load_targets(root)
    discovered = payload.setdefault("discovered", [])

    normalized_level = level.upper() if level else SCOPE_FULL
    if normalized_level not in {SCOPE_FULL, SCOPE_LIMITED, SCOPE_NONE, SCOPE_CUSTOM}:
        raise ValueError(f"invalid scope level: {level}")
    allowed_list = allowed or []
    approved_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for entry in discovered:
        if isinstance(entry, dict) and str(entry.get("target", "")) == target:
            entry["level"] = normalized_level
            entry["source"] = source
            entry["allowed"] = allowed_list
            entry["approved_at"] = approved_at
            _save_targets(payload, root)
            return entry

    entry = {
        "target": target,
        "level": normalized_level,
        "source": source,
        "allowed": allowed_list,
        "approved_at": approved_at,
    }
    discovered.append(entry)
    _save_targets(payload, root)
    return entry


def is_operation_allowed(command: str, level: str, allowed: list[str] | None = None) -> bool:
    """Return whether command is allowed under given scope level."""
    normalized = level.upper()
    if normalized == SCOPE_FULL:
        return True
    if normalized == SCOPE_NONE:
        return False
    if normalized == SCOPE_LIMITED:
        if _is_blocked_for_limited(command):
            return False
        return _is_allowed_for_limited(command)
    if normalized == SCOPE_CUSTOM:
        return True
    return False


def generate_scope_prompt(
    target: str,
    source: str = "",
    context: str = "",
    *,
    command: str = "",
) -> str:
    """Return prompt text for unapproved target escalation.

    Accepts both the V15 positional signature ``(target, source, context)``
    and the V17 keyword ``command`` parameter.  When *command* is provided
    but *context* is not, *command* is mapped to the context field so
    callers that only pass ``command=`` still get a meaningful prompt.
    """
    if not source:
        source = "Unknown source"
    if not context:
        context = command if command else "External reference"

    bar = "\u2550" * 63          # ═
    thin = "\u2500" * 63         # ─

    lines = [
        "",
        bar,
        "                    SCOPE CHECK REQUIRED",
        bar,
        "",
        f"Discovered: {target}",
        f"Source: {source}",
        f"Context: {context}",
        "",
        f"Is {target} in scope?",
        "",
        "A. Fully in Scope \u2014 all testing allowed",
        "B. Limited Scope \u2014 passive only (download referenced files, ping, DNS)",
        "C. Not in Scope \u2014 do not interact",
        "D. Custom \u2014 specify what's allowed",
        "",
        thin,
    ]
    return "\n".join(lines) + "\n"


def target_reset_cache() -> None:
    """Compatibility no-op for API parity."""


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        help_text = [
            "target_scope.py — Runtime target scope validation",
            "",
            "Usage:",
            "  target_scope.py --extract <cmd...>        Extract IP/domain from command",
            "  target_scope.py --approved <target>       Check if target is approved (exit 0/1)",
            "  target_scope.py --level <target>          Print scope level for target",
            "  target_scope.py --add <target> [<level>]  Add target to discovered list",
            "",
            "Scope Levels:",
            "  FULL    — All testing allowed (port scan, fuzz, exploit)",
            "  LIMITED — Passive only (download, ping, DNS lookup)",
            "  NONE    — Do not interact (document only)",
            "  CUSTOM  — Only operations specified in allowed list",
        ]
        print("\n".join(help_text))
        return 0

    if args[0] == "--extract":
        target = extract_target_from_command(" ".join(args[1:]))
        if target:
            print(target)
            return 0
        return 1

    if args[0] == "--approved" and len(args) >= 2:
        return 0 if is_target_approved(args[1]) else 1

    if args[0] == "--level" and len(args) >= 2:
        print(get_target_scope_level(args[1]))
        return 0

    if args[0] == "--add" and len(args) >= 2:
        level = args[2] if len(args) >= 3 else SCOPE_FULL
        print(json.dumps(add_approved_target(args[1], level=level), indent=2))
        return 0

    print("Invalid arguments", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
