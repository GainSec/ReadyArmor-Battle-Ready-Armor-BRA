#!/usr/bin/env python3
"""Read-only helpers for `.bra/overrides.json` rules."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


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


def _overrides_file(body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    return root / ".bra" / "overrides.json"


def _load_payload(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def list_overrides(body_root: Path | None = None) -> list[dict[str, Any]]:
    """Return all override rules; missing/invalid files return an empty list."""
    path = _overrides_file(body_root)
    payload = _load_payload(path)
    if not payload:
        return []
    rules = payload.get("rules", [])
    return [rule for rule in rules if isinstance(rule, dict)] if isinstance(rules, list) else []


def has_override(rule_id: str, body_root: Path | None = None) -> bool:
    """Return ``True`` when a rule with ``rule_id`` exists."""
    if not rule_id:
        return False
    return any(str(rule.get("id", "")) == rule_id for rule in list_overrides(body_root))


def override_count(body_root: Path | None = None) -> int:
    """Return number of override rules."""
    return len(list_overrides(body_root))


def validate_overrides_json(body_root: Path | None = None) -> tuple[bool, str]:
    """Validate overrides file shape and return ``(is_valid, message)``."""
    path = _overrides_file(body_root)
    if not path.is_file():
        return False, "overrides.json not found"

    payload = _load_payload(path)
    if payload is None:
        return False, "overrides.json invalid JSON"

    if "rules" not in payload:
        return False, "overrides.json invalid: missing 'rules' key"

    if not isinstance(payload["rules"], list):
        return False, "overrides.json invalid: 'rules' is not an array"

    return True, "overrides.json valid"


def _show_help() -> None:
    print(
        "overrides.py\n\n"
        "Usage:\n"
        "  overrides.py --list\n"
        "  overrides.py --count\n"
        "  overrides.py --has <rule-id>\n"
        "  overrides.py --validate\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        _show_help()
        return 0

    if args[0] == "--list":
        print(json.dumps(list_overrides(), indent=2))
        return 0

    if args[0] == "--count":
        print(override_count())
        return 0

    if args[0] == "--has" and len(args) >= 2:
        return 0 if has_override(args[1]) else 1

    if args[0] == "--validate":
        valid, message = validate_overrides_json()
        print(message)
        return 0 if valid else 1

    print("Invalid arguments", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
