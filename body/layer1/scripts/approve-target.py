#!/usr/bin/env python3
"""approve-target.py - Native Python port of approve-target.sh."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
APPROVED_TARGETS_PATH = PROJECT_ROOT / ".bra" / "approved_targets.json"
APPROVAL_TOKEN_DIR = PROJECT_ROOT / ".bra" / "one-time-approvals"
SCOPE_MD_PATH = PROJECT_ROOT / "layer3-engagement" / "SCOPE.md"
TARGET_SCOPE_LOG_PATH = PROJECT_ROOT / ".bra" / "logs" / "target-scope.log"

VALID_LEVELS = {"FULL", "LIMITED", "NONE", "CUSTOM"}


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_scope_log(message: str) -> None:
    try:
        TARGET_SCOPE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with TARGET_SCOPE_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"[{_utc_timestamp()}] {message}\n")
    except OSError:
        pass


def _sanitize_target(target: str) -> str:
    return re.sub(r"[/:.]+", "-", target).strip("-")


def _target_boundary_pattern(target: str) -> re.Pattern[str]:
    escaped = re.escape(target)
    return re.compile(rf"(^|[^a-zA-Z0-9._/-]){escaped}([^a-zA-Z0-9._/-]|$)", re.MULTILINE)


def _target_in_text(target: str, text: str) -> bool:
    return _target_boundary_pattern(target).search(text) is not None


def _consume_scope_grant_token(target: str) -> bool:
    sanitized = _sanitize_target(target)
    token_file = APPROVAL_TOKEN_DIR / f"SCOPE-GRANT-{sanitized}"
    if token_file.is_file():
        try:
            token_file.unlink()
        except OSError:
            return False
        _append_scope_log(f"TOKEN CONSUMED: SCOPE-GRANT-{sanitized}")
        return True

    print("ERROR: approve-target.py requires an approval grant token.", file=sys.stderr)
    print(
        f"No SCOPE-GRANT token found for '{target}' (expected: SCOPE-GRANT-{sanitized}).",
        file=sys.stderr,
    )
    print("Use the scope approval modal to approve targets.", file=sys.stderr)
    return False


def _default_payload() -> dict[str, Any]:
    return {"original": [], "discovered": []}


def _load_payload() -> dict[str, Any]:
    if not APPROVED_TARGETS_PATH.is_file():
        return _default_payload()

    try:
        payload = json.loads(APPROVED_TARGETS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _default_payload()

    if not isinstance(payload, dict):
        return _default_payload()

    original = payload.get("original")
    discovered = payload.get("discovered")
    if not isinstance(original, list):
        original = []
    if not isinstance(discovered, list):
        discovered = []
    return {"original": original, "discovered": discovered}


def _write_payload(payload: dict[str, Any]) -> None:
    APPROVED_TARGETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = APPROVED_TARGETS_PATH.with_suffix(".json.tmp")
    temp_path.write_text(f"{json.dumps(payload, indent=2, sort_keys=False)}\n", encoding="utf-8")
    temp_path.replace(APPROVED_TARGETS_PATH)


def _classify_target_type(target: str) -> str:
    if not target:
        return "network"
    if re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", target):
        return "local"
    if re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?", target):
        return "network"
    if ":" in target and re.fullmatch(r"[0-9a-fA-F:]+", target):
        return "network"
    if target.startswith(("http://", "https://")):
        return "network"
    if target.startswith(("BT-", "BT_")):
        return "local"
    if target.startswith(("/", "./")):
        return "local"
    if target.startswith("usb:"):
        return "local"
    if "." in target:
        return "network"
    return "network"


def _list_scope_targets() -> list[str]:
    if not SCOPE_MD_PATH.is_file():
        return []

    targets: list[str] = []
    try:
        for line in SCOPE_MD_PATH.read_text(encoding="utf-8").splitlines():
            match = re.search(r"\*\*([^*]+)\*\*", line)
            if match:
                targets.append(match.group(1).strip())
    except OSError:
        return []
    return targets


def _is_target_in_scope_md(target: str) -> bool:
    if not SCOPE_MD_PATH.is_file():
        return False
    try:
        content = SCOPE_MD_PATH.read_text(encoding="utf-8")
    except OSError:
        return False
    return _target_in_text(target, content)


def _sync_target_to_scope(target: str, level: str, source: str, target_type: str = "") -> None:
    if not SCOPE_MD_PATH.is_file():
        _append_scope_log("SYNC SKIP: SCOPE.md not found")
        return
    if level == "NONE":
        _append_scope_log(f"SYNC SKIP: {target} is NONE (document-only)")
        return

    try:
        content = SCOPE_MD_PATH.read_text(encoding="utf-8")
    except OSError:
        return

    if _target_in_text(target, content):
        _append_scope_log(f"SYNC SKIP: {target} already in SCOPE.md")
        return

    normalized_type = (target_type or "").strip().lower() or _classify_target_type(target)
    section_header = "### Local Targets" if normalized_type == "local" else "### Network Targets"
    if level == "FULL":
        bullet = f"- **{target}** *(runtime approved: {source})*"
    else:
        bullet = f"- **{target}** [{level}] *(runtime approved: {source})*"

    lines = content.splitlines()
    section_index = next((idx for idx, line in enumerate(lines) if line.startswith(section_header)), None)

    if section_index is None:
        if lines and lines[-1] != "":
            lines.append("")
        lines.extend([section_header, "", bullet])
    else:
        insert_at = len(lines)
        for idx in range(section_index + 1, len(lines)):
            if lines[idx].startswith("###") or lines[idx].startswith("---"):
                insert_at = idx
                break
        lines.insert(insert_at, bullet)

    updated_content = "\n".join(lines)
    if not updated_content.endswith("\n"):
        updated_content += "\n"

    SCOPE_MD_PATH.write_text(updated_content, encoding="utf-8")
    _append_scope_log(f"SYNC: {target} -> SCOPE.md ({section_header})")


def _usage() -> None:
    print(
        "\n".join(
            [
                "approve-target.py - Add discovered target to approved scope",
                "",
                "USAGE:",
                "  ./layer1/scripts/approve-target.py <target> <level> [source]",
                "  ./layer1/scripts/approve-target.py --list",
                "  ./layer1/scripts/approve-target.py --remove <target>",
                "  ./layer1/scripts/approve-target.py --check <target>",
                "",
                "ARGUMENTS:",
                "  target    IP address, CIDR, or domain to approve",
                "  level     FULL, LIMITED, NONE, or CUSTOM",
                "  source    How/where the target was discovered (optional)",
                "",
                "LEVELS:",
                "  FULL      All testing allowed (port scan, fuzz, exploit)",
                "  LIMITED   Passive only (download files, ping, DNS lookup)",
                "  NONE      Document only - no interaction allowed",
                '  CUSTOM    Comma-separated allowed operations (e.g., "ping,dns")',
                "",
                "OPTIONS:",
                "  --list    Show all approved targets",
                "  --remove  Remove a target from approved list",
                "  --check   Check if a target is approved and its level",
                "  --help    Show this help message",
                "",
                "EXAMPLES:",
                '  ./layer1/scripts/approve-target.py api.example.com FULL "Found in /js/app.js"',
                '  ./layer1/scripts/approve-target.py 192.168.1.50 LIMITED "Backend server"',
                '  ./layer1/scripts/approve-target.py cdn.example.com NONE "Third-party CDN"',
                '  ./layer1/scripts/approve-target.py custom.com CUSTOM "curl,wget,dig"',
                "  ./layer1/scripts/approve-target.py --check api.example.com",
                "  ./layer1/scripts/approve-target.py --list",
            ]
        )
    )


def cmd_list() -> int:
    payload = _load_payload()
    print("═══════════════════════════════════════════════════════════════")
    print("                    APPROVED TARGETS")
    print("═══════════════════════════════════════════════════════════════")
    print("")

    if not APPROVED_TARGETS_PATH.is_file():
        print("No approved targets file found.")
        print("Original targets from SCOPE.md:")
        for target in _list_scope_targets():
            print(f"  - {target} (FULL - original scope)")
        return 0

    print("ORIGINAL (from SCOPE.md):")
    originals = [item for item in payload.get("original", []) if isinstance(item, str) and item]
    if originals:
        for target in originals:
            print(f"  - {target} (FULL)")
    else:
        print("  (none specified in JSON - check SCOPE.md)")

    print("")
    print("DISCOVERED (runtime approved):")
    discovered_items = payload.get("discovered", [])
    printed = False
    for item in discovered_items:
        if not isinstance(item, dict):
            continue
        target = str(item.get("target", "")).strip()
        level = str(item.get("level", "")).strip() or "FULL"
        source = str(item.get("source", "")).strip() or "Unknown"
        if target:
            print(f"  - {target} ({level}) — {source}")
            printed = True
    if not printed:
        print("  (none)")

    print("")
    print("───────────────────────────────────────────────────────────────")
    return 0


def cmd_check(target: str) -> int:
    approved = False
    level = ""
    lib_dir = str(Path(__file__).resolve().parents[1] / "lib")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)
    try:
        import target_scope

        approved = target_scope.is_target_approved(target, body_root=PROJECT_ROOT)
        if approved:
            level = target_scope.get_target_scope_level(target, body_root=PROJECT_ROOT) or "FULL"
    except (ImportError, Exception):
        if _is_target_in_scope_md(target):
            approved = True
            level = "FULL"

    print(f"TARGET: {target}")
    if approved:
        print("STATUS: Approved")
        print(f"LEVEL:  {level or 'FULL'}")
        return 0

    print("STATUS: Not approved")
    print("")
    print("To approve, run:")
    print(f"  ./layer1/scripts/approve-target.py \"{target}\" <FULL|LIMITED|NONE|CUSTOM> \"<source>\"")
    return 1


def cmd_remove(target: str) -> int:
    if not APPROVED_TARGETS_PATH.is_file():
        print("No approved targets file found.", file=sys.stderr)
        return 1

    payload = _load_payload()
    discovered = payload.get("discovered", [])
    if isinstance(discovered, list):
        payload["discovered"] = [
            item for item in discovered if not (isinstance(item, dict) and item.get("target") == target)
        ]
    else:
        payload["discovered"] = []

    _write_payload(payload)
    print(f"Removed '{target}' from approved targets (if present).")
    return 0


def _parse_add_args(args: list[str]) -> tuple[str, str, str, str, str]:
    target = args[0]
    level = args[1]
    source = args[2] if len(args) >= 3 and args[2] else "Manually approved"

    allowed = ""
    target_type = ""
    if len(args) >= 4:
        fourth = args[3]
        if len(args) >= 5:
            allowed = fourth
            target_type = args[4]
        elif level.upper() != "CUSTOM" and fourth.lower() in {"network", "local"}:
            # Compatibility: Python caller may pass target_type as the 4th arg.
            target_type = fourth
        else:
            allowed = fourth

    return target, level, source, allowed, target_type


def _apply_target_approval(
    target: str,
    level: str,
    source: str = "Manually approved",
    allowed: str = "",
    target_type: str = "",
) -> int:
    level_upper = level.upper()
    if level_upper not in VALID_LEVELS:
        print(
            f"ERROR: Invalid level '{level}'. Must be FULL, LIMITED, NONE, or CUSTOM.",
            file=sys.stderr,
        )
        return 1

    if level_upper == "CUSTOM" and not allowed.strip():
        print("WARNING: CUSTOM level specified but no allowed operations given.", file=sys.stderr)
        print(
            "Usage: ./layer1/scripts/approve-target.py target CUSTOM \"source\" \"ping,dns,curl\"",
            file=sys.stderr,
        )

    payload = _load_payload()
    discovered_items = payload.get("discovered", [])
    if not isinstance(discovered_items, list):
        discovered_items = []

    allowed_list: list[str] = []
    if level_upper == "CUSTOM" and allowed.strip():
        allowed_list = [item.strip() for item in allowed.split(",") if item.strip()]

    updated_discovered: list[dict[str, Any]] = [
        item
        for item in discovered_items
        if not (isinstance(item, dict) and item.get("target") == target)
    ]
    updated_discovered.append(
        {
            "target": target,
            "level": level_upper,
            "allowed": allowed_list,
            "source": source,
            "approved_at": _utc_timestamp(),
        }
    )
    payload["discovered"] = updated_discovered
    payload.setdefault("original", [])
    _write_payload(payload)

    print("═══════════════════════════════════════════════════════════════")
    print("                    TARGET APPROVED")
    print("═══════════════════════════════════════════════════════════════")
    print("")
    print(f"  Target: {target}")
    print(f"  Level:  {level_upper}")
    print(f"  Source: {source}")
    if allowed.strip():
        print(f"  Allowed: {allowed}")
    print("")

    if level_upper == "FULL":
        print("  All testing operations are now allowed against this target.")
    elif level_upper == "LIMITED":
        print("  Passive operations only: download, ping, DNS lookup.")
        print("  Port scanning, fuzzing, and exploitation are BLOCKED.")
    elif level_upper == "NONE":
        print("  No interaction allowed. Document only.")
    elif level_upper == "CUSTOM":
        print("  Only specified operations are allowed.")

    print("")
    print("───────────────────────────────────────────────────────────────")

    _append_scope_log(f"APPROVED: {target} ({level_upper}) — {source}")
    _sync_target_to_scope(target, level_upper, source, target_type)
    return 0


def grant_target_from_ui(
    target: str,
    level: str,
    source: str = "UI approval",
    allowed: str = "",
    target_type: str = "",
) -> bool:
    """Direct backend registration for operator-approved scope changes."""
    return _apply_target_approval(target, level, source, allowed, target_type) == 0


def cmd_add(target: str, level: str, source: str = "Manually approved", allowed: str = "", target_type: str = "") -> int:
    if not _consume_scope_grant_token(target):
        return 1
    return _apply_target_approval(target, level, source, allowed, target_type)


def _check_killswitch() -> bool:
    """Check kill switch. Returns True if active."""
    lib_dir = str(PROJECT_ROOT / "layer1" / "lib")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)
    try:
        import killswitch
        return killswitch.is_killswitch_active(PROJECT_ROOT)
    except (ImportError, Exception):
        return False


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if not args:
        _usage()
        return 1

    if _check_killswitch():
        print("Kill switch is ACTIVE. All operations halted.", file=sys.stderr)
        return 99

    command = args[0]
    if command in {"--help", "-h"}:
        _usage()
        return 0
    if command in {"--list", "-l"}:
        return cmd_list()
    if command in {"--check", "-c"}:
        if len(args) < 2:
            print("ERROR: --check requires a target argument", file=sys.stderr)
            return 1
        return cmd_check(args[1])
    if command in {"--remove", "-r"}:
        if len(args) < 2:
            print("ERROR: --remove requires a target argument", file=sys.stderr)
            return 1
        return cmd_remove(args[1])
    if command.startswith("-"):
        print(f"ERROR: Unknown option '{command}'", file=sys.stderr)
        _usage()
        return 1
    if len(args) < 2:
        print("ERROR: Both target and level are required", file=sys.stderr)
        print("", file=sys.stderr)
        _usage()
        return 1

    target, level, source, allowed, target_type = _parse_add_args(args)
    return cmd_add(target, level, source, allowed, target_type)


if __name__ == "__main__":
    raise SystemExit(main())
