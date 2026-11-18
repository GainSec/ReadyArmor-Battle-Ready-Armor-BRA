#!/usr/bin/env python3
"""Native PostToolUse audit logger for track.log."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def _detect_body_root(script_path: Path) -> Path:
    for parent in script_path.parents:
        if parent.name == "body":
            return parent
    return script_path.parents[2]


def _utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _contains_track_marker(path: Path, marker: str) -> bool:
    if not path.is_file():
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    return marker in text


def _track_enabled(body_root: Path) -> bool:
    approvals = body_root / ".bra" / "approvals"
    if os.environ.get("TRACK") == "0":
        return False
    if (approvals / "TRACK_DISABLED").is_file():
        return False
    if os.environ.get("TRACK") == "1":
        return True
    if (approvals / "TRACK").is_file():
        return True

    roe = body_root / "layer3-engagement" / "ROE.md"
    root_roe = body_root / "layer1" / "rules" / "roe.md"
    if _contains_track_marker(roe, "TRACK: DISABLED") or _contains_track_marker(root_roe, "TRACK: DISABLED"):
        return False
    if _contains_track_marker(roe, "TRACK: ENABLED") or _contains_track_marker(root_roe, "TRACK: ENABLED"):
        return True

    # Match existing shell behavior: enabled by default unless explicitly disabled.
    return True


def _summarize_input(tool_name: str, tool_input: object) -> str:
    if not isinstance(tool_input, dict):
        return ""

    if tool_name == "Bash":
        return str(tool_input.get("command", ""))[:200]
    if tool_name in {"Read", "Write"}:
        return str(tool_input.get("file_path", ""))
    if tool_name == "Edit":
        file_path = str(tool_input.get("file_path", ""))
        old = str(tool_input.get("old_string", ""))[:50]
        return f"{file_path} (edit: {old}...)"
    if tool_name == "Glob":
        return str(tool_input.get("pattern", ""))
    if tool_name == "Grep":
        return f"pattern={tool_input.get('pattern', '')} path={tool_input.get('path', '')}"
    if tool_name == "Task":
        return f"agent={tool_input.get('subagent_type', '')}: {tool_input.get('description', '')}"
    if tool_name == "WebFetch":
        return str(tool_input.get("url", ""))
    if tool_name == "WebSearch":
        return str(tool_input.get("query", ""))

    keys = ", ".join(sorted(str(k) for k in tool_input.keys()))
    return keys[:100]


def _write_track_log(body_root: Path, category: str, action: str, reason: str, output: str) -> None:
    log_file = body_root / ".bra" / "logs" / "track.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(
            f"[{_utc_ts()}] [{category}] Action: {action} | Reason: {reason}"
            f"{' | Output: ' + output if output else ''}\n"
        )


def _is_network_command(command: str) -> bool:
    """Check if a command involves network activity."""
    patterns = [
        r"\bnmap\b", r"\bmasscan\b", r"\bcurl\b", r"\bwget\b",
        r"\bnc\b", r"\bsqlmap\b", r"\bnikto\b", r"\bnuclei\b",
        r"\bffuf\b", r"\bgobuster\b", r"\bhydra\b", r"\bssh\b",
    ]
    return any(re.search(pat, command) for pat in patterns)


def _extract_target(command: str) -> str:
    """Extract IP/domain target from a command."""
    # IP address
    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", command)
    if ip_match:
        ip = ip_match.group(1)
        if not ip.startswith("127.0.0.") and ip != "0.0.0.0":
            return ip
    # URL domain
    url_match = re.search(r"https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)", command)
    if url_match:
        return url_match.group(1)
    return ""


def _detect_service_down(target: str) -> bool:
    """Quick ping check to see if target is responding."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", target],
            capture_output=True, timeout=5,
        )
        return result.returncode != 0
    except (subprocess.TimeoutExpired, OSError):
        return True


def _check_service_down(body_root: Path, command: str) -> None:
    """Post-command service down detection."""
    if not _is_network_command(command):
        return
    target = _extract_target(command)
    if not target:
        return

    time.sleep(1)  # Brief delay to let service issues manifest

    if _detect_service_down(target):
        import sys
        print("", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print("  SERVICE DOWN DETECTED", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(f"  Target: {target}", file=sys.stderr)
        print(f"  After command: {command[:200]}", file=sys.stderr)
        print("", file=sys.stderr)
        print("  The target stopped responding after your last command.", file=sys.stderr)
        print("  Consider:", file=sys.stderr)
        print("    1. Pausing testing against this target", file=sys.stderr)
        print("    2. Documenting the incident", file=sys.stderr)
        print("    3. Checking if the service recovers", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

        _write_track_log(body_root, "SERVICE_DOWN", target,
                         "Service stopped responding after command", command[:200])


def main() -> int:
    script_path = Path(__file__).resolve()
    body_root = _detect_body_root(script_path)

    try:
        if not _track_enabled(body_root):
            return 0

        raw = ""
        try:
            import sys

            raw = sys.stdin.read()
        except Exception:
            raw = ""

        payload: dict[str, object] = {}
        if raw.strip():
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    payload = parsed
            except Exception:
                payload = {}

        tool_name = str(payload.get("tool_name", "unknown"))
        tool_input = payload.get("tool_input", {})
        summary = _summarize_input(tool_name, tool_input)
        _write_track_log(body_root, "TOOL", tool_name, "Tool execution completed", summary)

        # Service down detection: after Bash network commands, check if target went down
        if tool_name == "Bash" and summary:
            _check_service_down(body_root, summary)

        return 0
    except Exception:
        # PostToolUse hook must remain non-blocking.
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
