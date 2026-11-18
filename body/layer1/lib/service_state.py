#!/usr/bin/env python3
"""Service availability tracking helpers."""

from __future__ import annotations

import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

SERVICE_CHECK_TIMEOUT = 5
SERVICE_CONNECT_TIMEOUT = 3


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


def _state_file(body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    return root / ".bra" / "service_state.json"


def _log_file(body_root: Path | None = None) -> Path:
    root = _detect_body_root() if body_root is None else body_root
    return root / ".bra" / "logs" / "service_state.log"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _service_log(level: str, message: str, body_root: Path | None = None) -> None:
    log_path = _log_file(body_root)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"[{_utc_now()}] [{level}] {message}\n")
    except OSError:
        pass


def _init_service_state_file(body_root: Path | None = None) -> Path:
    """Ensure service-state file exists and return path."""
    path = _state_file(body_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.is_file():
        path.write_text('{"services": {}}\n', encoding="utf-8")
    return path


def _load_state(body_root: Path | None = None) -> dict[str, Any]:
    path = _init_service_state_file(body_root)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {"services": {}}
    if not isinstance(payload, dict):
        payload = {"services": {}}
    if not isinstance(payload.get("services"), dict):
        payload["services"] = {}
    return payload


def _save_state(payload: dict[str, Any], body_root: Path | None = None) -> None:
    path = _init_service_state_file(body_root)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check_service_responding(target: str, port: str | int | None = None, *, timeout: int = SERVICE_CONNECT_TIMEOUT) -> tuple[bool, str | None]:
    """Check whether target responds via TCP connect or HTTP probe.

    Returns ``(responding, http_code)`` where *http_code* is the HTTP status
    string for web probes or ``None`` for non-HTTP checks.
    """
    if not target:
        return False, None

    resolved_port: int | None = None
    if port not in {None, ""}:
        try:
            resolved_port = int(port)
        except (TypeError, ValueError):
            resolved_port = None

    if resolved_port is not None:
        try:
            with socket.create_connection((target, resolved_port), timeout=timeout):
                return True, None
        except OSError:
            return False, None

    if target.startswith("http://") or target.startswith("https://"):
        urls = [target]
    else:
        urls = [f"https://{target}", f"http://{target}"]

    for url in urls:
        req = request.Request(url, method="HEAD")
        try:
            with request.urlopen(req, timeout=SERVICE_CHECK_TIMEOUT) as response:  # noqa: S310
                if 100 <= response.status <= 599:
                    return True, str(response.status)
        except error.HTTPError as exc:
            if 100 <= exc.code <= 599:
                return True, str(exc.code)
        except Exception:
            continue

    return False, None


def _service_key(target: str, port: str | int | None = None) -> str:
    return f"{target}:{port}" if port not in {None, ""} else target


def record_service_state(
    target: str,
    port: str | int | None = None,
    protocol: str = "auto",
    *,
    body_root: Path | None = None,
) -> dict[str, Any]:
    """Record current service state and return stored entry."""
    if not target:
        raise ValueError("target is required")

    state = _load_state(body_root)
    key = _service_key(target, port)
    now = _utc_now()
    responding, http_code = check_service_responding(target, port)

    previous = state["services"].get(key, {})
    entry = {
        "target": target,
        "port": int(port) if port not in {None, ""} and str(port).isdigit() else None,
        "protocol": protocol,
        "responding": responding,
        "http_code": http_code,
        "last_checked": now,
        "last_responding": now if responding else previous.get("last_responding"),
    }
    state["services"][key] = entry
    _save_state(state, body_root)
    _service_log("RECORD", f"Service {key}: responding={responding}", body_root)
    return entry


def detect_service_down(target: str, port: str | int | None = None, *, body_root: Path | None = None) -> bool:
    """Return ``True`` if service changed from up to down."""
    state = _load_state(body_root)
    key = _service_key(target, port)
    was_responding = bool(state.get("services", {}).get(key, {}).get("responding", False))

    now_responding, _ = check_service_responding(target, port)
    record_service_state(target, port, body_root=body_root)

    went_down = was_responding and not now_responding
    if went_down:
        _service_log("DOWN", f"Service {key} went DOWN", body_root)
    return went_down


def get_service_state(target: str, port: str | int | None = None, *, body_root: Path | None = None) -> dict[str, Any] | None:
    """Return stored state for target or ``None``."""
    state = _load_state(body_root)
    return state.get("services", {}).get(_service_key(target, port))


def get_all_service_states(body_root: Path | None = None) -> list[dict[str, Any]]:
    """Return all stored service state entries."""
    state = _load_state(body_root)
    values = state.get("services", {}).values()
    return [entry for entry in values if isinstance(entry, dict)]


def get_service_down_guidance() -> str:
    """Return operator guidance text for service-down scenarios."""
    return (
        "═══════════════════════════════════════════════════════════════\n"
        "                    SERVICE DOWN DETECTED\n"
        "═══════════════════════════════════════════════════════════════\n"
        "\n"
        "The target service has stopped responding after your last action.\n"
        "\n"
        "RECOMMENDED ACTIONS (in order):\n"
        "\n"
        "1. STOP TESTING IMMEDIATELY\n"
        "   - Do not send more requests\n"
        "   - This may indicate a crash, DoS condition, or defensive response\n"
        "\n"
        "2. DOCUMENT THE INCIDENT\n"
        "   - Record what command/action was being performed\n"
        "   - Note any error messages or unusual responses\n"
        "   - Capture timestamps\n"
        "\n"
        "3. ASK THE USER\n"
        "   - Report the service outage\n"
        "   - Request guidance on how to proceed\n"
        "   - Do not resume testing without explicit approval\n"
        "\n"
        "4. WAIT BEFORE RETRY (if approved)\n"
        "   - Wait at least 60 seconds before checking again\n"
        "   - Use: sleep 60 && curl -I <target>\n"
        "   - Confirm with user that service is back before resuming\n"
        "\n"
        "───────────────────────────────────────────────────────────────\n"
        "NOTE: If you need to use sleep/delay before retrying:\n"
        "  - Confirm the service was responding before the sleep\n"
        "  - After the delay, verify it's still responding\n"
        "  - Ask user if uncertain about service availability\n"
        "───────────────────────────────────────────────────────────────\n"
    )


def generate_service_down_prompt(target: str, command: str = "Unknown command") -> str:
    """Return user-facing escalation prompt for outage handling."""
    return (
        "\n"
        "═══════════════════════════════════════════════════════════════\n"
        "                    SERVICE DOWN DETECTED\n"
        "═══════════════════════════════════════════════════════════════\n"
        "\n"
        f"Target: {target}\n"
        f"Last command: {command}\n"
        "\n"
        "The service has stopped responding after your action.\n"
        "\n"
        "REQUIRED ACTIONS:\n"
        f"  1. Stop all testing against this target immediately\n"
        f"  2. Document: Note the command and any error messages\n"
        f"  3. Ask user: 'The service at {target} stopped responding.\n"
        f"     Should I wait and retry, or stop testing this target?'\n"
        f"  4. Wait for explicit user approval before any retry\n"
        "\n"
        "───────────────────────────────────────────────────────────────\n"
    )


def clear_service_state(body_root: Path | None = None) -> None:
    """Delete all saved service state."""
    path = _state_file(body_root)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    _service_log("CLEAR", "Service state cleared", body_root)


def clear_service(target: str, port: str | int | None = None, *, body_root: Path | None = None) -> bool:
    """Remove a single tracked service entry."""
    path = _state_file(body_root)
    if not path.is_file():
        return True
    state = _load_state(body_root)
    key = _service_key(target, port)
    removed = state.get("services", {}).pop(key, None) is not None
    if removed:
        _save_state(state, body_root)
        _service_log("CLEAR", f"Service {key} state removed", body_root)
    return True if removed else True


def _show_help() -> None:
    print(
        "service_state.py\n\n"
        "Usage:\n"
        "  service_state.py --record <target> [port]\n"
        "  service_state.py --check <target> [port]\n"
        "  service_state.py --detect-down <target> [port]\n"
        "  service_state.py --list\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"--help", "-h"}:
        _show_help()
        return 0

    if args[0] == "--record" and len(args) >= 2:
        target = args[1]
        port = args[2] if len(args) >= 3 else None
        print(json.dumps(record_service_state(target, port), indent=2))
        return 0

    if args[0] == "--check" and len(args) >= 2:
        target = args[1]
        port = args[2] if len(args) >= 3 else None
        responding, _ = check_service_responding(target, port)
        return 0 if responding else 1

    if args[0] == "--detect-down" and len(args) >= 2:
        target = args[1]
        port = args[2] if len(args) >= 3 else None
        return 0 if detect_service_down(target, port) else 1

    if args[0] == "--list":
        print(json.dumps(get_all_service_states(), indent=2))
        return 0

    print("Invalid arguments", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
