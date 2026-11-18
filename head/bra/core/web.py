"""Web GUI status and configuration module.

Handles:
- Loading/saving web config from body/.bra/web-config.json
- Health checking the web GUI via /api/health endpoint
"""

import json
from pathlib import Path
from urllib.parse import urlparse

import httpx

from bra.config.settings import BRA_STATE
from bra.debug_log import write_debug_log


def get_web_config_path() -> Path:
    """Get path to web config file."""
    write_debug_log("web", "resolve_config_path", path=str(BRA_STATE / "web-config.json"))
    return BRA_STATE / "web-config.json"


def load_web_config() -> dict | None:
    """Load web GUI configuration.

    Returns:
        Config dict with 'url' and 'token' keys, or None if not configured.
    """
    config_path = get_web_config_path()
    write_debug_log("web", "load_start", path=str(config_path), exists=config_path.exists())
    if not config_path.exists():
        write_debug_log("web", "load_missing")
        return None

    try:
        data = json.loads(config_path.read_text())
        write_debug_log(
            "web",
            "load_parsed",
            has_url=bool(data.get("url")),
            has_token=bool(data.get("token")),
        )
        if data.get("url") and data.get("token"):
            return data
        write_debug_log("web", "load_invalid_shape")
        return None
    except (json.JSONDecodeError, IOError):
        write_debug_log("web", "load_error", error_type="json_or_io")
        return None


def save_web_config(url: str, token: str) -> None:
    """Save web GUI configuration.

    Args:
        url: Web GUI URL (e.g., http://localhost:9999)
        token: Access token for authentication
    """
    config_path = get_web_config_path()
    write_debug_log(
        "web",
        "save_start",
        path=str(config_path),
        url=url,
        token_present=bool(token),
    )
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps({"url": url, "token": token}, indent=2))
    write_debug_log("web", "save_done", path=str(config_path))


def validate_web_url(url: str) -> str | None:
    """Validate a web GUI URL.

    Returns:
        None if valid, or an error message string if invalid.
    """
    if not url or not url.strip():
        write_debug_log("web", "validate_fail", reason="empty_url")
        return "URL cannot be empty"

    try:
        parsed = urlparse(url)
    except Exception:
        write_debug_log("web", "validate_fail", reason="parse_error")
        return "Unable to parse URL"

    if parsed.scheme not in ("http", "https"):
        write_debug_log("web", "validate_fail", reason="bad_scheme", scheme=parsed.scheme)
        return "URL must start with http:// or https://"

    if not parsed.hostname:
        write_debug_log("web", "validate_fail", reason="missing_hostname")
        return "URL must include a hostname"

    try:
        port = parsed.port
    except ValueError:
        write_debug_log("web", "validate_fail", reason="bad_port")
        return "Port must be between 1 and 65535"

    if port is not None:
        if not (1 <= port <= 65535):
            write_debug_log("web", "validate_fail", reason="port_out_of_range", port=port)
            return "Port must be between 1 and 65535"

    write_debug_log("web", "validate_ok", host=parsed.hostname, port=parsed.port, scheme=parsed.scheme)
    return None


def check_web_status(url: str, token: str) -> tuple[bool, str]:
    """Check if web GUI is accessible.

    Makes a request to {url}/api/health with Bearer token authentication.

    Args:
        url: Web GUI base URL
        token: Access token

    Returns:
        Tuple of (is_online, status_message)
        - (True, "Online") if server responds with 200
        - (False, "Offline") if connection fails or times out
        - (False, "Auth failed") if 401/403 response
    """
    try:
        endpoint = f"{url.rstrip('/')}/api/health"
        write_debug_log("web", "status_check_start", endpoint=endpoint, token_present=bool(token))
        response = httpx.get(
            endpoint,
            headers={"Authorization": f"Bearer {token}"},
            timeout=3.0,
        )
        write_debug_log("web", "status_check_response", status_code=response.status_code)

        if response.status_code == 200:
            write_debug_log("web", "status_check_result", online=True, result="Online")
            return (True, "Online")
        elif response.status_code in (401, 403):
            write_debug_log("web", "status_check_result", online=False, result="Auth failed")
            return (False, "Auth failed")
        else:
            write_debug_log("web", "status_check_result", online=False, result="Offline")
            return (False, "Offline")

    except Exception as exc:
        write_debug_log("web", "status_check_error", error=str(exc))
        return (False, "Offline")
