"""Gated debug logging utilities.

Writes newline-delimited JSON debug events to .bra/logs/*-debug.log
only when the BRA-DEBUG governance token is enabled.
"""

from __future__ import annotations

import inspect
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SENSITIVE_KEYS = {
    "token",
    "api_key",
    "authorization",
    "auth",
    "secret",
    "password",
    "key",
    "anthropic_api_key",
    "proxy_backend_api_key",
}


def _mask(value: Any) -> str:
    text = str(value)
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}...{text[-4:]}"


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            key_l = str(key).lower()
            if any(mark in key_l for mark in _SENSITIVE_KEYS):
                out[str(key)] = _mask(item)
            else:
                out[str(key)] = _sanitize(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    return value


def _resolve_paths(
    logs_dir: Path | None = None,
    approvals_dir: Path | None = None,
) -> tuple[Path, Path]:
    if approvals_dir is None or logs_dir is None:
        try:
            from bra.config.settings import APPROVALS_DIR, LOGS_DIR  # lazy import avoids cycles
            if approvals_dir is None:
                approvals_dir = APPROVALS_DIR
            if logs_dir is None:
                logs_dir = LOGS_DIR
        except Exception:
            base = Path(".bra")
            if approvals_dir is None:
                approvals_dir = base / "approvals"
            if logs_dir is None:
                logs_dir = base / "logs"
    return Path(logs_dir), Path(approvals_dir)


def is_debug_token_enabled(
    *,
    approvals_dir: Path | None = None,
    logs_dir: Path | None = None,
) -> bool:
    """Return True when BRA-DEBUG governance token is enabled."""
    _, resolved_approvals = _resolve_paths(logs_dir=logs_dir, approvals_dir=approvals_dir)
    return (resolved_approvals / "BRA-DEBUG").exists()


def write_debug_log(
    log_name: str,
    message: str,
    *,
    approvals_dir: Path | None = None,
    logs_dir: Path | None = None,
    **fields: Any,
) -> None:
    """Write one debug event if BRA-DEBUG is active."""
    try:
        resolved_logs, resolved_approvals = _resolve_paths(logs_dir=logs_dir, approvals_dir=approvals_dir)
        if not is_debug_token_enabled(approvals_dir=resolved_approvals, logs_dir=resolved_logs):
            return

        resolved_logs.mkdir(parents=True, exist_ok=True)
        log_path = resolved_logs / f"{log_name}-debug.log"

        # Capture caller location — skip wrapper functions (named _debug)
        caller = ""
        try:
            frame = inspect.currentframe()
            f = frame.f_back if frame else None
            # Walk past thin _debug wrappers to the real call site
            while f and f.f_code.co_name == "_debug":
                f = f.f_back
            if f:
                co = f.f_code
                fname = os.path.basename(co.co_filename)
                # Include class name if inside a method
                cls = ""
                if "self" in f.f_locals:
                    cls = type(f.f_locals["self"]).__name__ + "."
                elif "cls" in f.f_locals:
                    cls_val = f.f_locals["cls"]
                    if isinstance(cls_val, type):
                        cls = cls_val.__name__ + "."
                caller = f"{fname}:{f.f_lineno} {cls}{co.co_name}"
            del frame
        except Exception:
            pass

        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "pid": os.getpid(),
            "caller": caller,
            "msg": message,
            "fields": _sanitize(fields),
        }
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    except Exception:
        # Never let diagnostics affect runtime behavior.
        return
