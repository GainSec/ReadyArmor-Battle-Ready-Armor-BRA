"""BRA Verbose Runtime Tracer.

Activated by BRA_VERBOSE=1 environment variable.
Dumps everything happening at runtime to both stderr (terminal) and a log file.

Usage:
    BRA_VERBOSE=1 PYTHONPATH=head:boots python3 -m uvicorn boots.main:app --reload

Log file: .bra/logs/verbose.log (auto-created)

Coverage:
    - All HTTP requests/responses with timing
    - All WebSocket connect/disconnect/messages
    - EngageManager method calls with arguments
    - AgentRunner callbacks (on_text, on_command, on_blocked, etc.)
    - bridge.run_script() calls with args, return codes, stdout/stderr
    - Harness registry lookups and execution
    - Governance token checks
    - Broadcast events to WebSocket clients
    - All boots.* and bra.* module logging at DEBUG level
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ──────────────────────────────────────────────────────────────────────
# Gate: everything is a no-op unless BRA_VERBOSE=1 or approval file exists
# ──────────────────────────────────────────────────────────────────────


def _approval_file_enables_verbose() -> bool:
    candidates: list[Path] = []
    bra_dir = os.environ.get("BRA_DIR", "").strip()
    if bra_dir:
        candidates.append(Path(bra_dir))
    try:
        candidates.append(Path.cwd())
    except FileNotFoundError:
        pass

    for candidate in candidates:
        body_root = candidate / "body" if (candidate / "body" / ".bra").exists() else candidate
        approvals_dir = body_root / ".bra" / "approvals"
        if (approvals_dir / "BRA_VERBOSE").exists() or (approvals_dir / "BRA-VERBOSE").exists():
            return True
    return False


ENABLED = os.environ.get("BRA_VERBOSE", "").strip() in ("1", "true", "yes") or _approval_file_enables_verbose()

_log_file_handle = None
_installed = False

# Truncation limits
_MAX_ARG_LEN = 2000
_MAX_RESULT_LEN = 2000

# Results that are too boring to log (terminal only — still written to file)
_TRIVIAL_RESULTS = {None, True, False, 0, "", "None", "True", "False", "0"}
_TRIVIAL_RESULT_STRS = {"{'action': 'none', 'reason': 'inactive'}", "{'action': 'none', 'reason': 'query_unavailable'}"}


def _is_trivial(result: Any) -> bool:
    try:
        return result in _TRIVIAL_RESULTS or str(result) in _TRIVIAL_RESULT_STRS
    except TypeError:
        return str(result) in _TRIVIAL_RESULT_STRS


def _truncate(value: Any, limit: int = _MAX_ARG_LEN) -> str:
    s = str(value)
    if len(s) <= limit:
        return s
    return s[:limit] + f"... [{len(s)} chars]"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]


def _emit(category: str, message: str, *, _file_only: bool = False, **fields: Any) -> None:
    """Write one trace line to stderr and log file.

    If _file_only=True, write to log file but skip terminal output.
    """
    if not ENABLED:
        return

    parts = [f"[{_ts()}] [{category}] {message}"]
    for k, v in fields.items():
        parts.append(f"  {k}={_truncate(v)}")
    line = "\n".join(parts)

    # stderr — colorized (unless file-only)
    if not _file_only:
        color = _COLORS.get(category, "\033[37m")
        sys.stderr.write(f"{color}{line}\033[0m\n")
        sys.stderr.flush()

    # log file (tag file-only lines so the logviewer can hide them)
    if _file_only:
        line = f"[FILE-ONLY] {line}"
    global _log_file_handle
    if _log_file_handle is not None:
        try:
            _log_file_handle.write(line + "\n")
            _log_file_handle.flush()
        except Exception:
            pass


_COLORS = {
    "HTTP": "\033[36m",      # cyan
    "WS": "\033[35m",        # magenta
    "ENGAGE": "\033[33m",    # yellow
    "RUNNER": "\033[32m",    # green
    "SCRIPT": "\033[31m",    # red
    "HARNESS": "\033[34m",   # blue
    "GOV": "\033[91m",       # bright red
    "BCAST": "\033[95m",     # bright magenta
    "LOG": "\033[90m",       # gray
    "SUBAGENT": "\033[96m",  # bright cyan
    "AGENT": "\033[92m",     # bright green
}


# ──────────────────────────────────────────────────────────────────────
# 1. Python logging interceptor — captures all boots.*/bra.* loggers
# ──────────────────────────────────────────────────────────────────────

class _VerboseHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        _emit("LOG", f"{record.name}: {record.getMessage()}", level=record.levelname)


def _install_logging() -> None:
    handler = _VerboseHandler()
    handler.setLevel(logging.DEBUG)
    for prefix in ("boots", "bra", "uvicorn", "fastapi"):
        logger = logging.getLogger(prefix)
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)


# ──────────────────────────────────────────────────────────────────────
# 2. Method tracing decorator — wraps class methods
# ──────────────────────────────────────────────────────────────────────

def _safe_repr_args(args: tuple, kwargs: dict, skip_self: bool = True) -> str:
    parts = []
    arg_list = list(args)
    if skip_self and arg_list:
        arg_list = arg_list[1:]  # skip self
    for a in arg_list:
        parts.append(_truncate(a))
    for k, v in kwargs.items():
        parts.append(f"{k}={_truncate(v)}")
    return ", ".join(parts)


def _trace_method(category: str):
    """Decorator that traces method calls and results."""
    def decorator(fn):
        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                name = fn.__qualname__
                _emit(category, f"-> {name}({_safe_repr_args(args, kwargs)})")
                t0 = time.monotonic()
                try:
                    result = await fn(*args, **kwargs)
                    ms = int((time.monotonic() - t0) * 1000)
                    if _is_trivial(result):
                        _emit(category, f"<- {name} [{ms}ms]")
                        _emit(category, f"<- {name} [{ms}ms]", _file_only=True, result=_truncate(result, _MAX_RESULT_LEN))
                    else:
                        _emit(category, f"<- {name} [{ms}ms]", result=_truncate(result, _MAX_RESULT_LEN))
                    return result
                except Exception as exc:
                    ms = int((time.monotonic() - t0) * 1000)
                    _emit(category, f"!! {name} RAISED [{ms}ms]", error=str(exc))
                    raise
            return async_wrapper
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args, **kwargs):
                name = fn.__qualname__
                _emit(category, f"-> {name}({_safe_repr_args(args, kwargs)})")
                t0 = time.monotonic()
                try:
                    result = fn(*args, **kwargs)
                    ms = int((time.monotonic() - t0) * 1000)
                    if _is_trivial(result):
                        _emit(category, f"<- {name} [{ms}ms]")
                        _emit(category, f"<- {name} [{ms}ms]", _file_only=True, result=_truncate(result, _MAX_RESULT_LEN))
                    else:
                        _emit(category, f"<- {name} [{ms}ms]", result=_truncate(result, _MAX_RESULT_LEN))
                    return result
                except Exception as exc:
                    ms = int((time.monotonic() - t0) * 1000)
                    _emit(category, f"!! {name} RAISED [{ms}ms]", error=str(exc))
                    raise
            return sync_wrapper
    return decorator


def _patch_class_methods(cls, category: str, method_names: list[str] | None = None) -> None:
    """Monkey-patch methods on a class to add tracing."""
    for name in (method_names or []):
        original = getattr(cls, name, None)
        if original is None:
            continue
        if isinstance(original, (staticmethod, classmethod)):
            continue
        wrapped = _trace_method(category)(original)
        setattr(cls, name, wrapped)


# ──────────────────────────────────────────────────────────────────────
# 3. Function-level patches — wrap standalone functions
# ──────────────────────────────────────────────────────────────────────

def _patch_function(module, func_name: str, category: str):
    """Monkey-patch a module-level function with tracing."""
    original = getattr(module, func_name, None)
    if original is None:
        return
    wrapped = _trace_method(category)(original)
    setattr(module, func_name, wrapped)


# ──────────────────────────────────────────────────────────────────────
# 4. Install all patches
# ──────────────────────────────────────────────────────────────────────

def install() -> None:
    """Install verbose tracing across the entire runtime. Idempotent."""
    global _installed, _log_file_handle
    if _installed or not ENABLED:
        return
    _installed = True

    # Open log file
    log_dir = Path(".bra") / "logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        _log_file_handle = open(log_dir / "verbose.log", "a", encoding="utf-8")
    except Exception as exc:
        sys.stderr.write(f"[BRA_VERBOSE] Could not open log file: {exc}\n")

    _emit("ENGAGE", "=" * 60)
    _emit("ENGAGE", "BRA VERBOSE TRACING ACTIVE")
    _emit("ENGAGE", f"Log file: {log_dir / 'verbose.log'}")
    _emit("ENGAGE", "=" * 60)

    # 1. Python logging
    _install_logging()

    # 2. Patch EngageManager
    try:
        from boots.engage import EngageManager
        _patch_class_methods(EngageManager, "ENGAGE", [
            "broadcast",
            "start_agent",
            "resume_agent",
            "stop_agent",
            "pause_agent",
            "resolve_approval",
            "select_option",
            "continue_with_message",
            "debug_message_to_session",
            "toggle_kill_switch",
            "clear_history",
            "get_state",
            "_prepare_runner",
            "_handle_blocked_operation",
            "_process_approval_result",
            "_on_options",
            "_on_turn_complete",
            "_on_agent_done",
            "_do_stop_agent",
            "_cancel_lingering_agent_task",
            "_terminate_all_agent_subprocesses",
        ])
        _emit("ENGAGE", "Patched EngageManager methods")
    except Exception as exc:
        _emit("ENGAGE", f"Failed to patch EngageManager: {exc}")

    # 3. Patch route_message and helpers in engage module
    try:
        import boots.engage as engage_mod
        for fn_name in [
            "route_message",
            "_run_script",
            "_run_wizard",
            "_wizard_submit",
            "_wizard_launch",
            "_wizard_launch_agent",
            "_run_end_engagement",
            "_run_packup",
            "_broadcast_end_intake",
            "_submit_end_intake",
            "_ensure_end_intake_ready",
            "_load_token_states",
            "_save_token_states",
            "_get_engagement_menu",
        ]:
            _patch_function(engage_mod, fn_name, "ENGAGE")
        _emit("ENGAGE", "Patched engage module functions")
    except Exception as exc:
        _emit("ENGAGE", f"Failed to patch engage functions: {exc}")

    # 4. Patch AgentRunner
    try:
        from bra.core.runner import AgentRunner
        _patch_class_methods(AgentRunner, "RUNNER", [
            "start",
            "resume",
            "stop",
            "send_message",
            "_process_message",
            "_run_agent_loop",
        ])
        # Subagent methods get their own category
        _patch_class_methods(AgentRunner, "SUBAGENT", [
            "_run_findings_subagent",
            "_handle_writeup_trigger",
            "_surface_subagent_message",
            "_build_forced_findings_prompt",
        ])
        # Main agent lifecycle gets AGENT category
        _patch_class_methods(AgentRunner, "AGENT", [
            "run",
            "continue_with_input",
            "_process_message",
            "_handle_tool_use",
            "_handle_tool_result",
            "select_option",
            "pause",
            "stop",
        ])
        # Wrap the callback setters to trace when callbacks fire
        _wrap_runner_callbacks()
        _emit("RUNNER", "Patched AgentRunner methods")
    except Exception as exc:
        _emit("RUNNER", f"Failed to patch AgentRunner: {exc}")

    # 5. Patch bridge.run_script
    try:
        from bra.core import bridge
        _original_run_script = bridge.run_script

        @functools.wraps(_original_run_script)
        def _traced_run_script(name, *args, **kwargs):
            _emit("SCRIPT", f"-> run_script({name}, {args})")
            t0 = time.monotonic()
            try:
                result = _original_run_script(name, *args, **kwargs)
                ms = int((time.monotonic() - t0) * 1000)
                _emit("SCRIPT", f"<- run_script({name}) [{ms}ms]",
                       returncode=result.returncode,
                       stdout=_truncate(result.stdout or "", _MAX_RESULT_LEN),
                       stderr=_truncate(result.stderr or "", _MAX_RESULT_LEN))
                return result
            except Exception as exc:
                ms = int((time.monotonic() - t0) * 1000)
                _emit("SCRIPT", f"!! run_script({name}) RAISED [{ms}ms]", error=str(exc))
                raise

        bridge.run_script = _traced_run_script
        _emit("SCRIPT", "Patched bridge.run_script")
    except Exception as exc:
        _emit("SCRIPT", f"Failed to patch bridge.run_script: {exc}")

    # 6. Patch harness registry
    try:
        from boots.harness import base as harness_base
        for fn_name in ["get_registry", "get_harness"]:
            _patch_function(harness_base, fn_name, "HARNESS")
        _emit("HARNESS", "Patched harness registry")
    except Exception as exc:
        _emit("HARNESS", f"Failed to patch harness: {exc}")

    # 7. Patch governance approval functions (skip is_debug_token_enabled — too noisy)
    try:
        from bra.core import approval
        for fn_name in dir(approval):
            obj = getattr(approval, fn_name)
            if callable(obj) and not fn_name.startswith("_"):
                _patch_function(approval, fn_name, "GOV")
        _emit("GOV", "Patched governance/approval functions")
    except Exception as exc:
        _emit("GOV", f"Failed to patch governance: {exc}")

    # 8. Patch governance hooks (in-process gatekeepers)
    try:
        from bra.hooks import bash_hook, file_hook, killswitch, finding_guard
        from bra.hooks import tool_approval_hook, post_hook
        from bra.hooks import compact_hook
        for mod, fn_name in [
            (bash_hook, "pre_bash"),
            (file_hook, "pre_file"),
            (killswitch, "check_killswitch_hook"),
            (finding_guard, "pre_finding_guard"),
            (tool_approval_hook, "check_tool_approval_hook"),
            (post_hook, "post_tool"),
            (compact_hook, "pre_compact"),
        ]:
            _patch_function(mod, fn_name, "GOV")
        _emit("GOV", "Patched governance hooks (bash/file/killswitch/finding/approval/post)")
    except Exception as exc:
        _emit("GOV", f"Failed to patch governance hooks: {exc}")

    # 9. Patch main._debug for WebSocket tracing
    try:
        import boots.main as main_mod
        _original_main_debug = main_mod._debug

        @functools.wraps(_original_main_debug)
        def _traced_main_debug(event: str, **fields):
            if event.startswith("ws_"):
                _emit("WS", event, **{k: v for k, v in fields.items() if k != "bra_root"})
            _original_main_debug(event, **fields)

        main_mod._debug = _traced_main_debug
        _emit("WS", "Patched main._debug for WebSocket tracing")
    except Exception as exc:
        _emit("WS", f"Failed to patch WS tracing: {exc}")

    # 10. Patch TakeoverController
    try:
        from boots.takeover import TakeoverController
        _patch_class_methods(TakeoverController, "ENGAGE", [
            "on_engage_event",
            "evaluate",
            "execute_action",
        ])
        _emit("ENGAGE", "Patched TakeoverController")
    except Exception as exc:
        _emit("ENGAGE", f"Failed to patch TakeoverController: {exc}")


# ──────────────────────────────────────────────────────────────────────
# Runner callback tracing — wraps the callbacks the EngageManager sets
# ──────────────────────────────────────────────────────────────────────

def _wrap_runner_callbacks() -> None:
    """Wrap AgentRunner.__init__ to trace all callback invocations."""
    from bra.core.runner import AgentRunner

    _original_init = AgentRunner.__init__

    @functools.wraps(_original_init)
    def _traced_init(self, *args, **kwargs):
        _original_init(self, *args, **kwargs)
        # Wrap each on_* callback
        for attr in dir(self):
            if attr.startswith("on_") and callable(getattr(self, attr, None)):
                original_cb = getattr(self, attr)
                cb_name = attr

                if asyncio.iscoroutinefunction(original_cb):
                    @functools.wraps(original_cb)
                    async def _traced_cb(*a, _name=cb_name, _orig=original_cb, **kw):
                        _emit("RUNNER", f"callback {_name} fired", args=_truncate(a), kwargs=_truncate(kw))
                        result = await _orig(*a, **kw)
                        if not _is_trivial(result):
                            _emit("RUNNER", f"callback {_name} returned", result=_truncate(result, _MAX_RESULT_LEN))
                        return result
                    setattr(self, attr, _traced_cb)
                elif callable(original_cb):
                    @functools.wraps(original_cb)
                    def _traced_cb(*a, _name=cb_name, _orig=original_cb, **kw):
                        _emit("RUNNER", f"callback {_name} fired", args=_truncate(a), kwargs=_truncate(kw))
                        result = _orig(*a, **kw)
                        if not _is_trivial(result):
                            _emit("RUNNER", f"callback {_name} returned", result=_truncate(result, _MAX_RESULT_LEN))
                        return result
                    setattr(self, attr, _traced_cb)

    AgentRunner.__init__ = _traced_init
