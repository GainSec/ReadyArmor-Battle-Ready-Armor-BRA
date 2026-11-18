"""EngageManager — agent lifecycle manager for the web GUI.

Singleton that manages the AgentRunner instance, WebSocket client pool,
event broadcasting, and approval flow coordination. This is the bridge
between the browser and head/bra's agent runtime.

The same governance hooks, approval system, and .bra/ state are used
as the TUI — the only difference is the UI frontend.
"""

import asyncio
import importlib.util
import ipaddress
import json
import logging
import os
import re
import signal
import subprocess
import sys
from datetime import datetime, timezone
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from bra.core.bridge import (
    get_scope_summary,
    is_scope_configured,
    run_script,
    update_session_state,
)
from bra.config.settings import get_proxy_config
from bra.proxy.litellm_sidecar import ProxySidecar
from bra.proxy.config import build_litellm_config


def _mask_user_input(text: str) -> str:
    """Mask identifiable data in user input before sending to the LLM."""
    try:
        from bra.anon.mapping import AnonMap
        from bra.config.settings import get_bra_root

        bra_root = get_bra_root()
        body_root = bra_root / "body"
        if not body_root.is_dir():
            body_root = bra_root

        approvals_dir = body_root / ".bra" / "approvals"
        if (approvals_dir / "NO-SCAN").exists() or (approvals_dir / "ANON-DISABLE").exists():
            return text

        map_path = body_root / ".bra" / "anon_map.json"
        if not map_path.exists():
            return text

        amap = AnonMap(map_path)
        return amap.mask(text)
    except Exception:
        return text


def _unmask_output(text: str) -> str:
    """Unmask anon nouns back to real values for operator display."""
    try:
        from bra.anon.mapping import AnonMap
        from bra.config.settings import get_bra_root

        bra_root = get_bra_root()
        body_root = bra_root / "body"
        if not body_root.is_dir():
            body_root = bra_root

        approvals_dir = body_root / ".bra" / "approvals"
        if (approvals_dir / "ANON-DISABLE").exists():
            return text

        map_path = body_root / ".bra" / "anon_map.json"
        if not map_path.exists():
            return text

        amap = AnonMap(map_path)
        return amap.unmask(text)
    except Exception:
        return text


def _approval_anon_highlights(value: Any) -> list[dict[str, str]]:
    """Return anon-map entries whose masked aliases appear in an approval event."""
    try:
        from bra.config.settings import get_bra_root

        bra_root = get_bra_root()
        body_root = bra_root / "body"
        if not body_root.is_dir():
            body_root = bra_root

        approvals_dir = body_root / ".bra" / "approvals"
        if (approvals_dir / "ANON-DISABLE").exists():
            return []

        map_path = body_root / ".bra" / "anon_map.json"
        if not map_path.exists():
            return []

        data = json.loads(map_path.read_text(encoding="utf-8"))
        mappings = data.get("mappings", [])
        if not isinstance(mappings, list):
            return []

        try:
            corpus = json.dumps(value, sort_keys=True, default=str)
        except Exception:
            corpus = str(value)

        highlights: list[dict[str, str]] = []
        seen: set[str] = set()
        for mapping in mappings:
            if not isinstance(mapping, dict):
                continue
            anon = str(mapping.get("anon") or "")
            real = str(mapping.get("real") or "")
            if not anon or not real or anon in seen or anon not in corpus:
                continue
            seen.add(anon)
            highlights.append(
                {
                    "anon": anon,
                    "real": real,
                    "type": str(mapping.get("type") or "value"),
                }
            )
        return highlights
    except Exception:
        return []


def _with_approval_anon_highlights(event: dict[str, Any]) -> dict[str, Any]:
    highlights = _approval_anon_highlights(event)
    if not highlights:
        return event
    event = dict(event)
    event["approval_anon_highlights"] = highlights
    return event


from bra.core.end_intake import (
    build_end_intake_payload,
    load_end_profile,
    normalize_report_types,
    save_end_profile,
    validate_end_intake_submission,
)
from bra.core.host_context import build_host_context_block
from bra.debug_log import write_debug_log
from boots.takeover import get_takeover_controller

logger = logging.getLogger(__name__)

HISTORY_MAX = 500
VOICECALL_BRA_AGENT_PROVIDER_HERMES = "hermes"
VOICECALL_BRA_AGENT_PROVIDER_OPENCLAW = "openclaw"
VOICECALL_BRA_HERMES_ACTIONS = {
    "voicecall_bra.initiate": "initiate_call",
    "voicecall_bra.continue": "continue_call",
    "voicecall_bra.speak": "speak_to_user",
    "voicecall_bra.end": "end_call",
    "voicecall_bra.kill": "kill_calls",
    "voicecall_bra.status": "get_status",
}
ENGAGEMENT_TOKEN_NAMES: tuple[str, ...] = (
    "ACTIVE-TESTING-APPROVAL",
    "DESTRUCTIVE-APPROVAL",
    "SYSTEM-INSTALL-APPROVAL",
    "FRAMEWORK-DEV-APPROVAL",
    "PUSH-APPROVAL",
    "LAYER2-WRITE-APPROVAL",
    "OVERRIDE-APPROVAL",
    "OFFENSIVE-TESTING-APPROVAL",
    "USER-INSTALL-APPROVAL",
    "VIRTUAL-INSTALL-APPROVAL",
    "FINDINGS-SELECTION",
    "WATCH",
    "TRACK",
    "BRA-DEBUG",
    "BRA_VERBOSE",
    "NO-TOKEN-TRACKING",
    "NEGATIVE-RESULTS",
    "IGNORE-BACKUP",
    "FINDINGS-FASTPATH",
    "SLOWPATH-FINDINGS",
    "SCOPE-CONFIRMED",
    "FRONTIER-SCOPE",
    "MICRO-SCOPE",
    "LOCAL-SCOPE",
    "DUMB-SCOPE",
    "NO-SCOPE",
    "MAP-SCAN",
    "ANON-SCAN",
    "LOCAL-SCAN",
    "NO-SCAN",
    "ANON-DISABLE",
)

SCOPE_TOKEN_NAMES: tuple[str, ...] = (
    "FRONTIER-SCOPE",
    "MICRO-SCOPE",
    "LOCAL-SCOPE",
    "DUMB-SCOPE",
    "NO-SCOPE",
)


def _resolve_body_and_project_roots(bra_root: str | Path) -> tuple[Path, Path]:
    """Resolve body root and project root from either root-or-body input path."""
    candidate = Path(bra_root).expanduser().resolve()

    if (candidate / ".bra").exists() and (candidate / "layer3-engagement").exists():
        body_root = candidate
    elif (candidate / "body" / ".bra").exists() and (candidate / "body" / "layer3-engagement").exists():
        body_root = candidate / "body"
    else:
        body_root = candidate

    if body_root.name == "body":
        project_root = body_root.parent
    else:
        project_root = body_root

    return body_root, project_root


def _body_root(bra_dir: str | Path) -> Path:
    """Get body root from project root."""
    body_root, _ = _resolve_body_and_project_roots(bra_dir)
    return body_root


def _sync_settings_root_for_path(bra_root: str | Path) -> None:
    """Align head runtime settings root with boots-selected BRA directory."""
    _, project_root = _resolve_body_and_project_roots(bra_root)
    if not (project_root / "body").exists():
        return
    try:
        from bra.config.settings import set_bra_root
        set_bra_root(project_root)
        _debug(
            "sync_settings_root",
            bra_root=str(project_root / "body"),
            project_root=str(project_root),
        )
    except Exception as exc:
        _debug("sync_settings_root_error", bra_root=str(project_root / "body"), error=str(exc))


def _debug(event: str, *, bra_root: str | None = None, **fields: Any) -> None:
    approvals_dir = None
    logs_dir = None
    if bra_root:
        root = Path(bra_root)
        approvals_dir = root / ".bra" / "approvals"
        logs_dir = root / ".bra" / "logs"
    write_debug_log("engage", event, approvals_dir=approvals_dir, logs_dir=logs_dir, **fields)


def _proxy_debug(event: str, *, bra_root: str | None = None, **fields: Any) -> None:
    """Debug log for proxy sidecar events — shows as [PROXY] in verbose.log."""
    logs_dir = None
    if bra_root:
        logs_dir = Path(bra_root) / ".bra" / "logs"
    write_debug_log("proxy", event, logs_dir=logs_dir, **fields)


def _is_sigterm_noise(text: str) -> bool:
    """True when error text is expected SIGTERM subprocess cleanup noise."""
    t = (text or "").lower()
    return "exit code -15" in t or "sigterm" in t or "signal 15" in t


def _friendly_task_name(script: str) -> str:
    """Convert internal script/config filenames into UI-safe task labels."""
    base = Path(script).name
    # Hide implementation filename details from operator-facing stream text.
    base = re.sub(r"\.(sh|json|yaml|yml|py|txt|md)$", "", base, flags=re.IGNORECASE)
    base = base.replace("_", " ").replace("-", " ").strip()
    return base.title() if base else "Task"


def _invoke_voicecall_bra_gateway_sync(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    timeout_ms: int = 10000,
) -> dict[str, Any]:
    payload = params or {}
    cmd = [
        "openclaw",
        "gateway",
        "call",
        method,
        "--json",
        "--params",
        json.dumps(payload, separators=(",", ":")),
        "--timeout",
        str(timeout_ms),
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip() or f"exit={proc.returncode}"
        raise RuntimeError(f"voicecall gateway call failed: {detail}")

    output = (proc.stdout or "").strip()
    if not output:
        return {}
    for line in reversed(output.splitlines()):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    return {}


def _normalize_voicecall_bra_agent_provider(value: Any) -> str:
    if str(value or "").strip().lower() == VOICECALL_BRA_AGENT_PROVIDER_HERMES:
        return VOICECALL_BRA_AGENT_PROVIDER_HERMES
    return VOICECALL_BRA_AGENT_PROVIDER_OPENCLAW


def _load_voicecall_bra_agent_config() -> dict[str, Any]:
    config_path = Path(__file__).with_name(".bra-gui-config.json")
    try:
        parsed = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _invoke_voicecall_bra_hermes_sync(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    timeout_ms: int = 10000,
) -> dict[str, Any]:
    action = VOICECALL_BRA_HERMES_ACTIONS.get(method)
    if not action:
        raise RuntimeError(f"unsupported Hermes voicecall method: {method}")

    plugin_path = Path.home() / ".hermes" / "plugins" / "voice-call-bra" / "__init__.py"
    if not plugin_path.exists():
        raise RuntimeError("Hermes voice-call-bra plugin is not installed")

    spec = importlib.util.spec_from_file_location("bra_hermes_voice_call_bra", plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Hermes voice-call-bra plugin")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    handler = getattr(module, "_handle_tool", None)
    if not callable(handler):
        raise RuntimeError("Hermes voice-call-bra plugin has no _handle_tool")

    raw = handler({"action": action, **(params or {})})
    parsed = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(parsed, dict):
        return {}
    if parsed.get("error"):
        raise RuntimeError(str(parsed["error"]))
    details = parsed.get("details")
    return details if isinstance(details, dict) else parsed


async def _invoke_voicecall_bra_gateway(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    timeout_ms: int = 10000,
) -> dict[str, Any]:
    return await asyncio.to_thread(
        _invoke_voicecall_bra_gateway_sync,
        method,
        params,
        timeout_ms=timeout_ms,
    )


async def _invoke_voicecall_bra_hermes(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    timeout_ms: int = 10000,
) -> dict[str, Any]:
    return await asyncio.to_thread(
        _invoke_voicecall_bra_hermes_sync,
        method,
        params,
        timeout_ms=timeout_ms,
    )


async def _invoke_voicecall_bra(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    timeout_ms: int = 10000,
) -> dict[str, Any]:
    config = _load_voicecall_bra_agent_config()
    provider = _normalize_voicecall_bra_agent_provider(config.get("numbuh_2x4_call_agent_provider"))
    if provider == VOICECALL_BRA_AGENT_PROVIDER_HERMES:
        return await _invoke_voicecall_bra_hermes(method, params, timeout_ms=timeout_ms)
    return await _invoke_voicecall_bra_gateway(method, params, timeout_ms=timeout_ms)


def _token_file_exists(approvals_dir: Path, token_name: str) -> bool:
    dashed = approvals_dir / token_name
    underscored = approvals_dir / token_name.replace("-", "_")
    return dashed.exists() or underscored.exists()


def _resolve_operator_ip(target_ip: str, operator_ips: list[str]) -> Optional[str]:
    """Match an operator IP to a target IP by /24 subnet."""
    try:
        if "/" in target_ip:
            target_net = ipaddress.ip_network(target_ip, strict=False)
        else:
            target_net = ipaddress.ip_network(f"{target_ip}/24", strict=False)
    except ValueError:
        return None

    for op_ip in operator_ips:
        try:
            op_addr = ipaddress.ip_address(op_ip)
            if op_addr in target_net:
                return op_ip
        except ValueError:
            continue
    return None


class EngageManager:
    """Manages agent lifecycle and WebSocket event distribution.

    One instance per server process. Multiple WebSocket clients can
    connect simultaneously — all receive broadcasts.
    """

    def __init__(self):
        self.runner = None  # AgentRunner instance when active
        self.session_id: Optional[str] = None
        self.state: str = "idle"  # idle | running | paused | awaiting_input | blocked
        self.ws_clients: set = set()
        self.history: list[dict] = []
        self.pending_approval: Optional[asyncio.Future] = None
        self._pending_blocked = None  # BlockedOperation when awaiting approval
        self._pending_approval_event: Optional[dict[str, Any]] = None
        self._pending_anon_map: Optional[dict[str, Any]] = None
        self._current_options: list[str] = []
        self._allow_override: bool = False
        self._agent_task: Optional[asyncio.Task] = None
        self._prior_approvals: dict[str, int] = {}
        self._overrides = None  # OverrideManager, lazy-loaded
        self._end_step_future: Optional[asyncio.Future] = None
        self._findings_filter_future: Optional[asyncio.Future] = None
        self._end_engagement_running: bool = False
        self._suppress_done_for_task: Optional[asyncio.Task] = None
        self._stop_in_progress: bool = False
        self._active_body_root: Optional[Path] = None
        self._proxy_sidecar: Optional[ProxySidecar] = None
        self._takeover_query_fn: Optional[Callable[[dict[str, Any]], Awaitable[str | dict[str, Any]]]] = None
        self.takeover_controller = get_takeover_controller()
        self.takeover_controller.set_runtime_hooks(
            query_fn=self._query_takeover_action,
            dispatch_fn=self._dispatch_takeover_action,
            notify_fn=self._broadcast_takeover_event,
        )
        _debug("manager_init")

    def set_takeover_query_fn(
        self,
        query_fn: Optional[Callable[[dict[str, Any]], Awaitable[str | dict[str, Any]]]],
    ) -> None:
        """Set runtime query hook for takeover decision generation (tests/integration)."""
        self._takeover_query_fn = query_fn

    async def _query_takeover_action(self, payload: dict[str, Any]) -> str | dict[str, Any]:
        if self._takeover_query_fn is None:
            return {"action": "none", "reason": "query_unavailable"}
        return await self._takeover_query_fn(payload)

    async def _dispatch_takeover_action(self, msg: dict[str, Any]) -> None:
        if not self._active_body_root:
            raise RuntimeError("BRA directory not configured")
        await route_message(self, msg, str(self._active_body_root))

    async def _broadcast_takeover_event(self, event: dict[str, Any]) -> None:
        await self.broadcast(event)

    def _set_active_body_root(self, bra_root: str | Path) -> Path:
        """Track current body root path for event log mirroring."""
        body_root, _ = _resolve_body_and_project_roots(bra_root)
        self._active_body_root = body_root
        return body_root

    def _is_token_active(self, token_name: str) -> bool:
        """Check whether an approval/governance token file is present."""
        if not self._active_body_root:
            return False
        approvals_dir = self._active_body_root / ".bra" / "approvals"
        return _token_file_exists(approvals_dir, token_name)

    def _sync_settings_root(self, bra_root: str | Path) -> None:
        """Align head runtime settings root with boots-selected BRA directory."""
        _sync_settings_root_for_path(bra_root)

    def _append_event_log(self, event: dict) -> None:
        """Mirror engage event stream into .bra/logs/engage.log for ops visibility."""
        if not self._active_body_root:
            return
        try:
            logs_dir = self._active_body_root / ".bra" / "logs"
            logs_dir.mkdir(parents=True, exist_ok=True)
            log_file = logs_dir / "engage.log"

            # Keep this compact and safe for large payloads.
            payload = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "type": str(event.get("type", "")),
            }
            for key in (
                "msg_type",
                "event_type",
                "action",
                "decision",
                "approval_type",
                "scope_level",
                "option",
                "status",
                "session_id",
                "call_id",
                "lease_id",
                "active",
                "suppress_chat_echo",
                "mode",
                "panel",
                "method",
                "method_name",
                "policy",
                "requested_decision",
                "enforced_decision",
                "repeat_count",
                "content",
                "command",
                "message",
                "reason",
                "severity",
                "tool_name",
                "tool_input",
                "target",
                "script",
                "script_path",
            ):
                if key in event and event.get(key) is not None:
                    value = str(event.get(key))
                    payload[key] = value if len(value) <= 2000 else value[:2000] + "... [truncated]"

            with log_file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, sort_keys=True) + "\n")
        except Exception:
            return

    async def broadcast(self, event: dict) -> None:
        """Send event to all connected WebSocket clients and append to history."""
        for key in ("content", "message", "delta"):
            if key in event and isinstance(event[key], str):
                event[key] = _unmask_output(event[key])

        _debug("broadcast", event_type=event.get("type", ""), clients=len(self.ws_clients))
        self.history.append(event)
        self._append_event_log(event)
        if len(self.history) > HISTORY_MAX:
            self.history = self.history[-HISTORY_MAX:]

        if self.takeover_controller is not None:
            try:
                await self.takeover_controller.on_engage_event(event)
            except Exception as exc:
                _debug(
                    "takeover_notify_error",
                    event_type=event.get("type", ""),
                    error=str(exc),
                )

        dead = set()
        for ws in list(self.ws_clients):  # snapshot: prevents RuntimeError if a client connects/disconnects during broadcast
            try:
                await ws.send_json(event)
            except Exception as _send_err:
                dead.add(ws)
                _debug("broadcast_send_failed", event_type=event.get("type", ""), error=str(_send_err))
        if dead:
            _debug("broadcast_dead_clients_removed", count=len(dead))
            self.ws_clients -= dead

    async def clear_history(self) -> None:
        """Clear all history events."""
        self.history.clear()
        _debug("clear_history")
        await self.broadcast({"type": "history_cleared"})

    def _resolve_overrides_md_path(self) -> Optional[Path]:
        """Resolve engagement OVERRIDES.md path from current override manager root."""
        if not self._overrides:
            return None
        try:
            bra_state = Path(self._overrides.bra_root)
            return bra_state.parent / "layer3-engagement" / "OVERRIDES.md"
        except Exception:
            return None

    def _record_override_decision(
        self,
        decision_type: str,
        subtype: str,
        decision: str,
        *,
        command: str = "",
        override_id: str | None = None,
    ) -> None:
        """Write structured decision history to engagement OVERRIDES.md."""
        if not self._overrides:
            return
        kwargs = {
            "command": command,
            "override_id": override_id,
        }
        overrides_md_path = self._resolve_overrides_md_path()
        if overrides_md_path is not None:
            kwargs["overrides_md_path"] = overrides_md_path
        self._overrides.record_decision(decision_type, subtype, decision, **kwargs)

    def _reconcile_state(self) -> None:
        """Self-heal stale in-memory state when no live agent activity exists."""
        has_live_task = bool(self._agent_task and not self._agent_task.done())
        runner_awaiting = bool(self.runner and getattr(self.runner, "awaiting_input", False))
        has_pending_approval = bool(self.pending_approval and not self.pending_approval.done())

        if self.pending_approval and self.pending_approval.done():
            self.pending_approval = None

        stale_running = self.state in {"running", "paused"} and not has_live_task and not runner_awaiting
        stale_blocked = self.state == "blocked" and not has_pending_approval and not has_live_task and not runner_awaiting
        stale_awaiting = self.state == "awaiting_input" and not runner_awaiting and not has_live_task

        if stale_running or stale_blocked or stale_awaiting:
            _debug(
                "reconcile_state_idle",
                prior_state=self.state,
                has_live_task=has_live_task,
                runner_awaiting=runner_awaiting,
                has_pending_approval=has_pending_approval,
            )
            self.state = "idle"
            self._current_options = []
            self._allow_override = False
            self._pending_blocked = None
            self._pending_approval_event = None
            self._pending_anon_map = None

    def get_state(self) -> dict:
        """Get current state snapshot for reconnection."""
        self._reconcile_state()
        try:
            scope_configured = is_scope_configured()
        except Exception:
            scope_configured = False
        _debug("get_state", status=self.state, session_id=self.session_id or "")
        return {
            "status": self.state,
            "session_id": self.session_id,
            "options": self._current_options,
            "allow_override": self._allow_override,
            "pending_approval": self._get_pending_approval_info(),
            "agent_running": self.state == "running",
            "awaiting_input": self.state == "awaiting_input",
            "scope_configured": scope_configured,
        }

    def _get_pending_approval_info(self) -> Optional[dict]:
        """Get serializable info about pending approval, if any."""
        if self._pending_approval_event:
            # Return a copy to avoid accidental mutation of server state.
            return dict(self._pending_approval_event)
        if not self._pending_blocked:
            return None
        # Keep reconnection payload shape identical to live approval events
        # so the frontend can always render/act on pending approvals.
        event = self._build_approval_event(self._pending_blocked)
        self._pending_approval_event = dict(event)
        return event

    def _get_masking_body_root(self) -> Optional[Path]:
        if self._active_body_root is not None:
            return self._active_body_root
        try:
            from bra.config.settings import get_bra_root

            bra_root = get_bra_root()
        except Exception:
            return None
        if not bra_root:
            return None
        body_root = Path(bra_root)
        candidate = body_root / "body"
        if candidate.is_dir():
            body_root = candidate
        self._active_body_root = body_root
        return body_root

    def _get_active_chat_token_for_body(self, body_root: Path) -> str:
        approvals_dir = body_root / ".bra" / "approvals"
        for token in ("MAP-SCAN", "ANON-SCAN", "LOCAL-SCAN", "NO-SCAN"):
            if (approvals_dir / token).exists():
                return token
        return "MAP-SCAN"

    def _ensure_override_history_manager(self, body_root: Path) -> None:
        if self._overrides is not None:
            return
        try:
            from bra.core.overrides import OverrideManager

            self._overrides = OverrideManager(body_root / ".bra")
        except Exception:
            self._overrides = None

    def _build_anon_map_approval_event(self) -> Optional[dict[str, Any]]:
        pending = self._pending_anon_map
        if not pending:
            return None
        idx = int(pending.get("index", 0))
        proposals = pending.get("proposals", [])
        if idx < 0 or idx >= len(proposals):
            return None
        proposal = proposals[idx]
        return {
            "type": "approval_anon_map",
            "reason": "ANON-SCAN detected a new value before sending upstream.",
            "command": pending.get("message", ""),
            "proposal_value": proposal.get("value", ""),
            "proposal_type": proposal.get("type", "operator-flagged"),
            "proposal_index": idx + 1,
            "proposal_total": len(proposals),
        }

    async def _dispatch_prepared_user_input(self, user_input: str) -> None:
        self.state = "running"
        await self._cancel_lingering_agent_task(reason="pre_turn_replace")
        await self._terminate_all_agent_subprocesses(reason="pre_turn", grace_s=0.25)
        await self.broadcast({"type": "streaming_start"})
        self._agent_task = asyncio.create_task(self.runner.continue_with_input(user_input))
        self._agent_task.add_done_callback(self._on_agent_done)

    async def _prepare_user_input_for_send(self, user_input: str) -> Optional[str]:
        body_root = self._get_masking_body_root()
        if body_root is None:
            return _mask_user_input(user_input)

        approvals_dir = body_root / ".bra" / "approvals"
        if (approvals_dir / "ANON-DISABLE").exists():
            return user_input

        chat_token = self._get_active_chat_token_for_body(body_root)
        if chat_token == "NO-SCAN":
            return user_input
        if chat_token == "LOCAL-SCAN":
            await self.broadcast({"type": "error", "message": "Local Mask is not available yet"})
            return None
        if chat_token != "ANON-SCAN":
            return _mask_user_input(user_input)

        try:
            from bra.anon.detect import detect_regex
            from bra.anon.mapping import AnonMap

            map_path = body_root / ".bra" / "anon_map.json"
            amap = AnonMap(map_path)
            detections = detect_regex(user_input)
            existing = {mapping["real"] for mapping in amap.all_mappings()}
            proposals = [
                {"value": detection.value, "type": detection.type_, "span": list(detection.span)}
                for detection in detections
                if detection.value not in existing
            ]
            if proposals:
                self._pending_blocked = None
                self._pending_anon_map = {
                    "body_root": str(body_root),
                    "message": user_input,
                    "proposals": proposals,
                    "index": 0,
                }
                self.pending_approval = asyncio.get_event_loop().create_future()
                self._pending_approval_event = self._build_anon_map_approval_event()
                self.state = "blocked"
                await self.broadcast(dict(self._pending_approval_event))
                return None
            return amap.mask(user_input)
        except Exception:
            return _mask_user_input(user_input)

    async def _resolve_anon_map_approval(self, result: dict) -> None:
        pending = self._pending_anon_map
        if not pending:
            return

        idx = int(pending.get("index", 0))
        proposals = pending.get("proposals", [])
        if idx < 0 or idx >= len(proposals):
            self.pending_approval = None
            self._pending_approval_event = None
            self._pending_anon_map = None
            return

        proposal = proposals[idx]
        decision = str(result.get("decision", "deny") or "deny").strip().lower()
        body_root = Path(str(pending.get("body_root", "")))
        message = str(pending.get("message", ""))
        from boots.main import append_override_history_entry

        if decision in {"mask", "mask_engagement"}:
            try:
                from bra.anon.mapping import AnonMap

                map_path = body_root / ".bra" / "anon_map.json"
                amap = AnonMap(map_path)
                source = "chat-input" if decision == "mask" else "chat-input-engagement"
                amap.add(proposal["value"], type_=proposal["type"], source=source)
                amap.save()
            except Exception:
                pass
            append_override_history_entry(
                body_root,
                decision_type="ANON_MAP",
                subtype=proposal["value"],
                decision="MASK" if decision == "mask" else "MASK FOR ENGAGEMENT",
                command=message,
            )
        else:
            append_override_history_entry(
                body_root,
                decision_type="ANON_MAP",
                subtype=proposal["value"],
                decision="DENIED",
                command=message,
            )

        idx += 1
        if idx < len(proposals):
            pending["index"] = idx
            self.pending_approval = asyncio.get_event_loop().create_future()
            self._pending_approval_event = self._build_anon_map_approval_event()
            self.state = "blocked"
            await self.broadcast(dict(self._pending_approval_event))
            return

        self.pending_approval = None
        self._pending_approval_event = None
        self._pending_anon_map = None
        prepared = _mask_user_input(message)
        await self._dispatch_prepared_user_input(prepared)

    async def _ensure_proxy_running(self) -> None:
        """Start proxy sidecar if proxy is enabled in config."""
        proxy_cfg = get_proxy_config()
        if not proxy_cfg["proxy_enabled"]:
            return

        if self._proxy_sidecar and self._proxy_sidecar.is_running:
            return

        bra_root = str(self._active_body_root) if self._active_body_root else None
        _proxy_debug(
            "sidecar_starting",
            bra_root=bra_root,
            backend_url=proxy_cfg["proxy_backend_url"],
            port=proxy_cfg["proxy_port"],
        )

        config_yaml = build_litellm_config(
            backend_url=proxy_cfg["proxy_backend_url"],
            backend_api_key=proxy_cfg["proxy_backend_api_key"],
            model_map=proxy_cfg["proxy_model_map"],
            port=proxy_cfg["proxy_port"],
            context_window=proxy_cfg["proxy_context_window"],
            max_completion_tokens=proxy_cfg["proxy_max_completion_tokens"],
        )
        bra_state = str(self._active_body_root / ".bra") if self._active_body_root else ""
        self._proxy_sidecar = ProxySidecar(
            port=proxy_cfg["proxy_port"],
            config_dir=bra_state,
        )
        await self.broadcast({
            "type": "proxy_starting",
            "backend_url": proxy_cfg["proxy_backend_url"],
            "port": proxy_cfg["proxy_port"],
        })
        result = await self._proxy_sidecar.start(config_yaml)
        if not result.ok:
            _proxy_debug(
                "sidecar_failed",
                bra_root=bra_root,
                error=result.error,
            )
            await self.broadcast({
                "type": "proxy_error",
                "error": result.error,
                "message": f"Proxy sidecar failed to start: {result.error}",
            })
            self._proxy_sidecar = None
        else:
            sidecar_pid = self._proxy_sidecar._process.pid if self._proxy_sidecar._process else None
            _proxy_debug(
                "sidecar_started",
                bra_root=bra_root,
                port=result.port,
                pid=sidecar_pid,
            )
            await self.broadcast({
                "type": "proxy_started",
                "port": result.port,
                "pid": sidecar_pid,
                "backend_url": proxy_cfg["proxy_backend_url"],
            })

    async def _prepare_runner(self, prompt: str, bra_root: str, model: Optional[str] = None) -> Optional[str]:
        """Set up the AgentRunner without starting a run.

        Returns the effective prompt on success, or None on failure.
        """
        if self.runner and self.state == "running":
            _debug("prepare_runner_skip_running", bra_root=bra_root)
            await self.broadcast({"type": "error", "message": "Agent already running"})
            return None

        api_key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
        body_root = self._set_active_body_root(bra_root)
        self._sync_settings_root(body_root)
        await self._ensure_proxy_running()

        _debug(
            "prepare_runner",
            bra_root=str(body_root),
            model=model or "",
            prompt_preview=prompt[:160],
            api_key_present=bool(api_key),
        )
        proxy_cfg = get_proxy_config()
        if not api_key and not proxy_cfg["proxy_enabled"]:
            self.state = "idle"
            await self.broadcast({
                "type": "error",
                "message": "ANTHROPIC_API_KEY is required. Engagement launch blocked.",
            })
            _debug("prepare_runner_fail_missing_api_key", bra_root=str(body_root))
            return None
        if not api_key and proxy_cfg["proxy_enabled"]:
            # Inject placeholder — the proxy handles actual auth to the backend.
            api_key = "proxy-routed"
            os.environ["ANTHROPIC_API_KEY"] = api_key
        os.environ["ANTHROPIC_API_KEY"] = api_key
        effective_prompt = prompt
        if "## Host Environment (Auto-Detected)" not in prompt:
            host_context = build_host_context_block().strip()
            if host_context:
                effective_prompt = f"{prompt.rstrip()}\n\n{host_context}"
                _debug(
                    "host_context_appended",
                    bra_root=str(body_root),
                    host_context_chars=len(host_context),
                )

        from bra.core.runner import AgentRunner
        from bra.core.overrides import OverrideManager

        root = body_root
        notes_dir = root / "layer3-engagement" / "NOTES"

        self._overrides = OverrideManager(root / ".bra")

        self.runner = AgentRunner(
            notes_dir=str(notes_dir) if notes_dir.exists() else None,
            model=model,
            on_text=lambda t: asyncio.ensure_future(self.broadcast({"type": "text", "content": t})),
            on_command=lambda c: asyncio.ensure_future(self.broadcast({"type": "command", "command": c})),
            on_output=lambda o: asyncio.ensure_future(self.broadcast({"type": "output", "content": o})),
            on_finding=lambda s, m: asyncio.ensure_future(self.broadcast({"type": "finding", "severity": s, "message": m})),
            on_lead=lambda m: asyncio.ensure_future(self.broadcast({"type": "lead", "message": m})),
            on_service=lambda p, st, sv, v, src: asyncio.ensure_future(self.broadcast({"type": "service", "port": p, "state": st, "service": sv, "version": v, "source": src})),
            on_endpoint=lambda pa, m, f, r, s, src: asyncio.ensure_future(self.broadcast({"type": "endpoint", "path": pa, "method": m, "function": f, "risk": r, "status": s, "source": src})),
            on_target=lambda p, v, src: asyncio.ensure_future(self.broadcast({"type": "target", "property": p, "value": v, "source": src})),
            on_suggestion=lambda d, p, r: asyncio.ensure_future(self.broadcast({"type": "suggestion", "description": d, "priority": p, "rationale": r})),
            on_options=self._on_options,
            on_error=lambda e: asyncio.ensure_future(self.broadcast({"type": "error", "message": e})),
            on_turn_complete=self._on_turn_complete,
            on_blocked_operation=self._handle_blocked_operation,
        )

        self.state = "running"
        _debug("prepare_runner_created", bra_root=str(body_root))
        return effective_prompt

    async def start_agent(self, prompt: str, bra_root: str, model: Optional[str] = None) -> None:
        """Start a new agent session.

        Args:
            prompt: Initial prompt
            bra_root: Path to BRA body root
            model: Optional model override
        """
        _debug(
            "start_agent",
            bra_root=bra_root,
            model=model or "",
            prompt_preview=prompt[:160],
        )
        effective_prompt = await self._prepare_runner(prompt, bra_root, model)
        if effective_prompt is None:
            return

        await self._cancel_lingering_agent_task(reason="pre_start_replace")
        await self._terminate_all_agent_subprocesses(reason="pre_start", grace_s=0.25)
        await self.broadcast({"type": "streaming_start"})

        self._agent_task = asyncio.create_task(self.runner.run(effective_prompt))
        self._agent_task.add_done_callback(self._on_agent_done)
        _debug("start_agent_task_started", bra_root=bra_root)

    async def resume_agent(self, bra_root: str, session_id: Optional[str] = None,
                           prompt: Optional[str] = None, model: Optional[str] = None) -> None:
        """Resume an existing agent session.

        Creates a fresh runner and starts it with resume_session so the
        LLM picks up from the previous conversation.  Unlike the old
        implementation this does NOT start a throwaway fresh run first,
        which previously left orphan subprocesses that could produce
        ghost output.
        """
        from bra.core.bridge import get_active_session

        sid = session_id or get_active_session()
        if not sid:
            _debug("resume_agent_fail_no_session", bra_root=bra_root)
            await self.broadcast({"type": "error", "message": "No active session to resume"})
            return

        self.session_id = sid
        effective_prompt = prompt or "Continue."
        _debug("resume_agent_start", bra_root=bra_root, session_id=sid, model=model or "",
               prompt_preview=effective_prompt[:160])

        prepared = await self._prepare_runner(effective_prompt, bra_root, model)
        if prepared is None:
            return

        await self._cancel_lingering_agent_task(reason="pre_resume_replace")
        await self._terminate_all_agent_subprocesses(reason="pre_resume", grace_s=0.25)
        await self.broadcast({"type": "streaming_start"})

        self._agent_task = asyncio.create_task(
            self.runner.run(prepared, resume_session=sid)
        )
        self._agent_task.add_done_callback(self._on_agent_done)
        _debug("resume_agent_task_started", bra_root=bra_root, session_id=sid)

    def _on_options(self, items: list[str]) -> None:
        """Handle options from agent."""
        capped = list(items[:4])
        self._current_options = capped
        _debug("on_options", count=len(capped), raw_count=len(items))
        self._allow_override = False
        asyncio.ensure_future(self.broadcast({
            "type": "options",
            "items": capped,
            "allow_override": False,
        }))

    def _on_turn_complete(self) -> None:
        """Handle turn completion."""
        _debug("on_turn_complete", has_runner=bool(self.runner), session_id=self.runner.session_id if self.runner else "")
        if self.runner and self.runner.session_id:
            self.session_id = self.runner.session_id
            try:
                update_session_state(
                    session_id=self.runner.session_id,
                    status="in_progress",
                    update_turn=True,
                )
            except Exception:
                logger.exception("Failed to update pipeline session state on turn completion")
        self.state = "awaiting_input"
        asyncio.ensure_future(self.broadcast({"type": "streaming_stop"}))
        asyncio.ensure_future(self.broadcast({"type": "turn_complete"}))

    async def _handle_blocked_operation(self, blocked) -> bool:
        """Handle a blocked operation — broadcast to clients and await response.

        Args:
            blocked: BlockedOperation from the runner

        Returns:
            True if approved and retry should proceed
        """
        from bra.core.approval import ApprovalType
        _debug(
            "blocked_operation",
            approval_type=blocked.approval_type.value if hasattr(blocked.approval_type, "value") else str(blocked.approval_type),
            token_name=blocked.token_name or "",
            target=blocked.target or "",
            tool_name=blocked.tool_name or "",
            script_path=blocked.script_path or "",
            command=blocked.command or "",
        )

        # Auto-approve built-in layer1 scripts — they are framework internals.
        if blocked.approval_type == ApprovalType.SCRIPT:
            sp = blocked.script_path or ""
            if sp.startswith("./layer1/") or sp.startswith("layer1/"):
                approved = await self.runner.handle_approval_result(blocked, True)
                if approved:
                    _debug("blocked_operation_layer1_auto", script_path=sp)
                    await self.broadcast({
                        "type": "script_passthrough",
                        "script_path": sp,
                        "command": blocked.command or "",
                    })
                    await self.runner.retry_blocked_operation(blocked)
                    return True

        # Check override rules first
        if self._overrides:
            match = self._overrides.match(blocked)
            if match:
                approved = await self.runner.handle_approval_result(blocked, True)
                if approved:
                    _debug("blocked_operation_override_auto", override_id=match.get("id", ""))
                    await self.broadcast({
                        "type": "override_auto",
                        "override_id": match.get("id", ""),
                        "approval_type": blocked.approval_type.value,
                        "command": blocked.command or "",
                    })
                    await self.runner.retry_blocked_operation(blocked)
                    return True

        self._pending_blocked = blocked
        self.state = "blocked"

        event = self._build_approval_event(blocked)

        # Build a key for repeat-approval tracking
        _repeat_key_map = {
            ApprovalType.TOKEN: f"TOKEN:{blocked.token_name or ''}",
            ApprovalType.SCOPE_ADD: f"SCOPE_ADD:{blocked.target or ''}",
            ApprovalType.SCOPE_UPGRADE: f"SCOPE_UPGRADE:{blocked.target or ''}",
            ApprovalType.SCRIPT: f"SCRIPT:{blocked.script_path or ''}",
            ApprovalType.TOOL: f"TOOL:{blocked.tool_name or ''}",
        }
        repeat_key = _repeat_key_map.get(blocked.approval_type)
        if repeat_key:
            count = self._prior_approvals.get(repeat_key, 0)
            if count > 0:
                event["repeat_count"] = count

        self._pending_approval_event = dict(event)
        self.pending_approval = asyncio.get_event_loop().create_future()
        await self.broadcast(event)

        # Wait for approval with periodic rebroadcast.  If the original
        # WebSocket event was lost (disconnect/reconnect, network hiccup),
        # rebroadcasting every 15s ensures the frontend eventually sees it.
        _REBROADCAST_INTERVAL = 15.0
        while True:
            try:
                result = await asyncio.wait_for(
                    asyncio.shield(self.pending_approval),
                    timeout=_REBROADCAST_INTERVAL,
                )
                break
            except asyncio.TimeoutError:
                if self.pending_approval.done():
                    result = self.pending_approval.result()
                    break
                _debug("approval_rebroadcast", approval_type=blocked.approval_type.value)
                await self.broadcast(event)

        _debug("blocked_operation_resolution", result=result)
        self.pending_approval = None
        self._pending_blocked = None
        self._pending_approval_event = None

        return await self._process_approval_result(blocked, result)

    def _build_approval_event(self, blocked) -> dict:
        """Build the WebSocket event for an approval request."""
        from bra.core.approval import ApprovalType

        base = {"command": blocked.command or "", "reason": blocked.reason or ""}

        if blocked.approval_type == ApprovalType.TOKEN:
            return _with_approval_anon_highlights({**base, "type": "approval_token", "token_name": blocked.token_name or ""})
        elif blocked.approval_type == ApprovalType.SCOPE_ADD:
            return _with_approval_anon_highlights({**base, "type": "approval_scope_add", "target": blocked.target or ""})
        elif blocked.approval_type == ApprovalType.SCOPE_UPGRADE:
            return _with_approval_anon_highlights({**base, "type": "approval_scope_upgrade",
                    "target": blocked.target or "",
                    "current_level": blocked.current_level or ""})
        elif blocked.approval_type == ApprovalType.SCRIPT:
            return _with_approval_anon_highlights({**base, "type": "approval_script",
                    "script_path": blocked.script_path or "",
                    "script_content": blocked.script_content or ""})
        elif blocked.approval_type == ApprovalType.TOOL:
            return _with_approval_anon_highlights({**base, "type": "approval_tool",
                    "tool_name": blocked.tool_name or "",
                    "tool_input": blocked.tool_input or {},
                    "tool_use_id": blocked.tool_use_id or ""})
        return _with_approval_anon_highlights({**base, "type": "approval_unknown"})

    async def _process_approval_result(self, blocked, result: dict) -> bool:
        """Process an approval decision from the operator."""
        from bra.core.approval import ApprovalType
        _debug("process_approval_result_start", result=result)

        decision = result.get("decision", "deny")
        decision_type = blocked.approval_type.value.upper() if hasattr(blocked.approval_type, "value") else "UNKNOWN"
        subtype = "unknown"
        if blocked.approval_type == ApprovalType.TOKEN:
            subtype = blocked.token_name or "UNKNOWN"
        elif blocked.approval_type in (ApprovalType.SCOPE_ADD, ApprovalType.SCOPE_UPGRADE):
            subtype = blocked.target or "unknown"
        elif blocked.approval_type == ApprovalType.SCRIPT:
            subtype = blocked.script_path or "unknown"
        elif blocked.approval_type == ApprovalType.TOOL:
            subtype = blocked.tool_name or "unknown"

        audit_decision = "APPROVED"
        override_id = None
        approved = True
        scope_level = None
        one_time = False

        if decision == "deny":
            audit_decision = "DENIED"
            self._record_override_decision(
                decision_type,
                subtype,
                audit_decision,
                command=blocked.command or "",
            )
            if self.runner:
                # Operator denied this action: immediately return to normal
                # selection loop so the session can continue without retrying
                # the denied command.
                self.runner.transition_to_awaiting_input(
                    options=[
                        "Continue with your proposed next step",
                        "Ask a clarifying question before continuing",
                        "Show alternative approaches",
                        "Something else",
                    ]
                )
            self.state = "awaiting_input"
            _debug("process_approval_result_denied", decision_type=decision_type, subtype=subtype)
            return False

        if blocked.approval_type == ApprovalType.TOKEN:
            one_time = decision == "grant_once"
            if decision == "grant_engagement" and self._overrides:
                override_id = self._overrides.add("TOKEN", {"token": blocked.token_name}, "grant_session", "3")
                audit_decision = "APPROVED FOR ENGAGEMENT"
            elif decision == "grant_once":
                audit_decision = "APPROVED ONCE"
            elif decision == "grant_session":
                audit_decision = "APPROVED (SESSION)"

        elif blocked.approval_type in (ApprovalType.SCOPE_ADD, ApprovalType.SCOPE_UPGRADE):
            scope_level = (result.get("scope_level") or decision or "").upper()
            if decision == "upgrade_engagement" and self._overrides:
                override_id = self._overrides.add("SCOPE_UPGRADE", {}, "FULL", "3")
                scope_level = "FULL"
                audit_decision = "APPROVED FOR ENGAGEMENT (FULL)"
            elif decision == "suggest":
                # Operator is suggesting custom guidance — approve as LIMITED
                # and attach the message for the retry prompt
                scope_level = "LIMITED"
                message = (result.get("message") or "").strip()
                if message:
                    blocked._approval_message = message
            elif blocked.approval_type == ApprovalType.SCOPE_UPGRADE and decision in ("upgrade", "full"):
                scope_level = "FULL"

            if scope_level and "APPROVED FOR ENGAGEMENT" not in audit_decision:
                audit_decision = f"APPROVED ({scope_level})"

        elif blocked.approval_type == ApprovalType.SCRIPT:
            if decision == "approve_engagement" and self._overrides:
                override_id = self._overrides.add("SCRIPT", {}, "allow", "3")
                audit_decision = "APPROVED FOR ENGAGEMENT"
            elif decision == "approve_once":
                audit_decision = "APPROVED ONCE"

        elif blocked.approval_type == ApprovalType.TOOL:
            if decision in ("allow_override",) and self._overrides:
                match = {"tool_name": blocked.tool_name}
                if blocked.command:
                    match["command"] = blocked.command
                else:
                    # Refuse blanket TOOL overrides — a tool override without a
                    # command would auto-approve every invocation of that tool
                    # (e.g. every Bash command for the rest of the engagement).
                    _debug("blocked_blanket_tool_override", tool_name=blocked.tool_name)
                    one_time = True
                    audit_decision = "APPROVED ONCE (blanket override refused)"
                    override_id = None
                if not one_time:
                    override_id = self._overrides.add("TOOL", match, "allow", "3")
                    audit_decision = "APPROVED FOR ENGAGEMENT"
            elif decision == "allow_once":
                one_time = True
                audit_decision = "APPROVED ONCE"

        # Track repeat approvals for all types
        _repeat_key_map = {
            ApprovalType.TOKEN: f"TOKEN:{blocked.token_name or ''}",
            ApprovalType.SCOPE_ADD: f"SCOPE_ADD:{blocked.target or ''}",
            ApprovalType.SCOPE_UPGRADE: f"SCOPE_UPGRADE:{blocked.target or ''}",
            ApprovalType.SCRIPT: f"SCRIPT:{blocked.script_path or ''}",
            ApprovalType.TOOL: f"TOOL:{blocked.tool_name or ''}",
        }
        repeat_key = _repeat_key_map.get(blocked.approval_type)
        if repeat_key:
            self._prior_approvals[repeat_key] = self._prior_approvals.get(repeat_key, 0) + 1

        # Attach approved scope level so retry message includes it
        if scope_level:
            blocked._approved_scope_level = scope_level

        # Attach operator message for retry context
        approval_message = (result.get("message") or "").strip()
        if approval_message:
            blocked._approval_message = approval_message

        granted = await self.runner.handle_approval_result(
            blocked, approved, scope_level=scope_level, one_time=one_time
        )
        _debug("process_approval_result_runner", granted=granted, decision=decision)

        self._record_override_decision(
            decision_type,
            subtype,
            audit_decision,
            command=blocked.command or "",
            override_id=override_id,
        )

        if granted:
            self.state = "running"
            await self._terminate_all_agent_subprocesses(reason="pre_retry", grace_s=0.25)
            if blocked.approval_type in (ApprovalType.SCOPE_ADD, ApprovalType.SCOPE_UPGRADE):
                approved_level = scope_level or getattr(blocked, "_approved_scope_level", None) or "APPROVED"
                target_label = blocked.target or "the target"
                resume_message = (
                    f"The target {target_label} is now approved at {approved_level} scope. "
                    "Do not rerun approve-target.py. Continue with your next step using the updated scope."
                )
                await self.runner.continue_with_input(resume_message)
                return True
            await self.runner.retry_blocked_operation(blocked)
            return True

        self.state = "running"
        return False

    async def select_option(
        self,
        option: int,
        message: Optional[str] = None,
        force_override: bool = False,
        suppress_echo: bool = False,
    ) -> None:
        """Handle option selection from the browser."""
        _debug("select_option", option=option, has_message=bool(message), force_override=force_override)
        if self.pending_approval and not self.pending_approval.done():
            await self.broadcast({
                "type": "error",
                "message": "Resolve pending approval before selecting an option.",
            })
            state = self.get_state()
            if state.get("pending_approval"):
                await self.broadcast({"type": "state", **state})
            return

        if not self.runner or not self.runner.awaiting_input:
            return

        selected = self.runner.select_option(option)
        if not selected:
            return

        user_input = selected
        if message:
            user_input = f"{selected}\n\nAdditional context: {message}"

        if force_override and self._overrides and self._pending_blocked:
            pass

        if not suppress_echo:
            await self.broadcast({"type": "text", "content": f"[user]{user_input}[/user]"})
        prepared = await self._prepare_user_input_for_send(user_input)
        if prepared is None:
            return
        await self._dispatch_prepared_user_input(prepared)

    async def continue_with_message(self, message: str, suppress_echo: bool = False) -> None:
        """Continue an existing awaiting-input turn with freeform text."""
        _debug("continue_with_message", message_preview=(message or "")[:160])
        if self.pending_approval and not self.pending_approval.done():
            await self.broadcast({
                "type": "error",
                "message": "Resolve pending approval before sending input.",
            })
            state = self.get_state()
            if state.get("pending_approval"):
                await self.broadcast({"type": "state", **state})
            return

        if not self.runner or not self.runner.awaiting_input:
            return

        user_input = (message or "").strip()
        if not user_input:
            return

        if not suppress_echo:
            await self.broadcast({"type": "text", "content": f"[user]{user_input}[/user]"})
        prepared = await self._prepare_user_input_for_send(user_input)
        if prepared is None:
            return
        await self._dispatch_prepared_user_input(prepared)

    async def debug_message_to_session(self, message: str, suppress_echo: bool = False) -> None:
        """Send a debug message into the current open session.

        Guarded by BRA-DEBUG token and session/open-turn checks.
        """
        user_input = (message or "").strip()
        _debug("debug_message_to_session", message_preview=user_input[:160])
        if not user_input:
            return

        if not self._is_token_active("BRA-DEBUG"):
            await self.broadcast({
                "type": "error",
                "message": "BRA-DEBUG token required for debug session messages.",
            })
            return

        if not self.runner:
            await self.broadcast({"type": "error", "message": "No active agent runner."})
            return

        sid = (self.runner.session_id or self.session_id or "").strip()
        if not sid:
            await self.broadcast({
                "type": "error",
                "message": "No open session to message. Start or resume engagement first.",
            })
            return

        if self.pending_approval and not self.pending_approval.done():
            await self.broadcast({
                "type": "error",
                "message": "Resolve pending approval before sending debug message.",
            })
            return

        has_live_task = bool(self._agent_task and not self._agent_task.done())
        runner_awaiting = bool(getattr(self.runner, "awaiting_input", False))
        if has_live_task and not runner_awaiting:
            await self.broadcast({
                "type": "error",
                "message": "Agent is currently busy. Wait for turn completion before debug message.",
            })
            return

        if not suppress_echo:
            await self.broadcast({"type": "text", "content": f"[user]{user_input}[/user]"})
        user_input = _mask_user_input(user_input)
        self.state = "running"
        await self._cancel_lingering_agent_task(reason="pre_debug_turn_replace")
        await self._terminate_all_agent_subprocesses(reason="pre_debug_turn", grace_s=0.25)
        await self.broadcast({"type": "streaming_start"})

        if runner_awaiting:
            self._agent_task = asyncio.create_task(self.runner.continue_with_input(user_input))
        else:
            # Session is open but currently idle (no live turn).
            self._agent_task = asyncio.create_task(self.runner.run(user_input, resume_session=sid))
        self._agent_task.add_done_callback(self._on_agent_done)

    async def resolve_approval(self, result: dict) -> None:
        """Resolve a pending approval from the browser."""
        _debug("resolve_approval", result=result)
        if self._pending_anon_map is not None:
            await self._resolve_anon_map_approval(result)
            return
        if self.pending_approval and not self.pending_approval.done():
            self.pending_approval.set_result(result)

    async def _cancel_lingering_agent_task(self, *, reason: str, timeout_s: float = 2.0) -> None:
        """Cancel a stale in-flight agent task before launching a replacement turn."""
        task = self._agent_task
        if not task or task.done():
            return

        current = asyncio.current_task()
        if task is current:
            _debug("cancel_lingering_agent_task_skip_current", reason=reason)
            return

        _debug("cancel_lingering_agent_task_start", reason=reason)
        self._suppress_done_for_task = task
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=timeout_s)
        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError:
            _debug("cancel_lingering_agent_task_timeout", reason=reason, timeout_s=timeout_s)
        except Exception as exc:
            exc_text = str(exc)
            if _is_sigterm_noise(exc_text):
                _debug("cancel_lingering_agent_task_sigterm_suppressed", reason=reason)
            else:
                _debug("cancel_lingering_agent_task_error", reason=reason, error=exc_text)

        if self._agent_task is task:
            self._agent_task = None

    async def stop_agent(self, cancel_timeout_s: float = 5.0) -> None:
        """Stop the running agent and await task teardown."""
        _debug(
            "stop_agent",
            has_runner=bool(self.runner),
            has_task=bool(self._agent_task),
            task_done=(self._agent_task.done() if self._agent_task else True),
        )
        # Guard re-entrancy: multiple clients may send stop simultaneously.
        if self._stop_in_progress:
            _debug("stop_agent_already_in_progress")
            return
        # Nothing to stop.
        if not self._agent_task or self._agent_task.done():
            if self.state == "idle":
                _debug("stop_agent_already_idle")
                return

        self._stop_in_progress = True
        # Broadcast immediately so all clients see feedback before the cancellation wait.
        await self.broadcast({"type": "stopping"})
        try:
            await self._do_stop_agent(cancel_timeout_s)
        finally:
            self._stop_in_progress = False

    async def _do_stop_agent(self, cancel_timeout_s: float = 5.0) -> None:
        """Internal stop implementation after re-entrancy check."""
        # Mark runner stopped before task cancellation so runtime SIGTERM
        # teardown does not surface as user-facing "agent error" noise.
        if self.runner:
            self.runner.stop()
        task = self._agent_task
        if task:
            # Avoid duplicate "agent_stopped" broadcasts from done-callback after manual stop.
            self._suppress_done_for_task = task
        if task and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=cancel_timeout_s)
            except asyncio.CancelledError:
                pass
            except asyncio.TimeoutError:
                _debug("stop_agent_cancel_timeout", timeout_s=cancel_timeout_s)
            except Exception as exc:
                _debug("stop_agent_cancel_error", error=str(exc))

        self._agent_task = None

        # Hard-stop any stray SDK subprocesses so stop/reset/kill cover
        # all live agent workers, not only the tracked _agent_task.
        terminated = await self._terminate_all_agent_subprocesses(reason="stop_agent")
        if terminated:
            _debug("stop_agent_subprocesses_terminated", count=len(terminated), pids=terminated)

        if self._proxy_sidecar:
            _proxy_debug("sidecar_stopping")
            await self.broadcast({"type": "proxy_stopped"})
            self._proxy_sidecar.stop()
            self._proxy_sidecar = None

        self._current_options = []
        self._allow_override = False
        self._pending_blocked = None
        self._pending_approval_event = None
        if self.pending_approval and not self.pending_approval.done():
            self.pending_approval.cancel()
        self.pending_approval = None
        self.state = "idle"
        await self.broadcast({"type": "agent_stopped", "reason": "stopped"})

    def pause_agent(self) -> None:
        """Toggle pause/resume."""
        pids = self._list_agent_subprocess_pids()
        _debug("pause_agent_toggle", has_runner=bool(self.runner), subprocess_count=len(pids))
        if not self.runner and not pids:
            return

        is_paused = bool((self.runner and self.runner.is_paused) or self.state == "paused")
        if is_paused:
            if self.runner:
                self.runner.resume()
            if pids:
                self._signal_agent_subprocesses(signal.SIGCONT, pids=pids, reason="resume")
            has_live_task = bool(self._agent_task and not self._agent_task.done())
            self.state = "running" if (has_live_task or pids) else "idle"
            asyncio.ensure_future(self.broadcast({"type": "agent_resumed"}))
            return

        if self.runner:
            self.runner.pause()
        if pids:
            self._signal_agent_subprocesses(signal.SIGSTOP, pids=pids, reason="pause")
        self.state = "paused"
        asyncio.ensure_future(self.broadcast({"type": "agent_paused"}))

    def _list_agent_subprocess_pids(self) -> list[int]:
        """List Claude SDK subprocess PIDs that belong to this server process tree."""
        try:
            output = subprocess.check_output(
                ["ps", "-Ao", "pid=,ppid=,command="],
                text=True,
            )
        except Exception as exc:
            _debug("agent_subprocess_scan_error", error=str(exc))
            return []

        parent_by_pid: dict[int, int] = {}
        command_by_pid: dict[int, str] = {}
        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            pid_text, ppid_text = parts[0], parts[1]
            if not (pid_text.isdigit() and ppid_text.isdigit()):
                continue
            pid = int(pid_text)
            ppid = int(ppid_text)
            command = parts[2] if len(parts) > 2 else ""
            parent_by_pid[pid] = ppid
            command_by_pid[pid] = command

        server_pid = os.getpid()

        def _is_descendant_of_server(pid: int) -> bool:
            visited: set[int] = set()
            current = pid
            while current not in visited:
                visited.add(current)
                parent = parent_by_pid.get(current)
                if parent is None:
                    return False
                if parent == server_pid:
                    return True
                if parent <= 1:
                    return False
                current = parent
            return False

        matches: list[int] = []
        for pid, command in command_by_pid.items():
            normalized = command.lower()
            if "claude_agent_sdk/_bundled/claude" not in normalized:
                continue
            if _is_descendant_of_server(pid):
                matches.append(pid)

        return sorted(set(matches))

    def _signal_agent_subprocesses(
        self,
        sig: signal.Signals,
        *,
        pids: Optional[list[int]] = None,
        reason: str = "",
    ) -> list[int]:
        """Send a UNIX signal to tracked Claude SDK subprocesses."""
        targets = list(pids or self._list_agent_subprocess_pids())
        signaled: list[int] = []
        for pid in targets:
            try:
                os.kill(pid, int(sig))
                signaled.append(pid)
            except ProcessLookupError:
                continue
            except Exception as exc:
                _debug("agent_subprocess_signal_error", pid=pid, signal=int(sig), error=str(exc), reason=reason)
        if signaled:
            _debug("agent_subprocess_signaled", signal=int(sig), count=len(signaled), pids=signaled, reason=reason)
        return signaled

    async def _terminate_all_agent_subprocesses(self, *, reason: str, grace_s: float = 0.75) -> list[int]:
        """Terminate all Claude SDK subprocesses for this server process tree."""
        initial = self._list_agent_subprocess_pids()
        if not initial:
            return []

        terminated = self._signal_agent_subprocesses(signal.SIGTERM, pids=initial, reason=reason)
        if terminated and grace_s > 0:
            await asyncio.sleep(grace_s)

        survivors: list[int] = []
        for pid in terminated:
            try:
                os.kill(pid, 0)
                survivors.append(pid)
            except ProcessLookupError:
                continue
            except Exception:
                survivors.append(pid)

        if survivors:
            self._signal_agent_subprocesses(signal.SIGKILL, pids=survivors, reason=f"{reason}_force")
            await asyncio.sleep(0.1)
            still_alive: list[int] = []
            for pid in survivors:
                try:
                    os.kill(pid, 0)
                    still_alive.append(pid)
                except ProcessLookupError:
                    continue
                except Exception:
                    still_alive.append(pid)
            if still_alive:
                _debug("agent_subprocess_sigkill_survivors", pids=still_alive, reason=reason)
        return terminated

    async def _deferred_subprocess_cleanup(self, grace_s: float = 150.0) -> None:
        """Wait for findings subagent to finish, then clean up stragglers.

        Called instead of immediate termination when the findings subagent is
        active.  Polls every 5s — if the subagent finishes early, cleanup
        runs immediately.  If it's still active after *grace_s*, force-kills
        and triggers handoff to the main agent (the runner already has a
        120s stall-check that sets ``_findings_handoff_required``; this is
        the outer safety net in case that mechanism doesn't fire).
        """
        elapsed = 0.0
        poll_interval = 5.0
        while elapsed < grace_s:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
            still_active = (
                self.runner
                and getattr(self.runner, "_findings_subagent_active", False)
            )
            if not still_active:
                _debug("deferred_cleanup_subagent_finished", elapsed=elapsed)
                break
        else:
            _debug("deferred_cleanup_grace_expired", grace_s=grace_s)
            # Signal the runner to hand remaining findings to the main agent
            if self.runner and getattr(self.runner, "_findings_subagent_active", False):
                self.runner._findings_handoff_required = True

        # Sweep any leftover SDK subprocesses
        remaining = self._list_agent_subprocess_pids()
        if remaining:
            await self._terminate_all_agent_subprocesses(reason="deferred_cleanup")

    def toggle_kill_switch(self, bra_root: str) -> bool:
        """Toggle the kill switch file. Returns new state (True=active)."""
        _debug("toggle_kill_switch_start", bra_root=bra_root)
        stop_file = _body_root(bra_root) / ".bra" / "STOP"
        if stop_file.exists():
            stop_file.unlink()
            _debug("toggle_kill_switch_result", bra_root=bra_root, active=False)
            return False
        else:
            stop_file.parent.mkdir(parents=True, exist_ok=True)
            stop_file.write_text("STOP")
            _debug("toggle_kill_switch_result", bra_root=bra_root, active=True)
            return True

    def _on_agent_done(self, task: asyncio.Task) -> None:
        """Callback when agent task completes."""
        if self._suppress_done_for_task is task:
            self._suppress_done_for_task = None
            return
        _debug("agent_done_callback")
        if self.runner and self.runner.session_id:
            self.session_id = self.runner.session_id
            try:
                update_session_state(
                    session_id=self.runner.session_id,
                    status="in_progress",
                    update_turn=True,
                )
            except Exception:
                logger.exception("Failed to update pipeline session state on agent completion")
        # Clean up SDK subprocesses that the runner spawned. The SDK's
        # transport.close() sends SIGTERM but some processes survive it —
        # this sweep adds a SIGKILL fallback.
        # When the findings subagent is active, defer termination to give
        # it time to finish (typically completes in <40s). A delayed
        # safety-net sweep fires after FINDINGS_SUBAGENT_GRACE_S to kill
        # any stuck subagent that would otherwise waste API tokens.
        findings_subagent_alive = (
            self.runner
            and getattr(self.runner, "_findings_subagent_active", False)
        )
        if findings_subagent_alive:
            # Scale grace period by pending findings count (~45s each + buffer)
            pending_count = 0
            enforcer = getattr(self.runner, "_finding_enforcer", None)
            if enforcer:
                pending_count = len(getattr(enforcer, "pending_queue", []))
            grace = max(150.0, pending_count * 60.0)
            asyncio.ensure_future(
                self._deferred_subprocess_cleanup(grace_s=grace)
            )
        else:
            asyncio.ensure_future(self._terminate_all_agent_subprocesses(reason="agent_done"))
        # If runner is awaiting input, this is a normal turn completion — don't
        # set idle or broadcast agent_stopped. The frontend already got
        # turn_complete and is showing options.
        if self.runner and self.runner.awaiting_input:
            self.state = "awaiting_input"
            return
        self.state = "idle"
        try:
            exc = task.exception()
            if exc:
                exc_text = str(exc)
                # Suppress expected SIGTERM noise from subprocess cleanup
                # between turns — exit code -15 is always our own teardown.
                if _is_sigterm_noise(exc_text):
                    _debug("agent_done_sigterm_suppressed", error=exc_text)
                else:
                    asyncio.ensure_future(self.broadcast({
                        "type": "agent_stopped",
                        "reason": "error",
                        "message": exc_text,
                    }))
            else:
                asyncio.ensure_future(self.broadcast({
                    "type": "agent_stopped",
                    "reason": "completed",
                }))
        except asyncio.CancelledError:
            asyncio.ensure_future(self.broadcast({
                "type": "agent_stopped",
                "reason": "cancelled",
            }))


async def route_message(
    mgr: EngageManager,
    msg: dict,
    bra_root: str,
    websocket: Any | None = None,
) -> None:
    """Route an incoming WebSocket message to the appropriate manager method.

    Args:
        mgr: The EngageManager singleton
        msg: Parsed JSON message from the client
        bra_root: Path to BRA body root
    """
    msg_type = msg.get("type", "")

    # Fast-path: keepalive ping — no logging, no state sync
    if msg_type == "ping":
        if websocket is not None:
            try:
                await websocket.send_json({"type": "pong"})
            except Exception:
                pass
        return

    suppress_chat_echo = bool(msg.get("suppress_chat_echo"))
    mgr._set_active_body_root(bra_root)
    mgr._sync_settings_root(bra_root)
    _debug("route_message", bra_root=bra_root, msg_type=msg_type)
    mgr._append_event_log(
        {
            "type": "client_action",
            "msg_type": msg_type,
            "message": msg.get("message"),
            "decision": msg.get("decision"),
            "option": msg.get("option"),
            "scope_level": msg.get("scope_level"),
            "call_id": msg.get("call_id") or msg.get("callId"),
            "panel": msg.get("panel"),
            "mode": msg.get("mode"),
            "session_id": msg.get("session_id"),
            "suppress_chat_echo": suppress_chat_echo,
        }
    )

    # Agent control
    if msg_type == "start":
        await mgr.start_agent(msg.get("prompt", ""), bra_root, msg.get("model"))
    elif msg_type == "resume":
        await mgr.resume_agent(bra_root, msg.get("session_id"), msg.get("prompt"), msg.get("model"))
    elif msg_type == "stop":
        await mgr.stop_agent()
    elif msg_type == "pause":
        mgr.pause_agent()
    elif msg_type == "kill":
        active = mgr.toggle_kill_switch(bra_root)
        if active:
            await mgr.stop_agent()
        await mgr.broadcast({"type": "kill_switch", "active": active})
    elif msg_type == "clear_history":
        await mgr.clear_history()
    elif msg_type == "takeover_enable":
        expiry = mgr.takeover_controller.request_takeover_confirmation()
        _debug("takeover_enable", bra_root=bra_root, expires_at=expiry)
        await mgr.broadcast(
            {
                "type": "takeover_confirmation_requested",
                "expires_in_sec": 15,
                "message": "Confirm takeover with Yes within 15 seconds.",
            }
        )
        await mgr.broadcast(
            {
                "type": "takeover_status",
                "active": False,
                "message": "2x4 takeover pending confirmation.",
            }
        )
    elif msg_type == "takeover_disable":
        mgr.takeover_controller.disable_takeover()
        _debug("takeover_disable", bra_root=bra_root)
        await mgr.broadcast(
            {
                "type": "takeover_stand_down",
                "message": "2x4 takeover stood down.",
            }
        )
        await mgr.broadcast(
            {
                "type": "takeover_status",
                "active": False,
                "message": "2x4 takeover inactive.",
            }
        )
    elif msg_type == "takeover_call_start":
        message = str(msg.get("message") or "").strip() or "Calling you now."
        params: dict[str, Any] = {
            "message": message,
            "mode": "conversation",
            "autoRespond": False,
        }
        to_value = str(msg.get("to") or "").strip()
        if to_value:
            params["to"] = to_value
        try:
            result = await _invoke_voicecall_bra("voicecall_bra.initiate", params)
            call_id = ""
            if isinstance(result, dict):
                call_id = str(
                    result.get("callId")
                    or result.get("call_id")
                    or result.get("providerCallId")
                    or ""
                ).strip()
            mgr.takeover_controller.start_call_session(call_id or None)
            _debug("takeover_call_start", bra_root=bra_root, call_id=call_id or None)
            await mgr.broadcast(
                {
                    "type": "takeover_call_started",
                    "call_id": call_id or None,
                    "method": "voicecall_bra.initiate",
                    "message": "2x4 call session active.",
                }
            )
        except Exception as exc:
            _debug("takeover_call_failed", bra_root=bra_root, error=str(exc), method="voicecall_bra.initiate")
            await mgr.broadcast(
                {
                    "type": "takeover_call_failed",
                    "method": "voicecall_bra.initiate",
                    "message": str(exc),
                }
            )
    elif msg_type == "takeover_call_stop":
        call_id = str(
            msg.get("call_id")
            or msg.get("callId")
            or getattr(mgr.takeover_controller, "call_id", "")
            or ""
        ).strip()
        try:
            if call_id:
                await _invoke_voicecall_bra("voicecall_bra.end", {"callId": call_id})
            mgr.takeover_controller.stop_call_session()
            _debug("takeover_call_stop", bra_root=bra_root, call_id=call_id or None)
            await mgr.broadcast(
                {
                    "type": "takeover_call_stopped",
                    "call_id": call_id or None,
                    "method": "voicecall_bra.end",
                    "message": "2x4 call session stopped.",
                }
            )
        except Exception as exc:
            _debug("takeover_call_failed", bra_root=bra_root, error=str(exc), method="voicecall_bra.end")
            await mgr.broadcast(
                {
                    "type": "takeover_call_failed",
                    "method": "voicecall_bra.end",
                    "call_id": call_id or None,
                    "message": str(exc),
                }
            )
    elif msg_type == "takeover_call_continue":
        call_id = str(
            msg.get("call_id")
            or msg.get("callId")
            or getattr(mgr.takeover_controller, "call_id", "")
            or ""
        ).strip()
        message = str(msg.get("message") or "").strip()
        try:
            if not call_id:
                raise ValueError("call_id required")
            if not message:
                raise ValueError("message required")
            await _invoke_voicecall_bra(
                "voicecall_bra.continue",
                {"callId": call_id, "message": message},
            )
            mgr.takeover_controller.start_call_session(call_id)
            _debug("takeover_call_continue", bra_root=bra_root, call_id=call_id)
            await mgr.broadcast(
                {
                    "type": "takeover_call_continued",
                    "call_id": call_id,
                    "method": "voicecall_bra.continue",
                    "message": "2x4 call session continued.",
                }
            )
        except Exception as exc:
            _debug("takeover_call_failed", bra_root=bra_root, error=str(exc), method="voicecall_bra.continue")
            await mgr.broadcast(
                {
                    "type": "takeover_call_failed",
                    "method": "voicecall_bra.continue",
                    "call_id": call_id or None,
                    "message": str(exc),
                }
            )
    elif msg_type == "takeover_call_speak":
        call_id = str(
            msg.get("call_id")
            or msg.get("callId")
            or getattr(mgr.takeover_controller, "call_id", "")
            or ""
        ).strip()
        message = str(msg.get("message") or "").strip()
        try:
            if not call_id:
                raise ValueError("call_id required")
            if not message:
                raise ValueError("message required")
            await _invoke_voicecall_bra(
                "voicecall_bra.speak",
                {"callId": call_id, "message": message},
            )
            mgr.takeover_controller.start_call_session(call_id)
            _debug("takeover_call_speak", bra_root=bra_root, call_id=call_id)
            await mgr.broadcast(
                {
                    "type": "takeover_call_spoken",
                    "call_id": call_id,
                    "method": "voicecall_bra.speak",
                    "message": "2x4 call speech queued.",
                }
            )
        except Exception as exc:
            _debug("takeover_call_failed", bra_root=bra_root, error=str(exc), method="voicecall_bra.speak")
            await mgr.broadcast(
                {
                    "type": "takeover_call_failed",
                    "method": "voicecall_bra.speak",
                    "call_id": call_id or None,
                    "message": str(exc),
                }
            )
    elif msg_type == "takeover_call_status":
        call_id = str(
            msg.get("call_id")
            or msg.get("callId")
            or getattr(mgr.takeover_controller, "call_id", "")
            or ""
        ).strip()
        include_history = bool(msg.get("includeHistory") or msg.get("include_history"))
        try:
            if not call_id:
                raise ValueError("call_id required")
            params: dict[str, Any] = {"callId": call_id}
            if include_history:
                params["includeHistory"] = True
            result = await _invoke_voicecall_bra("voicecall_bra.status", params)
            mgr.takeover_controller.start_call_session(call_id)
            _debug("takeover_call_status", bra_root=bra_root, call_id=call_id)
            await mgr.broadcast(
                {
                    "type": "takeover_call_status",
                    "call_id": call_id,
                    "method": "voicecall_bra.status",
                    "result": result,
                }
            )
        except Exception as exc:
            _debug("takeover_call_failed", bra_root=bra_root, error=str(exc), method="voicecall_bra.status")
            await mgr.broadcast(
                {
                    "type": "takeover_call_failed",
                    "method": "voicecall_bra.status",
                    "call_id": call_id or None,
                    "message": str(exc),
                }
            )
    elif msg_type == "pip_shell_mode":
        mode = "split" if str(msg.get("mode") or "").strip().lower() == "split" else "tabs"
        _debug("pip_shell_mode", bra_root=bra_root, mode=mode)
        await mgr.broadcast(
            {
                "type": "pip_shell_mode_changed",
                "mode": mode,
            }
        )
    elif msg_type == "pip_shell_panel":
        panel = "2x4" if str(msg.get("panel") or "").strip().lower() == "2x4" else "engage"
        _debug("pip_shell_panel", bra_root=bra_root, panel=panel)
        await mgr.broadcast(
            {
                "type": "pip_shell_panel_changed",
                "panel": panel,
            }
        )

    # Option selection (3 tiers)
    elif msg_type == "select":
        if suppress_chat_echo:
            await mgr.select_option(msg.get("option", 1), None, False, suppress_echo=True)
        else:
            await mgr.select_option(msg.get("option", 1), None, False)
    elif msg_type == "select_with_message":
        if suppress_chat_echo:
            await mgr.select_option(msg.get("option", 1), msg.get("message"), False, suppress_echo=True)
        else:
            await mgr.select_option(msg.get("option", 1), msg.get("message"), False)
    elif msg_type == "select_with_override":
        await mgr.broadcast({
            "type": "error",
            "message": "Override selection is only available in approval actions",
        })
    elif msg_type == "continue":
        if suppress_chat_echo:
            await mgr.continue_with_message(msg.get("message", ""), suppress_echo=True)
        else:
            await mgr.continue_with_message(msg.get("message", ""))
    elif msg_type == "debug_session_message":
        if suppress_chat_echo:
            await mgr.debug_message_to_session(msg.get("message", ""), suppress_echo=True)
        else:
            await mgr.debug_message_to_session(msg.get("message", ""))
    elif msg_type == "review_pending":
        state = mgr.get_state()
        if state.get("pending_approval"):
            event = {"type": "state", **state}
            if websocket is not None:
                await websocket.send_json(event)
            else:
                await mgr.broadcast(event)
        else:
            event = {
                "type": "error",
                "message": "No pending approval to review.",
            }
            if websocket is not None:
                await websocket.send_json(event)
            else:
                await mgr.broadcast(event)

    # Approval responses
    elif msg_type in ("approve_token", "approve_scope", "approve_scope_add", "approve_scope_upgrade",
                      "approve_script", "approve_tool", "approve_anon_map"):
        await mgr.resolve_approval({"decision": msg.get("decision", "deny"),
                                     "scope_level": msg.get("scope_level"),
                                     "custom_value": msg.get("custom_value"),
                                     "message": msg.get("message")})

    # Lifecycle
    elif msg_type == "battlestations":
        # Cancel any pending end-engagement futures if user navigates away
        if mgr._findings_filter_future and not mgr._findings_filter_future.done():
            mgr._findings_filter_future.cancel()
        if mgr._end_step_future and not mgr._end_step_future.done():
            mgr._end_step_future.cancel()
        menu = _get_engagement_menu(bra_root)
        await mgr.broadcast({"type": "engagement_menu",
                              "items": menu["items"],
                              "state": menu["state"]})
    elif msg_type == "wizard_start":
        await _run_wizard(mgr, bra_root)
    elif msg_type == "wizard_submit":
        await _wizard_submit(mgr, bra_root, msg.get("scope", {}), msg.get("tokens", {}))
    elif msg_type == "wizard_launch":
        await _wizard_launch(mgr, bra_root, msg.get("tokens", {}))
    elif msg_type == "end_intake_start":
        await _broadcast_end_intake(
            mgr,
            bra_root,
            report_types=msg.get("report_types"),
            force_emit=True,
        )
    elif msg_type == "end_intake_submit":
        await _submit_end_intake(
            mgr,
            bra_root,
            msg.get("report_types"),
            msg.get("fields"),
        )
    elif msg_type == "end_engagement":
        if mgr._end_engagement_running:
            _debug("end_engagement_duplicate_ignored", bra_root=bra_root)
            await mgr.broadcast(
                {
                    "type": "status",
                    "content": "End engagement already running; duplicate request ignored.",
                }
            )
            return

        async def _end_engagement_task() -> None:
            mgr._end_engagement_running = True
            try:
                if not await _ensure_end_intake_ready(mgr, bra_root):
                    return
                await _run_end_engagement(mgr, bra_root)
            finally:
                mgr._end_engagement_running = False

        asyncio.ensure_future(_end_engagement_task())
    elif msg_type == "end_step_retry":
        if mgr._end_step_future and not mgr._end_step_future.done():
            mgr._end_step_future.set_result("retry")
    elif msg_type == "end_step_continue":
        if mgr._end_step_future and not mgr._end_step_future.done():
            mgr._end_step_future.set_result("skip")
    elif msg_type == "findings_filter_response":
        if mgr._findings_filter_future and not mgr._findings_filter_future.done():
            # include_ids: list of finding ID strings to include, or null to include all
            include_ids = msg.get("include_ids")  # None means "all"
            mgr._findings_filter_future.set_result(include_ids)
    elif msg_type == "growth":
        await _run_script(mgr, bra_root, "growth.py", silent=True)
    elif msg_type == "packup":
        await _run_packup(mgr, bra_root, msg.get("mode", "default"))
    elif msg_type == "reset":
        await mgr.broadcast({"type": "confirm_needed", "action": "reset",
                              "message": "Reset will delete all engagement data. DESTRUCTIVE-APPROVAL token required.",
                              "requires_token": "DESTRUCTIVE-APPROVAL"})
    elif msg_type == "reset_confirm":
        # Ensure reset starts from a truly idle state: stop any live agent task
        # and clear persisted session pointers before/after destructive cleanup.
        should_stop = bool(
            mgr.runner
            or (mgr._agent_task and not mgr._agent_task.done())
            or (mgr.pending_approval and not mgr.pending_approval.done())
            or mgr.state != "idle"
        )
        if should_stop:
            try:
                await mgr.stop_agent()
            except Exception as exc:
                _debug("reset_confirm_stop_agent_error", bra_root=bra_root, error=str(exc))
        try:
            update_session_state(clear_session=True)
        except Exception as exc:
            _debug("reset_confirm_clear_session_pre_error", bra_root=bra_root, error=str(exc))
        mgr.session_id = None
        reset_rc = await _run_script(mgr, bra_root, "reset.py", "--force", silent=True)
        try:
            update_session_state(clear_session=True)
        except Exception as exc:
            _debug("reset_confirm_clear_session_post_error", bra_root=bra_root, error=str(exc))
        mgr.session_id = None
        # Clear stale history so reconnect/refresh starts clean, then
        # broadcast explicit success/failure so the frontend can show feedback.
        await mgr.clear_history()
        success = reset_rc == 0
        await mgr.broadcast({
            "type": "reset_complete",
            "success": success,
            "message": "Engagement reset complete. All data cleared." if success
                       else f"Reset failed (exit {reset_rc}). Check logs for details.",
        })
    elif msg_type == "resolve_operator_ip":
        ip = msg.get("selected_ip", "").strip()
        if ip:
            import json as jsonmod
            meta_path = _body_root(bra_root) / ".bra" / "engagement_meta.json"
            if meta_path.exists():
                try:
                    meta = jsonmod.loads(meta_path.read_text())
                    meta["operator_relevant_ip"] = ip
                    meta_path.write_text(jsonmod.dumps(meta, indent=2))
                except Exception:
                    pass



def _get_engagement_menu(bra_root: str) -> dict:
    """Build state-gated engagement menu items."""
    _sync_settings_root_for_path(bra_root)
    try:
        from bra.core.bridge import detect_session_state
        state = detect_session_state()
        s = state if isinstance(state, str) else state.value if hasattr(state, 'value') else str(state)
    except Exception:
        s = "FRESH"

    return {
        "state": s,
        "items": [
            {"key": "start", "label": "Start New Engagement", "enabled": True},
            {"key": "resume", "label": "Resume Engagement", "enabled": s == "IN_PROGRESS"},
            {"key": "end", "label": "End Engagement", "enabled": s == "IN_PROGRESS"},
            {"key": "growth", "label": "Growth & Pitches", "enabled": s in ("ENDED", "COMPLETE")},
            {"key": "packup", "label": "Packup", "enabled": s != "FRESH"},
            {"key": "reset", "label": "Reset", "enabled": True},
        ],
    }


async def _run_script(mgr: EngageManager, bra_root: str, script: str, *args: str, silent: bool = False) -> int:
    """Run a body script and stream output to clients.

    Runs the script in a thread executor to avoid blocking the event loop
    (which would kill WebSocket connections).

    When *silent* is True the raw stdout card is suppressed from the chat
    feed.  The "Running …" status and ``script_done`` event are still
    broadcast normally.

    Returns the script exit code (1 on exception).
    """
    await mgr.broadcast(
        {
            "type": "script_output",
            "script": script,
            "content": f"Running {_friendly_task_name(script)}...",
        }
    )
    _sync_settings_root_for_path(bra_root)
    _debug("run_script_start", bra_root=bra_root, script=script, args=list(args))
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, lambda: run_script(script, *args, timeout=120))
        if not silent:
            await mgr.broadcast({"type": "script_output", "script": script, "content": result.stdout or ""})
        await mgr.broadcast({"type": "script_done", "script": script, "returncode": result.returncode})
        _debug("run_script_result", bra_root=bra_root, script=script, returncode=result.returncode)
        return result.returncode
    except Exception as e:
        await mgr.broadcast({"type": "script_done", "script": script, "returncode": 1, "error": str(e)})
        _debug("run_script_error", bra_root=bra_root, script=script, error=str(e))
        return 1


def _load_token_states(bra_root: str) -> dict[str, bool]:
    """Load current token states from .bra/approvals/ directory."""
    approvals_dir = _body_root(bra_root) / ".bra" / "approvals"
    token_names: list[str] = list(ENGAGEMENT_TOKEN_NAMES)
    if approvals_dir.exists():
        for token_file in approvals_dir.iterdir():
            if not token_file.is_file() or token_file.name.startswith("."):
                continue
            normalized = token_file.name.upper().replace("_", "-")
            if normalized and normalized not in token_names:
                token_names.append(normalized)
    states = {t: _token_file_exists(approvals_dir, t) for t in token_names}
    _debug("load_token_states", bra_root=bra_root, enabled=[k for k, v in states.items() if v])
    return states


def _save_token_states(bra_root: str, tokens: dict[str, bool]) -> None:
    """Write token states to .bra/approvals/ directory."""
    approvals_dir = _body_root(bra_root) / ".bra" / "approvals"
    approvals_dir.mkdir(parents=True, exist_ok=True)
    for name, enabled in tokens.items():
        if enabled:
            token_file = approvals_dir / name
            token_file.touch()
            alt_file = approvals_dir / name.replace("-", "_")
            if alt_file != token_file and alt_file.exists():
                alt_file.unlink()
        else:
            for candidate in {name, name.replace("-", "_")}:
                token_file = approvals_dir / candidate
                if token_file.exists():
                    token_file.unlink()
    _debug("save_token_states", bra_root=bra_root, enabled=[k for k, v in tokens.items() if v])


async def _run_wizard(mgr: EngageManager, bra_root: str) -> None:
    """Run the full wizard flow: precheck → check scope → load tokens → broadcast phase."""
    _debug("wizard_start", bra_root=bra_root)
    # Run precheck in executor
    await mgr.broadcast({"type": "script_output", "script": "precheck.py", "content": "Running precheck..."})
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, lambda: run_script("precheck.py", "--fix", timeout=60))
        precheck_passed = result.returncode == 0
        precheck_output = result.stdout or ""
        if result.stderr:
            precheck_output += "\n" + result.stderr
    except Exception as e:
        precheck_passed = False
        precheck_output = str(e)

    await mgr.broadcast({"type": "script_output", "script": "precheck.py", "content": precheck_output})
    await mgr.broadcast({"type": "script_done", "script": "precheck.py", "returncode": 0 if precheck_passed else 1})

    # Reset override rules for a clean battlestations setup pass.
    overrides_file = _body_root(bra_root) / ".bra" / "overrides.json"
    try:
        overrides_file.parent.mkdir(parents=True, exist_ok=True)
        overrides_file.write_text(json.dumps({"rules": []}, indent=2))
        await mgr.broadcast({
            "type": "script_output",
            "script": "overrides.json",
            "content": "Reset override rules",
        })
    except Exception as e:
        await mgr.broadcast({
            "type": "script_output",
            "script": "overrides.json",
            "content": f"Failed to reset overrides: {e}",
        })

    # Run dry-run as non-fatal visibility check, matching battlestations setup flow.
    await mgr.broadcast({"type": "script_output", "script": "dry-run.py", "content": "Running dry-run..."})
    try:
        dry_run_result = await loop.run_in_executor(None, lambda: run_script("dry-run.py", timeout=60))
        dry_run_output = dry_run_result.stdout or ""
        if dry_run_result.stderr:
            dry_run_output += ("\n" if dry_run_output else "") + dry_run_result.stderr
        await mgr.broadcast({"type": "script_output", "script": "dry-run.py", "content": dry_run_output})
        await mgr.broadcast({
            "type": "script_done",
            "script": "dry-run.py",
            "returncode": dry_run_result.returncode,
        })
    except Exception as e:
        await mgr.broadcast({
            "type": "script_done",
            "script": "dry-run.py",
            "returncode": 1,
            "error": str(e),
        })

    # Check scope and load tokens
    try:
        scope_configured = is_scope_configured()
        scope_summary = get_scope_summary() if scope_configured else {}
    except Exception:
        scope_configured = False
        scope_summary = {}
    tokens = _load_token_states(bra_root)

    await mgr.broadcast({
        "type": "wizard_phase",
        "phase": "privacy_posture",
        "precheck_passed": precheck_passed,
        "precheck_output": precheck_output,
        "scope_configured": scope_configured,
        "scope_summary": scope_summary,
        "tokens": tokens,
    })
    _debug(
        "wizard_phase",
        bra_root=bra_root,
        precheck_passed=precheck_passed,
        scope_configured=scope_configured,
        token_count=sum(1 for v in tokens.values() if v),
    )


def _write_scope_file(bra_root: str, scope: dict) -> None:
    """Write SCOPE.md in body scope-intake compatible format."""
    from datetime import datetime

    scope_file = _body_root(bra_root) / "layer3-engagement" / "SCOPE.md"
    scope_file.parent.mkdir(parents=True, exist_ok=True)

    now_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    today = datetime.now().strftime("%Y-%m-%d")

    target_name = scope.get("target_name", "Unknown")
    target_type = (scope.get("target_type", "pending-intel") or "pending-intel").strip().lower()
    version = scope.get("target_version", "Unknown") or "Unknown"

    # Keep methodology names aligned with body/layer1/scripts/scope-intake.py.
    methodology_map = {
        "android": "android-mobile-security",
        "ios": "ios-mobile-security",
        "iot": "iot-embedded-security",
        "firmware": "firmware-analysis",
        "thick-client": "thick-client-security",
        "dotnet": "dotnet-assessment",
        "bluetooth": "bluetooth-radio-security",
        "homekit": "hap-homekit-fuzzing",
    }
    if target_type in ("auto-detect", "unknown"):
        target_type = "pending-intel"
    methodology = methodology_map.get(target_type, "auto-detect")

    if methodology != "auto-detect":
        meth_file = _body_root(bra_root) / "layer2-templates" / "methodologies" / f"{methodology}.md"
        if not meth_file.exists():
            target_type = "pending-intel"
            methodology = "auto-detect"

    def to_bullets(value: str, default: str) -> str:
        text = (value or "").strip()
        if not text:
            return default
        lines = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("- "):
                line = line[2:].strip()
            lines.append(f"- {line}")
        return "\n".join(lines) if lines else default

    in_scope = to_bullets(scope.get("in_scope", ""), "- Everything")
    out_scope = to_bullets(scope.get("out_scope", ""), "- Nothing")

    # Unified targets: accept new 'targets' field or fall back to old split fields
    # Written as-is — the agent standardizes + tags during scope validation
    raw_targets = scope.get("targets", "")
    if not raw_targets.strip():
        # Backward compat: merge old local_targets + network_targets
        old_local = (scope.get("local_targets", "") or "").strip()
        old_net = (scope.get("network_targets", "") or "").strip()
        raw_targets = "\n".join(filter(None, [old_local, old_net]))
    targets_section = to_bullets(raw_targets, "- None specified")
    time_window = scope.get("time_window", "No restrictions")
    active_testing = (scope.get("active_testing", "ASK") or "ASK").strip().upper()
    notes = scope.get("notes", "None")

    content = f"""# Engagement Scope

> **Generated:** {now_iso}
> **Status:** ACTIVE

---

## Ethics & Authorization

**Authorization: Yes** - Operator solemnly confirmed authorization at {now_iso}

I solemnly swear that I am authorized to perform any actions that may occur from this point forward: **Yes**

---

## Target Definition

**Name:** {target_name}
**Target Type:** {target_type}
**Methodology:** {methodology}
**Version:** {version}

### Targets

{targets_section}

---

## In-Scope

{in_scope}

---

## Out-of-Scope

{out_scope}

---

## Time Window

- **Start:** {today}
- **End:** Ongoing (no end date)
- **Restrictions:** {time_window}

---

## Active Testing

ACTIVE-TESTING-APPROVAL: {active_testing}

| Setting | Meaning |
|---------|---------|
| YES | Network-based testing allowed |
| NO | Static analysis only |
| ASK | Prompt before network testing |

---

## Notes

{notes}

---

*Generated by scope-intake.py*
"""
    scope_file.write_text(content)
    _debug("write_scope_file", bra_root=bra_root, scope_file=str(scope_file), target_name=target_name, target_type=target_type)

    # Write engagement meta (with operator IPs captured at start)
    import json as jsonmod
    import socket
    import urllib.request

    # Internal IPs — all non-loopback addresses from local interfaces
    internal_ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = info[4][0]
            if addr and not addr.startswith("127."):
                if addr not in internal_ips:
                    internal_ips.append(addr)
    except Exception:
        pass
    # Fallback: UDP connect trick to get default route interface
    if not internal_ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 1))
            internal_ips = [s.getsockname()[0]]
            s.close()
        except Exception:
            pass

    # External IP — best-effort, non-blocking
    external_ip = None
    try:
        req = urllib.request.Request("https://api.ipify.org", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            external_ip = resp.read().decode().strip()
    except Exception:
        pass

    meta_file = _body_root(bra_root) / ".bra" / "engagement_meta.json"
    meta_file.parent.mkdir(parents=True, exist_ok=True)
    meta = {
        "started_at": now_iso,
        "operator_internal_ips": internal_ips,
        "operator_external_ip": external_ip,
    }
    meta_file.write_text(jsonmod.dumps(meta, indent=2))

    # Auto-resolve operator relevant IP from target subnet
    raw_targets = scope.get("targets", "")
    if internal_ips and raw_targets.strip():
        for line in raw_targets.splitlines():
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', line)
            if ip_match:
                resolved = _resolve_operator_ip(ip_match.group(1), internal_ips)
                if resolved:
                    meta["operator_relevant_ip"] = resolved
                    meta_file.write_text(jsonmod.dumps(meta, indent=2))
                    break

    # Create active testing token if YES
    if active_testing == "YES":
        approvals_dir = _body_root(bra_root) / ".bra" / "approvals"
        approvals_dir.mkdir(parents=True, exist_ok=True)
        (approvals_dir / "ACTIVE-TESTING-APPROVAL").touch()


async def _wizard_submit(mgr: EngageManager, bra_root: str, scope: dict, tokens: dict) -> None:
    """Handle wizard_submit: validate, write scope + tokens, launch agent."""
    _debug("wizard_submit", bra_root=bra_root, target_name=scope.get("target_name", ""), token_count=len(tokens))
    # Validate required fields
    if not scope.get("target_name", "").strip():
        await mgr.broadcast({"type": "wizard_error", "message": "Target name is required", "field": "target_name"})
        return
    if not scope.get("authorization"):
        await mgr.broadcast({"type": "wizard_error", "message": "Authorization is required", "field": "authorization"})
        return

    approvals_dir = _body_root(bra_root) / ".bra" / "approvals"
    approvals_dir.mkdir(parents=True, exist_ok=True)

    scope_token = "FRONTIER-SCOPE"
    for token in SCOPE_TOKEN_NAMES:
        if (approvals_dir / token).exists():
            scope_token = token
            break

    if scope_token == "LOCAL-SCOPE":
        await mgr.broadcast({"type": "wizard_error", "message": "Local Mask is not available yet"})
        return
    if scope_token == "MICRO-SCOPE" and os.environ.get("BRA_NER_ENABLED") != "1":
        await mgr.broadcast(
            {
                "type": "wizard_error",
                "message": "MICRO-SCOPE requires boots to be started with --ner.",
            }
        )
        return
    raw_scope = scope_token in {"FRONTIER-SCOPE", "NO-SCOPE"}

    # Write scope file
    try:
        from bra.anon.api import AnonAPI

        body_root = _body_root(bra_root)
        if not (approvals_dir / "ANON-DISABLE").exists():
            map_path = body_root / ".bra" / "anon_map.json"
            if map_path.exists() and not raw_scope:
                anon = AnonAPI(map_path=map_path)
                for field in ("target_name", "targets", "in_scope", "out_scope", "notes"):
                    if field in scope and scope[field]:
                        scope[field] = anon.mask(scope[field])
    except Exception:
        pass

    _write_scope_file(bra_root, scope)

    # Save tokens
    _save_token_states(bra_root, tokens)

    # Lock scope: set SCOPE-CONFIRMED so the agent can't edit SCOPE.md directly.
    # New targets discovered at runtime must go through approve-target.py.
    (approvals_dir / "SCOPE-CONFIRMED").touch()
    _debug("wizard_submit_scope_locked", bra_root=bra_root)

    # Launch agent
    await _wizard_launch_agent(mgr, bra_root)


async def _wizard_launch(mgr: EngageManager, bra_root: str, tokens: dict) -> None:
    """Handle wizard_launch: save tokens and launch agent (scope already configured)."""
    _debug("wizard_launch", bra_root=bra_root, token_count=len(tokens))
    _save_token_states(bra_root, tokens)

    # Ensure scope is locked even on re-launch
    approvals_dir = _body_root(bra_root) / ".bra" / "approvals"
    approvals_dir.mkdir(parents=True, exist_ok=True)
    (approvals_dir / "SCOPE-CONFIRMED").touch()

    await _wizard_launch_agent(mgr, bra_root)


async def _wizard_launch_agent(mgr: EngageManager, bra_root: str) -> None:
    """Generate handoff prompt via agentic-handler.py and start agent.

    Stops any existing agent first to prevent orphan subprocesses and
    ghost output from stale sessions.
    """
    # Stop any existing agent so stale subprocesses don't produce ghost output
    if mgr.runner and mgr.state in ("running", "awaiting_input", "blocked"):
        _debug("wizard_launch_agent_stopping_existing", bra_root=bra_root, state=mgr.state)
        await mgr.stop_agent()

    _debug("wizard_launch_agent_start", bra_root=bra_root)
    await mgr.broadcast({"type": "script_output", "script": "agentic-handler.py", "content": "Generating handoff..."})
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, lambda: run_script("agentic-handler.py", timeout=30))
        if result.returncode != 0:
            await mgr.broadcast({"type": "wizard_error", "message": f"Handoff generation failed: {result.stderr}"})
            _debug("wizard_launch_agent_fail_handoff", bra_root=bra_root, returncode=result.returncode)
            return
        prompt = result.stdout
    except Exception as e:
        await mgr.broadcast({"type": "wizard_error", "message": f"Launch failed: {e}"})
        _debug("wizard_launch_agent_error", bra_root=bra_root, error=str(e))
        return

    await mgr.broadcast({"type": "wizard_complete"})
    _debug("wizard_launch_agent_ready", bra_root=bra_root)
    await mgr.start_agent(prompt, bra_root)


async def _broadcast_end_intake(
    mgr: EngageManager,
    bra_root: str,
    report_types: list[str] | str | None = None,
    *,
    validation_errors: list[str] | None = None,
    force_emit: bool = False,
) -> bool:
    """Broadcast end-intake requirements and return True when intake is complete."""
    layer3_dir = _body_root(bra_root) / "layer3-engagement"
    payload = build_end_intake_payload(layer3_dir, report_types=report_types)
    missing = payload.get("missing_fields", [])
    if validation_errors is not None:
        payload["validation_errors"] = validation_errors

    if force_emit or missing or validation_errors:
        await mgr.broadcast({"type": "end_intake_required", **payload})
    return not (missing or validation_errors)


async def _submit_end_intake(
    mgr: EngageManager,
    bra_root: str,
    report_types: list[str] | str | None,
    fields: dict[str, Any] | None,
) -> None:
    """Validate and persist end-intake metadata submission."""
    layer3_dir = _body_root(bra_root) / "layer3-engagement"
    if isinstance(report_types, str):
        provided_types = [part.strip().lower() for part in report_types.split(",") if part.strip()]
    elif isinstance(report_types, list):
        provided_types = [str(item).strip().lower() for item in report_types if str(item).strip()]
    else:
        provided_types = []
    valid_types = [t for t in provided_types if t in ("generic", "vendor", "cna")]

    if not valid_types:
        await mgr.broadcast(
            {
                "type": "end_intake_invalid",
                "message": "Select at least one report type.",
                "missing_fields": [],
                "required_fields": [],
            }
        )
        await _broadcast_end_intake(
            mgr,
            bra_root,
            report_types=["generic", "vendor", "cna"],
            validation_errors=["report_types"],
            force_emit=True,
        )
        return

    profile, missing, required = validate_end_intake_submission(
        layer3_dir,
        valid_types,
        fields,
    )

    if missing:
        await mgr.broadcast(
            {
                "type": "end_intake_invalid",
                "message": "Missing required metadata fields.",
                "missing_fields": missing,
                "required_fields": required,
            }
        )
        await _broadcast_end_intake(
            mgr,
            bra_root,
            report_types=valid_types,
            validation_errors=missing,
            force_emit=True,
        )
        return

    profile_path = save_end_profile(layer3_dir, profile)
    await mgr.broadcast(
        {
            "type": "end_intake_saved",
            "path": str(profile_path),
            "report_types": normalize_report_types(profile.get("report_types", "")),
        }
    )


async def _ensure_end_intake_ready(mgr: EngageManager, bra_root: str) -> bool:
    """Return True only when required end-intake metadata is complete."""
    layer3_dir = _body_root(bra_root) / "layer3-engagement"
    existing = load_end_profile(layer3_dir)
    report_types = normalize_report_types(existing.get("report_types", ""))
    return await _broadcast_end_intake(mgr, bra_root, report_types=report_types)


_AGENT_STUB_MARKERS = (
    "_Pending AI-generated",
    "_AI-generated from findings_",
)


def _check_report_stubs(bra_root: str) -> list[str]:
    """Return list of section names still containing agent stub placeholders."""
    report = _body_root(bra_root) / "layer3-engagement" / "REPORT.md"
    if not report.exists():
        return ["REPORT.md missing"]
    content = report.read_text(encoding="utf-8")
    stubs: list[str] = []
    sections = {
        "Risk Summary": "### Risk Summary",
        "Recommendations": "### Recommendations Summary",
        "Intelligence Highlights": "### Intelligence Highlights",
        "Remediation Roadmap": "## Remediation Roadmap",
    }
    for name, heading in sections.items():
        idx = content.find(heading)
        if idx == -1:
            continue
        after = content[idx + len(heading):]
        end_markers = [after.find("\n---"), after.find("\n## ")]
        end_markers = [m for m in end_markers if m > 0]
        section_text = after[:min(end_markers)] if end_markers else after
        for marker in _AGENT_STUB_MARKERS:
            if marker in section_text:
                stubs.append(name)
                break
    return stubs


def _parse_findings_for_selection(bra_root: str) -> list[dict]:
    """Parse FINDINGS.md and return list of {id, title, severity} for selection UI."""
    findings_file = _body_root(bra_root) / "layer3-engagement" / "NOTES" / "FINDINGS.md"
    if not findings_file.exists():
        return []
    findings: list[dict] = []
    current: dict | None = None
    for line in findings_file.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^## \[FINDING-(\d+)\]\s*(.*)", line)
        if m:
            if current:
                findings.append(current)
            current = {"id": m.group(1), "title": m.group(2).strip(), "severity": "Unknown"}
            continue
        if current and re.match(r"^\| \*\*Severity\*\* \| ", line):
            sev = line.removeprefix("| **Severity** | ").removesuffix(" |").strip()
            current["severity"] = sev
    if current:
        findings.append(current)
    return findings


async def _run_end_engagement(mgr: EngageManager, bra_root: str) -> None:
    """Run the end engagement sequence with retry on failure."""
    from datetime import datetime

    _debug("end_engagement_start", bra_root=bra_root)
    _sync_settings_root_for_path(bra_root)
    layer3_dir = _body_root(bra_root) / "layer3-engagement"
    profile = load_end_profile(layer3_dir)
    report_types = normalize_report_types(profile.get("report_types", ""))
    types_csv = ",".join(report_types)

    total_steps = 5

    # Pre-step: finding selection governance (only if FINDINGS-SELECTION token is set)
    _findings_selection_enabled = _token_file_exists(
        _body_root(bra_root) / ".bra" / "approvals", "FINDINGS-SELECTION"
    )
    findings_list = _parse_findings_for_selection(bra_root) if _findings_selection_enabled else []
    if findings_list:
        mgr._findings_filter_future = asyncio.get_event_loop().create_future()
        await mgr.broadcast({
            "type": "findings_selection_required",
            "findings": findings_list,
        })
        try:
            include_ids = await mgr._findings_filter_future
        except asyncio.CancelledError:
            mgr._findings_filter_future = None
            await mgr.broadcast({"type": "status", "content": "End engagement cancelled."})
            return
        mgr._findings_filter_future = None
        filter_path = _body_root(bra_root) / ".bra" / "report_findings_filter.json"
        if include_ids is not None:
            filter_path.write_text(json.dumps({"include": include_ids}), encoding="utf-8")
            _debug("end_engagement_findings_filter_set", bra_root=bra_root, include=include_ids)
        else:
            # User chose to include all — write a marker so downstream knows selection ran
            filter_path.write_text(json.dumps({"include": [f["id"] for f in findings_list]}), encoding="utf-8")
            _debug("end_engagement_findings_filter_all", bra_root=bra_root)

    # Steps 1-3: shell scripts (report generation)
    shell_steps_pre = [
        ("stats.py", "--full"),
        ("report-ready.py", "--types", types_csv, "--non-interactive"),
        ("disclose.py", "--types", types_csv, "--non-interactive"),
    ]
    for i, step in enumerate(shell_steps_pre):
        while True:
            await mgr.broadcast({"type": "script_output", "script": step[0],
                                  "content": f"Step {i+1}/{total_steps}: {_friendly_task_name(step[0])}",
                                  "step": i + 1, "total_steps": total_steps})
            await _run_script(mgr, bra_root, *step, silent=True)

            last_done = None
            for evt in reversed(mgr.history):
                if evt.get("type") == "script_done" and evt.get("script") == step[0]:
                    last_done = evt
                    break

            if last_done and last_done.get("returncode", 0) != 0:
                rc = last_done.get("returncode", 1)
                reason = "insufficient_data" if rc == 2 else "error"
                mgr._end_step_future = asyncio.get_event_loop().create_future()
                await mgr.broadcast({
                    "type": "end_step_failed",
                    "script": step[0],
                    "step": i + 1,
                    "total_steps": total_steps,
                    "returncode": rc,
                    "reason": reason,
                })
                action = await mgr._end_step_future
                mgr._end_step_future = None
                if action == "retry":
                    _debug("end_engagement_retry_step", bra_root=bra_root, script=step[0])
                    continue
                _debug("end_engagement_skip_step", bra_root=bra_root, script=step[0])
            break

    # Step 4: Agent report enhancement (with retry/skip like shell steps)
    await mgr._terminate_all_agent_subprocesses(reason="pre_enhance", grace_s=0.25)
    while True:
        await mgr.broadcast({"type": "script_output", "script": "report-enhance",
                              "content": f"Step 4/{total_steps}: Agent is writing report content...",
                              "step": 4, "total_steps": total_steps})
        step4_failed = False
        step4_reason = ""
        try:
            from bra.core.report_enhance import enhance_reports
            result = await asyncio.wait_for(enhance_reports(str(_body_root(bra_root)), report_types), timeout=180)
            if not result.get("success"):
                step4_failed = True
                step4_reason = result.get("summary", "No reports were enhanced")
                print(f"[end-engage] step4 not successful: bra_root={bra_root} result={result}", flush=True)
            else:
                stubs = _check_report_stubs(bra_root)
                if stubs:
                    step4_failed = True
                    step4_reason = f"Report still has placeholders in: {', '.join(stubs)}"
                else:
                    summary = result.get("summary", "Reports enhanced")
                    await mgr.broadcast({"type": "script_output", "script": "report-enhance",
                                          "content": summary})
                    await mgr.broadcast({"type": "script_done", "script": "report-enhance",
                                          "returncode": 0})
                    _debug("end_engagement_enhance_done", bra_root=bra_root, summary=summary)
        except asyncio.TimeoutError:
            step4_failed = True
            step4_reason = "Agent enhancement timed out after 180s"
            _debug("end_engagement_enhance_timeout", bra_root=bra_root)
        except Exception as exc:
            import traceback
            step4_failed = True
            step4_reason = f"Agent enhancement error: {exc}"
            print(f"[end-engage] step4 exception: {exc}\n{traceback.format_exc()}", flush=True)
            _debug("end_engagement_enhance_error", bra_root=bra_root, error=str(exc))

        if step4_failed:
            await mgr.broadcast({"type": "script_output", "script": "report-enhance",
                                  "content": step4_reason})
            await mgr.broadcast({"type": "script_done", "script": "report-enhance",
                                  "returncode": 1})
            mgr._end_step_future = asyncio.get_event_loop().create_future()
            await mgr.broadcast({
                "type": "end_step_failed",
                "script": "report-enhance",
                "step": 4,
                "total_steps": total_steps,
                "returncode": 1,
            })
            action = await mgr._end_step_future
            mgr._end_step_future = None
            if action == "retry":
                _debug("end_engagement_retry_step", bra_root=bra_root, script="report-enhance")
                continue
            _debug("end_engagement_skip_step", bra_root=bra_root, script="report-enhance")
        break

    # Step 5: lessons-learned.py
    step = ("lessons-learned.py",)
    while True:
        await mgr.broadcast({"type": "script_output", "script": step[0],
                              "content": f"Step 5/{total_steps}: {_friendly_task_name(step[0])}",
                              "step": 5, "total_steps": total_steps})
        await _run_script(mgr, bra_root, *step, silent=True)

        last_done = None
        for evt in reversed(mgr.history):
            if evt.get("type") == "script_done" and evt.get("script") == step[0]:
                last_done = evt
                break

        if last_done and last_done.get("returncode", 0) != 0:
            rc = last_done.get("returncode", 1)
            reason = "insufficient_data" if rc == 2 else "error"
            mgr._end_step_future = asyncio.get_event_loop().create_future()
            await mgr.broadcast({
                "type": "end_step_failed",
                "script": step[0],
                "step": 5,
                "total_steps": total_steps,
                "returncode": rc,
                "reason": reason,
            })
            action = await mgr._end_step_future
            mgr._end_step_future = None
            if action == "retry":
                _debug("end_engagement_retry_step", bra_root=bra_root, script=step[0])
                continue
            _debug("end_engagement_skip_step", bra_root=bra_root, script=step[0])
        break

    # Mirror TUI end-complete behavior so state does not remain IN_PROGRESS.
    artifacts_dir = _body_root(bra_root) / ".bra" / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    for marker in (".intel_complete", ".static_complete", ".dynamic_complete", ".report_complete"):
        (artifacts_dir / marker).touch()

    meta_file = _body_root(bra_root) / ".bra" / "engagement_meta.json"
    meta_file.parent.mkdir(parents=True, exist_ok=True)
    meta: dict[str, Any] = {}
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        except Exception:
            meta = {}
    meta["ended_at"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # Clean up any agent state (step 4 uses standalone query(), not mgr.runner,
    # but stray subprocesses or a prior session's runner may still exist).
    try:
        await mgr.stop_agent()
    except Exception as exc:
        _debug("end_engagement_stop_agent_error", bra_root=bra_root, error=str(exc))

    try:
        update_session_state(clear_session=True)
    except Exception as exc:
        _debug("end_engagement_clear_session_error", bra_root=bra_root, error=str(exc))

    await mgr.broadcast({
        "type": "end_engagement_complete",
        "summary": "End engagement sequence complete",
        "ended_at": meta.get("ended_at", ""),
    })


async def _run_packup(mgr: EngageManager, bra_root: str, mode: str) -> None:
    """Run packup and broadcast download availability."""
    import glob as globmod

    _debug("run_packup_start", bra_root=bra_root, mode=mode)
    args = []
    if mode == "minimal":
        args.append("--minimal")
    elif mode == "full":
        args.append("--full")

    await _run_script(mgr, bra_root, "packup.py", *args, silent=True)

    # Find the generated tar.gz
    pattern = str(_body_root(bra_root) / "packup_*.tar.gz")
    archives = sorted(globmod.glob(pattern))
    if archives:
        latest = Path(archives[-1])
        await mgr.broadcast({
            "type": "packup_ready",
            "filename": latest.name,
            "size_bytes": latest.stat().st_size,
            "path": str(latest),
        })
        _debug("run_packup_ready", bra_root=bra_root, filename=latest.name, size_bytes=latest.stat().st_size)
