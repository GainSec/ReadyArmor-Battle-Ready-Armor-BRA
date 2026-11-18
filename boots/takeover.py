"""Backend controller for Numbuh 2x4 Engage takeover mode."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from typing import Any, Awaitable, Callable

HIDDEN_TAKEOVER_INSTRUCTION = (
    "You are Numbuh 2x4 takeover mode for Engage. "
    "Act safely and deterministically. "
    "Return strict JSON with one action object only."
)

TAKEOVER_CONFIRM_TIMEOUT_SEC = 15.0
TAKEOVER_ACTIVE_LEASE_SEC = 30.0


class TakeoverController:
    """State holder for takeover mode and Engage event observation."""

    def __init__(self) -> None:
        self.state: str = "inactive"
        self.active: bool = False
        self.busy: bool = False
        self.session_id: str | None = None
        self.call_active: bool = False
        self.call_id: str | None = None
        self.takeover_lease_id: str | None = None
        self.pending_expires_at: float | None = None
        self.active_expires_at: float | None = None
        self.last_event_fingerprint: str | None = None
        self.last_policy_override: dict[str, Any] | None = None
        self.hidden_instruction: str = HIDDEN_TAKEOVER_INSTRUCTION
        self.ws_url: str = ""
        self.token: str = ""
        self._inflight_decision_task: asyncio.Task[Any] | None = None
        self._query_fn: Callable[[dict[str, Any]], Awaitable[str | dict[str, Any]]] | None = None
        self._dispatch_fn: Callable[[dict[str, Any]], Awaitable[None]] | None = None
        self._notify_fn: Callable[[dict[str, Any]], Awaitable[None]] | None = None

    def set_runtime_hooks(
        self,
        *,
        query_fn: Callable[[dict[str, Any]], Awaitable[str | dict[str, Any]]] | None = None,
        dispatch_fn: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        notify_fn: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> None:
        self._query_fn = query_fn
        self._dispatch_fn = dispatch_fn
        self._notify_fn = notify_fn

    def configure_standby(self, session_id: str | None = None) -> None:
        self._cancel_inflight_decision_task()
        if session_id is not None:
            self.session_id = session_id
        self.state = "configured_standby"
        self.active = False
        self.busy = False
        self.pending_expires_at = None
        self.active_expires_at = None
        self.takeover_lease_id = None

    def request_takeover_confirmation(self, *, now_ts: float | None = None) -> float:
        now = float(now_ts if now_ts is not None else time.monotonic())
        if self.state == "inactive":
            self.configure_standby()
        self._cancel_inflight_decision_task()
        self.state = "takeover_pending_confirm"
        self.active = False
        self.busy = False
        self.takeover_lease_id = None
        self.active_expires_at = None
        self.pending_expires_at = now + TAKEOVER_CONFIRM_TIMEOUT_SEC
        return self.pending_expires_at

    def confirm_takeover(self, confirmation: str, *, now_ts: float | None = None) -> bool:
        now = float(now_ts if now_ts is not None else time.monotonic())
        if self.reconcile_timeouts(now_ts=now) is not None:
            return False
        if self.state != "takeover_pending_confirm":
            return False
        if str(confirmation or "").strip().lower() != "yes":
            return False
        self.state = "takeover_active"
        self.active = True
        self.busy = False
        self.pending_expires_at = None
        self.active_expires_at = now + TAKEOVER_ACTIVE_LEASE_SEC
        self.takeover_lease_id = uuid.uuid4().hex
        return True

    def reconcile_timeouts(self, *, now_ts: float | None = None) -> str | None:
        now = float(now_ts if now_ts is not None else time.monotonic())
        if (
            self.state == "takeover_pending_confirm"
            and self.pending_expires_at is not None
            and now >= self.pending_expires_at
        ):
            self.configure_standby()
            return "pending_expired"
        if (
            self.state == "takeover_active"
            and self.active_expires_at is not None
            and now >= self.active_expires_at
        ):
            self.disable_takeover()
            return "active_expired"
        return None

    def enable_takeover(self, session_id: str | None = None) -> None:
        now = time.monotonic()
        if self.state == "inactive":
            self.configure_standby(session_id=session_id)
        self.state = "takeover_active"
        self.active = True
        self.pending_expires_at = None
        self.active_expires_at = now + TAKEOVER_ACTIVE_LEASE_SEC
        self.takeover_lease_id = uuid.uuid4().hex
        if session_id is not None:
            self.session_id = session_id

    def disable_takeover(self) -> None:
        self._cancel_inflight_decision_task()
        self.state = "configured_standby" if self.state != "inactive" else "inactive"
        self.active = False
        self.busy = False
        self.pending_expires_at = None
        self.active_expires_at = None
        self.takeover_lease_id = None

    def start_call_session(self, call_id: str | None = None) -> None:
        self.call_active = True
        self.call_id = str(call_id or "").strip() or None

    def stop_call_session(self) -> None:
        self.call_active = False
        self.call_id = None

    async def on_engage_event(self, event: dict[str, Any]) -> dict[str, Any]:
        timeout_status = self.reconcile_timeouts()
        if timeout_status == "pending_expired":
            await self._emit_notify(
                {
                    "type": "takeover_confirmation_expired",
                    "active": False,
                    "message": "2x4 takeover confirmation expired. Returned to standby.",
                }
            )
        elif timeout_status == "active_expired":
            await self._emit_notify(
                {
                    "type": "takeover_auto_expired",
                    "active": False,
                    "message": "2x4 takeover lease expired. Returned to standby.",
                }
            )
        if self.busy:
            return {"action": "none", "reason": "busy"}
        if not self.active or self.state != "takeover_active":
            return {"action": "none", "reason": self.state}
        event_type = str(event.get("type") or "").strip().lower()
        if event_type == "takeover_status" or event_type.startswith("takeover_") or event_type.startswith("pip_shell_"):
            return {"action": "none", "reason": "ignored_event"}
        fingerprint = self._fingerprint_event(event)
        if self.last_event_fingerprint == fingerprint:
            return {"action": "none", "reason": "duplicate_event"}
        self.last_event_fingerprint = fingerprint
        self.busy = True
        self._inflight_decision_task = asyncio.current_task()
        try:
            await self._emit_notify(
                {
                    "type": "takeover_decision_requested",
                    "event_type": event_type,
                }
            )
            action = await self.query_2x4_structured_action(
                {"event": event},
                query_fn=self._query_fn,
            )
            await self._emit_notify(
                {
                    "type": "takeover_decision_parsed",
                    "action": action.get("action"),
                    "reason": action.get("reason"),
                }
            )
            if not self.active or self.state != "takeover_active" or not self.takeover_lease_id:
                await self._emit_notify(
                    {
                        "type": "takeover_cancelled",
                        "reason": "state_changed",
                    }
                )
                return {"action": "none", "reason": "stand_down_cancelled"}
            if action.get("action") == "none":
                await self._emit_notify(
                    {
                        "type": "takeover_noop",
                        "reason": action.get("reason", "no_action"),
                    }
                )
                return action
            if self._dispatch_fn is None:
                await self._emit_notify(
                    {
                        "type": "takeover_dispatch_failed",
                        "reason": "dispatch_unavailable",
                    }
                )
                return {"action": "none", "reason": "dispatch_unavailable"}
            dispatched = await self.dispatch_action_to_engage(
                action,
                dispatch_fn=self._dispatch_fn,
                notify_fn=self._notify_fn,
            )
            if not dispatched:
                await self._emit_notify(
                    {
                        "type": "takeover_noop",
                        "reason": "unmapped_action",
                    }
                )
                return {"action": "none", "reason": "unmapped_action"}
            await self._emit_notify(
                {
                    "type": "takeover_dispatch_sent",
                    "action": action.get("action"),
                }
            )
            return action
        except Exception as exc:
            await self._emit_notify(
                {
                    "type": "takeover_dispatch_failed",
                    "reason": str(exc),
                }
            )
            return {"action": "none", "reason": "dispatch_failed"}
        except asyncio.CancelledError:
            await self._emit_notify(
                {
                    "type": "takeover_cancelled",
                    "reason": "stand_down",
                }
            )
            return {"action": "none", "reason": "stand_down_cancelled"}
        finally:
            self.busy = False
            current = asyncio.current_task()
            if self._inflight_decision_task is current:
                self._inflight_decision_task = None

    def configure_relay_settings(self, config: dict[str, Any]) -> None:
        self.ws_url = str(
            config.get("numbuh_2x4_ws_url") or config.get("openclaw_ws_url") or ""
        ).strip()
        self.token = str(
            config.get("numbuh_2x4_token") or config.get("openclaw_token") or ""
        ).strip()
        configured_instruction = str(
            config.get("numbuh_2x4_takeover_prompt")
            or config.get("openclaw_takeover_prompt")
            or ""
        ).strip()
        self.hidden_instruction = configured_instruction or HIDDEN_TAKEOVER_INSTRUCTION
        if self.ws_url and self.token and self.state == "inactive":
            self.configure_standby()

    async def query_2x4_structured_action(
        self,
        context: dict[str, Any],
        *,
        query_fn: Callable[[dict[str, Any]], Awaitable[str | dict[str, Any]]] | None = None,
        timeout_sec: float = 10.0,
    ) -> dict[str, Any]:
        payload = self.build_query_payload(context)
        if query_fn is None or not self.ws_url or not self.token:
            return {"action": "none", "reason": "query_unavailable"}
        try:
            raw_response = await asyncio.wait_for(query_fn(payload), timeout=timeout_sec)
        except Exception:
            return {"action": "none", "reason": "query_failed"}
        return self._parse_action_response(raw_response)

    def build_query_payload(self, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "ws_url": self.ws_url,
            "token": self.token,
            "hidden_instruction": self.hidden_instruction,
            "context": context,
        }

    def build_call_decision_context(
        self,
        *,
        event: dict[str, Any],
        summary: str = "",
    ) -> dict[str, Any]:
        context: dict[str, Any] = {
            "event": event,
            "call": {
                "active": self.call_active,
                "call_id": self.call_id,
            },
        }
        trimmed_summary = str(summary or "").strip()
        if trimmed_summary:
            context["summary"] = trimmed_summary
        return context

    async def query_call_decision(
        self,
        *,
        event: dict[str, Any],
        summary: str = "",
        query_fn: Callable[[dict[str, Any]], Awaitable[str | dict[str, Any]]] | None = None,
        timeout_sec: float = 10.0,
    ) -> dict[str, Any]:
        context = self.build_call_decision_context(event=event, summary=summary)
        return await self.query_2x4_structured_action(
            context,
            query_fn=query_fn,
            timeout_sec=timeout_sec,
        )

    async def dispatch_action_to_engage(
        self,
        action: dict[str, Any],
        *,
        dispatch_fn: Callable[[dict[str, Any]], Awaitable[None]],
        notify_fn: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> bool:
        msg, override_event = self._map_action_to_route_message(action)
        if not msg:
            return False
        if override_event is not None and notify_fn is not None:
            await notify_fn(override_event)
        await dispatch_fn(msg)
        return True

    async def _emit_notify(self, event: dict[str, Any]) -> None:
        if self._notify_fn is None:
            return
        try:
            await self._notify_fn(event)
        except Exception:
            return

    def _cancel_inflight_decision_task(self) -> None:
        task = self._inflight_decision_task
        if task is None:
            return
        if task.done():
            self._inflight_decision_task = None
            return
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        if task is current:
            return
        task.cancel()

    def _fingerprint_event(self, event: dict[str, Any]) -> str:
        blob = json.dumps(event, sort_keys=True, separators=(",", ":"))
        return hashlib.sha1(blob.encode("utf-8")).hexdigest()

    def _parse_action_response(self, raw_response: str | dict[str, Any]) -> dict[str, Any]:
        if isinstance(raw_response, str):
            try:
                parsed = json.loads(raw_response)
            except Exception:
                return {"action": "none", "reason": "invalid_action_json"}
        elif isinstance(raw_response, dict):
            parsed = raw_response
        else:
            return {"action": "none", "reason": "invalid_action_json"}

        if not isinstance(parsed, dict):
            return {"action": "none", "reason": "invalid_action_json"}

        action = str(parsed.get("action") or "").strip().lower()
        if action == "none":
            reason = str(parsed.get("reason") or "no_action").strip() or "no_action"
            return {"action": "none", "reason": reason}
        if action == "continue":
            message = parsed.get("message")
            if isinstance(message, str):
                return {"action": "continue", "message": message}
            return {"action": "none", "reason": "invalid_action_json"}
        if action == "select":
            option = parsed.get("option")
            if not isinstance(option, int):
                return {"action": "none", "reason": "invalid_action_json"}
            result: dict[str, Any] = {"action": "select", "option": option}
            if isinstance(parsed.get("message"), str):
                result["message"] = parsed["message"]
            return result
        if action == "approve":
            approval_type = str(parsed.get("approval_type") or "").strip().lower()
            decision = parsed.get("decision")
            if approval_type not in {
                "token",
                "scope_add",
                "scope_upgrade",
                "script",
                "tool",
            }:
                return {"action": "none", "reason": "invalid_action_json"}
            if not isinstance(decision, str) or not decision.strip():
                return {"action": "none", "reason": "invalid_action_json"}
            result = {
                "action": "approve",
                "approval_type": approval_type,
                "decision": decision.strip(),
            }
            if isinstance(parsed.get("scope_level"), str):
                result["scope_level"] = parsed["scope_level"]
            if isinstance(parsed.get("message"), str):
                result["message"] = parsed["message"]
            return result
        return {"action": "none", "reason": "invalid_action_json"}

    def _map_action_to_route_message(
        self, action: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        action_type = str(action.get("action") or "").strip().lower()
        override_event: dict[str, Any] | None = None
        if action_type == "continue":
            return (
                {
                    "type": "continue",
                    "message": str(action.get("message") or ""),
                    "suppress_chat_echo": True,
                },
                None,
            )
        if action_type == "select":
            option = action.get("option")
            if not isinstance(option, int):
                return None, None
            message = action.get("message")
            if isinstance(message, str):
                return (
                    {
                        "type": "select_with_message",
                        "option": option,
                        "message": message,
                        "suppress_chat_echo": True,
                    },
                    None,
                )
            return (
                {
                    "type": "select",
                    "option": option,
                    "suppress_chat_echo": True,
                },
                None,
            )
        if action_type == "approve":
            approval_type = str(action.get("approval_type") or "").strip().lower()
            msg_type = {
                "token": "approve_token",
                "scope_add": "approve_scope_add",
                "scope_upgrade": "approve_scope_upgrade",
                "script": "approve_script",
                "tool": "approve_tool",
            }.get(approval_type)
            decision = action.get("decision")
            if not msg_type or not isinstance(decision, str):
                return None, None
            normalized_decision = decision
            if approval_type in {"scope_add", "scope_upgrade"} and self.state == "takeover_active":
                normalized_decision = "deny"
                override_event = {
                    "type": "takeover_policy_override",
                    "policy": "force_deny_scope_mutation",
                    "approval_type": approval_type,
                    "requested_decision": decision,
                    "enforced_decision": normalized_decision,
                }
                self.last_policy_override = dict(override_event)
            payload: dict[str, Any] = {
                "type": msg_type,
                "decision": normalized_decision,
                "suppress_chat_echo": True,
            }
            if isinstance(action.get("scope_level"), str):
                payload["scope_level"] = action["scope_level"]
            if isinstance(action.get("message"), str):
                payload["message"] = action["message"]
            return payload, override_event
        return None, None


_TAKEOVER_CONTROLLER_SINGLETON: TakeoverController | None = None


def get_takeover_controller() -> TakeoverController:
    global _TAKEOVER_CONTROLLER_SINGLETON
    if _TAKEOVER_CONTROLLER_SINGLETON is None:
        _TAKEOVER_CONTROLLER_SINGLETON = TakeoverController()
    return _TAKEOVER_CONTROLLER_SINGLETON
