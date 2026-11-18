from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, patch


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from boots import engage


class FakeEngageManager:
    def __init__(self) -> None:
        self.history: list[dict] = []
        self.runner = None
        self.state = "idle"
        self.session_id: str | None = None
        self.pending_approval = None
        self._agent_task = None
        self._findings_filter_future = None
        self._end_step_future = None
        self._end_engagement_running = False
        self.stop_agent_calls = 0
        self.start_agent_calls: list[tuple[str, str]] = []
        self.takeover_controller = SimpleNamespace(disable_takeover=lambda: None)

    def _set_active_body_root(self, bra_root: str | Path) -> Path:
        return Path(bra_root)

    def _sync_settings_root(self, bra_root: str | Path) -> None:
        return None

    def _append_event_log(self, event: dict) -> None:
        return None

    async def broadcast(self, event: dict) -> None:
        self.history.append(dict(event))

    async def clear_history(self) -> None:
        self.history.clear()
        self.history.append({"type": "history_cleared"})

    async def stop_agent(self, cancel_timeout_s: float = 5.0) -> None:
        self.stop_agent_calls += 1
        self.runner = None
        self.state = "idle"

    async def start_agent(self, prompt: str, bra_root: str, model: str | None = None) -> None:
        self.start_agent_calls.append((prompt, bra_root))

    async def resume_agent(
        self,
        bra_root: str,
        session_id: str | None = None,
        prompt: str | None = None,
        model: str | None = None,
    ) -> None:
        return None

    async def clear_history_route(self) -> None:
        await self.clear_history()

    def toggle_kill_switch(self, bra_root: str) -> bool:
        return False

    def pause_agent(self) -> None:
        return None

    async def resolve_approval(self, result: dict) -> None:
        return None

    async def select_option(
        self,
        option: int,
        message: str | None = None,
        force_override: bool = False,
        suppress_echo: bool = False,
    ) -> None:
        return None

    async def continue_with_message(self, message: str, suppress_echo: bool = False) -> None:
        return None

    async def debug_message_to_session(self, message: str, suppress_echo: bool = False) -> None:
        return None

    async def _terminate_all_agent_subprocesses(self, *, reason: str, grace_s: float = 0.75) -> list[int]:
        return []


def _completed_process(*, returncode: int = 0, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _make_project_root() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    body = root / "body"
    (body / ".bra" / "approvals").mkdir(parents=True, exist_ok=True)
    (body / ".bra" / "logs").mkdir(parents=True, exist_ok=True)
    (body / "layer3-engagement").mkdir(parents=True, exist_ok=True)
    return td, root


class EngageEntrypointWiringTests(unittest.IsolatedAsyncioTestCase):
    async def test_growth_route_calls_growth_python_port(self) -> None:
        td, root = _make_project_root()
        with td, patch.object(engage, "_run_script", new=AsyncMock(return_value=0)) as run_script:
            mgr = FakeEngageManager()

            await engage.route_message(mgr, {"type": "growth"}, str(root))

            run_script.assert_awaited_once_with(mgr, str(root), "growth.py", silent=True)

    async def test_packup_route_calls_packup_helper(self) -> None:
        td, root = _make_project_root()
        with td, patch.object(engage, "_run_packup", new=AsyncMock(return_value=None)) as run_packup:
            mgr = FakeEngageManager()

            await engage.route_message(mgr, {"type": "packup", "mode": "full"}, str(root))

            run_packup.assert_awaited_once_with(mgr, str(root), "full")

    async def test_reset_confirm_runs_force_reset_after_session_cleanup(self) -> None:
        td, root = _make_project_root()
        with (
            td,
            patch.object(engage, "_run_script", new=AsyncMock(return_value=0)) as run_script,
            patch.object(engage, "update_session_state") as update_session_state,
        ):
            mgr = FakeEngageManager()
            mgr.runner = object()
            mgr.state = "running"
            mgr.session_id = "session-123"

            await engage.route_message(mgr, {"type": "reset_confirm"}, str(root))

            self.assertEqual(mgr.stop_agent_calls, 1)
            run_script.assert_awaited_once_with(mgr, str(root), "reset.py", "--force", silent=True)
            self.assertEqual(
                update_session_state.mock_calls,
                [call(clear_session=True), call(clear_session=True)],
            )
            self.assertEqual(mgr.history[-1]["type"], "reset_complete")
            self.assertTrue(mgr.history[-1]["success"])

    async def test_voicecall_router_uses_hermes_when_configured(self) -> None:
        with (
            patch.object(
                engage,
                "_load_voicecall_bra_agent_config",
                return_value={"numbuh_2x4_call_agent_provider": "hermes"},
            ),
            patch.object(
                engage,
                "_invoke_voicecall_bra_hermes",
                new=AsyncMock(return_value={"ok": True}),
            ) as hermes_call,
            patch.object(engage, "_invoke_voicecall_bra_gateway", new=AsyncMock()) as openclaw_call,
        ):
            result = await engage._invoke_voicecall_bra("voicecall_bra.status", {"callId": "c1"})

        self.assertEqual(result, {"ok": True})
        hermes_call.assert_awaited_once_with("voicecall_bra.status", {"callId": "c1"}, timeout_ms=10000)
        openclaw_call.assert_not_awaited()

    async def test_voicecall_router_defaults_to_openclaw(self) -> None:
        with (
            patch.object(engage, "_load_voicecall_bra_agent_config", return_value={}),
            patch.object(engage, "_invoke_voicecall_bra_hermes", new=AsyncMock()) as hermes_call,
            patch.object(
                engage,
                "_invoke_voicecall_bra_gateway",
                new=AsyncMock(return_value={"ok": True}),
            ) as openclaw_call,
        ):
            result = await engage._invoke_voicecall_bra("voicecall_bra.status", {"callId": "c1"})

        self.assertEqual(result, {"ok": True})
        openclaw_call.assert_awaited_once_with("voicecall_bra.status", {"callId": "c1"}, timeout_ms=10000)
        hermes_call.assert_not_awaited()

    async def test_run_wizard_runs_precheck_and_dry_run_then_emits_phase(self) -> None:
        td, root = _make_project_root()
        with (
            td,
            patch.object(
                engage,
                "run_script",
                side_effect=[
                    _completed_process(returncode=0, stdout="precheck ok"),
                    _completed_process(returncode=0, stdout="dry run ok"),
                ],
            ) as run_script,
            patch.object(engage, "is_scope_configured", return_value=False),
            patch.object(engage, "_load_token_states", return_value={"WATCH": True}),
        ):
            mgr = FakeEngageManager()

            await engage._run_wizard(mgr, str(root))

            self.assertEqual(
                run_script.call_args_list,
                [
                    call("precheck.py", "--fix", timeout=60),
                    call("dry-run.py", timeout=60),
                ],
            )
            wizard_phase = next(evt for evt in mgr.history if evt.get("type") == "wizard_phase")
            self.assertEqual(wizard_phase["phase"], "privacy_posture")
            self.assertEqual(wizard_phase["tokens"], {"WATCH": True})

    async def test_wizard_launch_agent_runs_agentic_handler_then_starts_agent(self) -> None:
        td, root = _make_project_root()
        with td, patch.object(
            engage,
            "run_script",
            return_value=_completed_process(returncode=0, stdout="handoff prompt"),
        ) as run_script:
            mgr = FakeEngageManager()

            await engage._wizard_launch_agent(mgr, str(root))

            run_script.assert_called_once_with("agentic-handler.py", timeout=30)
            self.assertEqual(mgr.start_agent_calls, [("handoff prompt", str(root))])
            self.assertTrue(any(evt.get("type") == "wizard_complete" for evt in mgr.history))

    async def test_end_engagement_runs_report_pipeline_ports_in_order(self) -> None:
        td, root = _make_project_root()
        body = root / "body"
        report_file = body / "layer3-engagement" / "REPORT.md"
        report_file.write_text("# Report\n\n## Remediation Roadmap\n\nComplete.\n")
        with (
            td,
            patch.object(engage, "load_end_profile", return_value={"report_types": "generic,vendor"}),
            patch.object(engage, "_token_file_exists", return_value=False),
            patch.object(engage, "_run_script", new=AsyncMock(return_value=0)) as run_script,
            patch.object(engage, "update_session_state") as update_session_state,
            patch("bra.core.report_enhance.enhance_reports", new=AsyncMock(return_value={"success": True, "summary": "Reports enhanced"})),
        ):
            mgr = FakeEngageManager()

            await engage._run_end_engagement(mgr, str(root))

            self.assertEqual(
                run_script.await_args_list,
                [
                    call(mgr, str(root), "stats.py", "--full", silent=True),
                    call(mgr, str(root), "report-ready.py", "--types", "generic,vendor", "--non-interactive", silent=True),
                    call(mgr, str(root), "disclose.py", "--types", "generic,vendor", "--non-interactive", silent=True),
                    call(mgr, str(root), "lessons-learned.py", silent=True),
                ],
            )
            self.assertEqual(update_session_state.mock_calls, [call(clear_session=True)])
            self.assertTrue(any(evt.get("type") == "end_engagement_complete" for evt in mgr.history))


if __name__ == "__main__":
    unittest.main()
