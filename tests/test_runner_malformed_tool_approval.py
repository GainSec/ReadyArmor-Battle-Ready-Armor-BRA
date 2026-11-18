from __future__ import annotations

import asyncio
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch


REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_ROOT = REPO_ROOT / "head"
if str(HEAD_ROOT) not in sys.path:
    sys.path.insert(0, str(HEAD_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bra.core.runner import AgentRunner

class RunnerMalformedToolApprovalTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _append_capture_record(
        bra_state_dir: Path,
        *,
        capture_id: str,
        tool_name: str,
        action: str,
        artifact_path: str,
        command: str = "",
        target: str = "",
        source_kind: str = "tool_capture",
    ) -> None:
        index_path = bra_state_dir / "logs" / "evidence_index.jsonl"
        index_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "capture_id": capture_id,
            "session_id": "sess-1",
            "tool_use_id": capture_id,
            "tool_name": tool_name,
            "action": action,
            "target": target,
            "command": command,
            "url": "",
            "method": "",
            "host": "",
            "endpoint": "",
            "target_kind": "file",
            "artifact_path": artifact_path,
            "artifact_sha256": "deadbeef",
            "source_kind": source_kind,
            "created_at": "2026-03-08T18:49:31.250170+00:00",
        }
        with index_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    @staticmethod
    def _make_result_message(result: str, *, is_error: bool = True):
        message = type("ResultMessage", (), {})()
        message.is_error = is_error
        message.result = result
        return message

    @staticmethod
    def _make_assistant_message(text: str):
        block = SimpleNamespace(text=text)
        message = type("AssistantMessage", (), {})()
        message.content = [block]
        return message

    async def test_main_agent_hook_denial_with_unrecoverable_metadata_surfaces_malformed_tool_approval_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            approvals_dir = bra_state_dir / "approvals"
            notes_dir.mkdir(parents=True, exist_ok=True)
            approvals_dir.mkdir(parents=True, exist_ok=True)
            (approvals_dir / "SLOWPATH-FINDINGS").touch()

            blocked_events = []
            seen_errors: list[str] = []

            async def on_blocked_operation(blocked) -> bool:
                blocked_events.append(blocked)
                return False

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_error=seen_errors.append,
                on_blocked_operation=on_blocked_operation,
            )

            user_message = type("UserMessage", (), {})()
            user_message.content = [
                SimpleNamespace(
                    is_error=True,
                    content="Hook PreToolUse:Read denied this tool",
                )
            ]

            with patch("bra.core.runner.write_debug_log"):
                await runner._process_message(user_message)

        self.assertEqual(blocked_events, [])
        self.assertEqual(len(seen_errors), 1)
        self.assertRegex(seen_errors[0], r"(?i)malformed tool approval")
        self.assertRegex(seen_errors[0], r"(?i)\bread\b")

    async def test_cached_tool_use_id_does_not_rehabilitate_explicitly_malformed_unknown_blank_tool_approval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            approvals_dir = bra_state_dir / "approvals"
            notes_dir.mkdir(parents=True, exist_ok=True)
            approvals_dir.mkdir(parents=True, exist_ok=True)
            (approvals_dir / "SLOWPATH-FINDINGS").touch()

            blocked_events = []
            seen_errors: list[str] = []

            async def on_blocked_operation(blocked) -> bool:
                blocked_events.append(blocked)
                return False

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_error=seen_errors.append,
                on_blocked_operation=on_blocked_operation,
            )
            runner._handle_tool_use(
                "Read",
                {"file_path": "/tmp/target.txt", "offset": 12, "limit": 34},
                tool_use_id="toolu_123",
            )

            malformed = "\n".join(
                [
                    "TOOL_APPROVAL_REQUIRED",
                    "TOOL_NAME=unknown",
                    "TOOL_USE_ID=toolu_123",
                    "Command: ",
                    "Reason: Hook emitted malformed approval payload",
                ]
            )

            with patch("bra.core.runner.write_debug_log"):
                await runner._check_for_blocked_operation(malformed)

        self.assertEqual(blocked_events, [])
        self.assertEqual(len(seen_errors), 1)
        self.assertRegex(seen_errors[0], r"(?i)malformed tool approval")

    async def test_findings_subagent_result_forwards_malformed_tool_approval_into_blocked_operation_handling(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            notes_dir.mkdir(parents=True, exist_ok=True)

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
            )

            result_message = type("ResultMessage", (), {})()
            result_message.is_error = True
            result_message.result = "\n".join(
                [
                    "TOOL_APPROVAL_REQUIRED",
                    "TOOL_NAME=unknown",
                    "TOOL_USE_ID=unknown",
                    "Command: ",
                    "Reason: Hook emitted malformed approval payload",
                ]
            )

            blocked_recorder = AsyncMock()

            with patch("bra.core.runner.write_debug_log"), patch.object(
                runner,
                "_check_for_blocked_operation",
                blocked_recorder,
            ):
                runner._surface_subagent_message(result_message, "001")
                await asyncio.sleep(0)

        blocked_recorder.assert_awaited_once_with(
            result_message.result,
            clear_pending_bash_command=False,
        )

    async def test_findings_subagent_malformed_approval_does_not_clear_main_agent_pending_bash_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            approvals_dir = bra_state_dir / "approvals"
            notes_dir.mkdir(parents=True, exist_ok=True)
            approvals_dir.mkdir(parents=True, exist_ok=True)
            (approvals_dir / "SLOWPATH-FINDINGS").touch()

            seen_commands: list[str] = []
            seen_errors: list[str] = []
            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_command=seen_commands.append,
                on_error=seen_errors.append,
            )
            runner._handle_tool_use("Bash", {"command": "echo hi"}, tool_use_id="toolu_bash")

            result_message = type("ResultMessage", (), {})()
            result_message.is_error = True
            result_message.result = "\n".join(
                [
                    "TOOL_APPROVAL_REQUIRED",
                    "TOOL_NAME=unknown",
                    "TOOL_USE_ID=unknown",
                    "Command: ",
                    "Reason: Hook emitted malformed approval payload",
                ]
            )

            with patch("bra.core.runner.write_debug_log"):
                runner._surface_subagent_message(result_message, "001")
                await asyncio.sleep(0)
                await runner._handle_tool_result("ok")

        self.assertEqual(seen_commands, ["echo hi"])
        self.assertEqual(len(seen_errors), 1)
        self.assertRegex(seen_errors[0], r"(?i)malformed tool approval")

    async def test_findings_subagent_malformed_approval_counts_as_failed_attempt_and_handoffs_after_retry_budget(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            approvals_dir = bra_state_dir / "approvals"
            notes_dir.mkdir(parents=True, exist_ok=True)
            approvals_dir.mkdir(parents=True, exist_ok=True)
            (approvals_dir / "SLOWPATH-FINDINGS").touch()

            seen_text: list[str] = []
            seen_errors: list[str] = []
            on_blocked_operation = AsyncMock(return_value=False)

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_text=seen_text.append,
                on_error=seen_errors.append,
                on_blocked_operation=on_blocked_operation,
            )
            runner._finding_enforcer.enqueue_finding(
                "001",
                "HIGH",
                "Malformed approval retry",
                "[FINDING] source: test://finding-001 | attack_surface: Web Service - Missing Authentication | cvss: 8.1",
            )
            reqs_dir = notes_dir / "reqs"
            reqs_dir.mkdir(parents=True, exist_ok=True)
            (reqs_dir / "finding-001-poc.sh").write_text("#!/bin/sh\necho poc\n")

            prompts: list[str] = []
            overconsumed_events: list[int] = []
            malformed = "\n".join(
                [
                    "TOOL_APPROVAL_REQUIRED",
                    "TOOL_NAME=unknown",
                    "TOOL_USE_ID=unknown",
                    "Command: ",
                    "Reason: Hook emitted malformed approval payload",
                ]
            )

            def fake_run_agent(prompt, **_kwargs):
                prompts.append(prompt)
                attempt_number = len(prompts)

                async def gen():
                    yield self._make_result_message(malformed, is_error=True)
                    overconsumed_events.append(attempt_number)
                    yield self._make_assistant_message(f"late-event-attempt-{attempt_number}")

                return gen()

            with patch("bra.core.agent.run_agent", new=fake_run_agent), patch(
                "bra.core.runner.write_debug_log"
            ):
                await runner._run_findings_subagent()

        on_blocked_operation.assert_not_awaited()
        self.assertEqual(len(prompts), 2)
        self.assertEqual(overconsumed_events, [])
        self.assertNotEqual(prompts[0], prompts[1])
        self.assertTrue(runner._findings_handoff_required)
        self.assertEqual(runner._findings_handoff_ids, {"001"})
        self.assertEqual([pf.id for pf in runner._finding_enforcer.pending_queue], ["001"])
        self.assertEqual(len(seen_errors), 2)
        self.assertTrue(all("malformed tool approval" in text.lower() for text in seen_errors))

    async def test_findings_subagent_slowpath_completes_one_written_finding_per_loop(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            approvals_dir = bra_state_dir / "approvals"
            notes_dir.mkdir(parents=True, exist_ok=True)
            approvals_dir.mkdir(parents=True, exist_ok=True)
            (approvals_dir / "SLOWPATH-FINDINGS").touch()

            seen_text: list[str] = []
            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_text=seen_text.append,
            )
            runner._finding_enforcer.enqueue_finding(
                "001",
                "HIGH",
                "First slowpath finding",
                "[FINDING] source: test://finding-001 | attack_surface: Web Service - Missing Authentication | cvss: 8.1",
            )
            runner._finding_enforcer.enqueue_finding(
                "002",
                "MEDIUM",
                "Second slowpath finding",
                "[FINDING] source: test://finding-002 | attack_surface: Web Service - Information Disclosure | cvss: 6.5",
            )
            reqs_dir = notes_dir / "reqs"
            reqs_dir.mkdir(parents=True, exist_ok=True)
            (reqs_dir / "finding-001-poc.sh").write_text("#!/bin/sh\necho poc 001\n")
            (reqs_dir / "finding-002-poc.sh").write_text("#!/bin/sh\necho poc 002\n")

            call_ids: list[str] = []

            def fake_run_agent(prompt, **_kwargs):
                match = re.search(r"FINDING-(\d{3})", prompt)
                self.assertIsNotNone(match)
                finding_id = match.group(1)
                call_ids.append(finding_id)

                async def gen():
                    artifacts_dir = bra_state_dir / "artifacts"
                    artifacts_dir.mkdir(parents=True, exist_ok=True)
                    (artifacts_dir / f"{finding_id}-output.md").write_text(
                        "\n".join(
                            [
                                "1: 306",
                                f"2: Description for FINDING-{finding_id}",
                                f"3: Impact for FINDING-{finding_id}",
                                f"4: Attack vector for FINDING-{finding_id}",
                                f"5: Remediation for FINDING-{finding_id}",
                                f"6: Tooling for FINDING-{finding_id}",
                            ]
                        )
                    )
                    if False:
                        yield None

                return gen()

            with patch("bra.core.agent.run_agent", new=fake_run_agent), patch(
                "bra.core.runner.write_debug_log"
            ):
                await runner._run_findings_subagent()

        self.assertEqual(call_ids, ["001", "002"])
        self.assertEqual(runner._findings_handoff_ids, set())
        self.assertFalse(runner._findings_handoff_required)
        self.assertEqual(runner._finding_enforcer.pending_queue, [])
        self.assertGreaterEqual(len(seen_text), 3)

    async def test_findings_subagent_slowpath_dequeues_finding_with_corrected_origin_capture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            approvals_dir = bra_state_dir / "approvals"
            notes_dir.mkdir(parents=True, exist_ok=True)
            approvals_dir.mkdir(parents=True, exist_ok=True)
            (approvals_dir / "SLOWPATH-FINDINGS").touch()

            seen_text: list[str] = []
            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_text=seen_text.append,
            )

            artifact_rel = ".bra/artifacts/raw/port80_root.html"
            artifact_abs = root / artifact_rel
            artifact_abs.parent.mkdir(parents=True, exist_ok=True)
            artifact_abs.write_text("GET /cgi-bin/factoryreset.cgi HTTP/1.1\n", encoding="utf-8")

            origin_capture_id = "anon_20260308_184959_000003"
            self._append_capture_record(
                bra_state_dir,
                capture_id=origin_capture_id,
                tool_name="Bash",
                action="bash",
                command="curl -sv http://octopus/ -o .bra/artifacts/raw/port80_root.html",
                target="curl -sv http://octopus/ -o .bra/artifacts/raw/port80_root.html",
                artifact_path=str(artifact_abs),
                source_kind="anon_intercept",
            )
            derivative_capture_id = "toolu_01Tvyrwhig8aoXqagkhQXCTZ"
            derivative_artifact = (
                bra_state_dir / "artifacts" / "raw" / "toolu_01tvyrwhig8aoxqagkhqxctz_read_port80_root.html.txt"
            )
            derivative_artifact.parent.mkdir(parents=True, exist_ok=True)
            derivative_artifact.write_text("factoryreset.cgi", encoding="utf-8")
            self._append_capture_record(
                bra_state_dir,
                capture_id=derivative_capture_id,
                tool_name="Read",
                action="read",
                target=str(artifact_abs),
                artifact_path=str(derivative_artifact),
                source_kind="tool_capture",
            )
            runner._latest_tool_capture_id = derivative_capture_id
            runner._latest_tool_source_kind = "tool_capture"

            runner._parse_and_dispatch_text(
                "[FINDING] HIGH: Unauthenticated factory reset endpoint "
                "| cvss: 8.1 | attack_surface: Web Service - Missing Authentication "
                "| capture_id: toolu_01T39vwDSxZYNVyEhZNscAtp\n"
            )
            self.assertIn(
                f"capture_id: {origin_capture_id}",
                runner._finding_enforcer.pending_queue[0].source_marker,
            )
            self.assertNotIn(
                derivative_capture_id,
                runner._finding_enforcer.pending_queue[0].source_marker,
            )

            call_ids: list[str] = []

            def fake_run_agent(prompt, **_kwargs):
                match = re.search(r"FINDING-(\d{3})", prompt)
                self.assertIsNotNone(match)
                finding_id = match.group(1)
                call_ids.append(finding_id)

                async def gen():
                    artifacts_dir = bra_state_dir / "artifacts"
                    artifacts_dir.mkdir(parents=True, exist_ok=True)
                    (artifacts_dir / f"{finding_id}-output.md").write_text(
                        "\n".join(
                            [
                                "1: CWE-306",
                                f"2: Description for FINDING-{finding_id}",
                                f"3: Impact for FINDING-{finding_id}",
                                f"4: Attack vector for FINDING-{finding_id}",
                                f"5: Remediation for FINDING-{finding_id}",
                                f"6: Tooling for FINDING-{finding_id}",
                            ]
                        ),
                        encoding="utf-8",
                    )
                    if False:
                        yield None

                return gen()

            with patch("bra.core.agent.run_agent", new=fake_run_agent), patch(
                "bra.core.runner.write_debug_log"
            ):
                await runner._run_findings_subagent()
            self.assertEqual(call_ids, ["001"])
            self.assertEqual(runner._finding_enforcer.pending_queue, [])
            self.assertFalse(runner._findings_handoff_required)
            reqs_dir = notes_dir / "reqs"
            self.assertTrue((reqs_dir / "finding-001-poc.sh").exists())
            self.assertTrue((reqs_dir / "finding-001-evidence.txt").exists())
            context_text = (reqs_dir / "finding-001-context.md").read_text(encoding="utf-8")
            self.assertIn(f"capture_id: {origin_capture_id}", context_text)
            self.assertNotIn("toolu_01T39vwDSxZYNVyEhZNscAtp", context_text)
            self.assertNotIn(derivative_capture_id, context_text)

    async def test_findings_subagent_launches_agent_with_runner_scoped_body_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            approvals_dir = bra_state_dir / "approvals"
            notes_dir.mkdir(parents=True, exist_ok=True)
            approvals_dir.mkdir(parents=True, exist_ok=True)
            (approvals_dir / "SLOWPATH-FINDINGS").touch()

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
            )
            runner._finding_enforcer.enqueue_finding(
                "001",
                "HIGH",
                "Runner-scoped findings subagent root",
                "[FINDING] source: .bra/artifacts/raw/http_root.txt | cvss: 8.1",
            )

            seen_kwargs: list[dict] = []

            def fake_run_agent(prompt, **kwargs):
                seen_kwargs.append(kwargs)

                async def gen():
                    artifacts_dir = bra_state_dir / "artifacts"
                    artifacts_dir.mkdir(parents=True, exist_ok=True)
                    (artifacts_dir / "001-output.md").write_text(
                        "\n".join(
                            [
                                "1: CWE-306",
                                "2: Description for FINDING-001",
                                "3: Impact for FINDING-001",
                                "4: Attack vector for FINDING-001",
                                "5: Remediation for FINDING-001",
                                "6: Tooling for FINDING-001",
                            ]
                        ),
                        encoding="utf-8",
                    )
                    if False:
                        yield None

                return gen()

            with patch("bra.core.agent.run_agent", new=fake_run_agent), patch(
                "bra.core.runner.write_debug_log"
            ):
                await runner._run_findings_subagent()

        self.assertGreaterEqual(len(seen_kwargs), 1)
        for kwargs in seen_kwargs:
            self.assertEqual(
                kwargs.get("cwd"),
                str(bra_state_dir / "artifacts"),
            )
            self.assertEqual(
                kwargs.get("body_root_override"),
                root,
            )

    async def test_subagent_malformed_approval_does_not_contaminate_following_main_agent_blocked_read_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            approvals_dir = bra_state_dir / "approvals"
            notes_dir.mkdir(parents=True, exist_ok=True)
            approvals_dir.mkdir(parents=True, exist_ok=True)
            (approvals_dir / "SLOWPATH-FINDINGS").touch()

            seen_text: list[str] = []
            seen_errors: list[str] = []
            blocked_events = []
            prompts: list[str] = []
            allowed_tools_seen: list[list[str] | None] = []

            async def on_blocked_operation(blocked) -> bool:
                blocked_events.append(blocked)
                return False

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_text=seen_text.append,
                on_error=seen_errors.append,
                on_blocked_operation=on_blocked_operation,
            )
            runner._finding_enforcer.enqueue_finding(
                "001",
                "HIGH",
                "Pending finding should not contaminate main agent flow",
                "[FINDING] source: test://finding-001 | attack_surface: Web Service - Missing Authentication | cvss: 8.1",
            )

            malformed = "\n".join(
                [
                    "TOOL_APPROVAL_REQUIRED",
                    "TOOL_NAME=unknown",
                    "TOOL_USE_ID=unknown",
                    "Command: ",
                    "Reason: Hook emitted malformed approval payload",
                ]
            )
            result_message = self._make_result_message(malformed, is_error=True)

            with patch("bra.core.runner.write_debug_log"):
                runner._surface_subagent_message(result_message, "001")
                await asyncio.sleep(0)

            self.assertEqual(blocked_events, [])
            self.assertEqual(len(seen_errors), 1)
            self.assertRegex(seen_errors[0], r"(?i)malformed tool approval")
            self.assertFalse(runner._findings_handoff_required)
            self.assertEqual(runner._findings_handoff_ids, set())

            def fake_run_agent(prompt, **kwargs):
                prompts.append(prompt)
                allowed_tools_seen.append(kwargs.get("allowed_tools"))

                async def gen():
                    yield self._make_assistant_message("Main agent still responding.")
                    yield {
                        "type": "tool_use",
                        "name": "Read",
                        "input": {
                            "file_path": "/tmp/normal.txt",
                            "offset": 0,
                            "limit": 20,
                        },
                        "id": "toolu_main_123",
                    }
                    user_message = type("UserMessage", (), {})()
                    user_message.content = [
                        SimpleNamespace(
                            is_error=True,
                            content="Hook PreToolUse:Read denied this tool",
                            tool_use_id="toolu_main_123",
                        )
                    ]
                    yield user_message
                    yield self._make_result_message("Turn complete.", is_error=False)

                return gen()

            with patch("bra.core.runner.get_anthropic_api_key", return_value="test-key"), patch(
                "bra.core.agent.run_agent",
                new=fake_run_agent,
            ), patch("bra.core.runner.write_debug_log"), patch.object(
                runner,
                "_run_findings_subagent",
                new=AsyncMock(),
            ), patch.object(
                runner,
                "_build_findings_handoff_prompt",
                wraps=runner._build_findings_handoff_prompt,
            ) as handoff_prompt_builder:
                await runner.run("Continue the assessment normally.")

        handoff_prompt_builder.assert_not_called()
        self.assertEqual(prompts, ["Continue the assessment normally."])
        self.assertEqual(allowed_tools_seen, [None])
        self.assertFalse(runner._findings_handoff_required)
        self.assertEqual(runner._findings_handoff_ids, set())
        self.assertEqual(len(blocked_events), 1)
        self.assertEqual(blocked_events[0].tool_name, "Read")
        self.assertEqual(blocked_events[0].tool_use_id, "toolu_main_123")
        self.assertEqual(blocked_events[0].command, "/tmp/normal.txt")
        self.assertIn("Main agent still responding.", "".join(seen_text))
        self.assertFalse(any("Findings handoff active" in text for text in seen_text))
        self.assertEqual(len(seen_errors), 1)
        self.assertRegex(seen_errors[0], r"(?i)malformed tool approval")

    async def test_main_agent_findings_takeover_text_is_suppressed_while_subagent_path_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            notes_dir = root / "layer3-engagement" / "NOTES"
            bra_state_dir = root / ".bra"
            approvals_dir = bra_state_dir / "approvals"
            notes_dir.mkdir(parents=True, exist_ok=True)
            approvals_dir.mkdir(parents=True, exist_ok=True)
            (approvals_dir / "SLOWPATH-FINDINGS").touch()

            seen_text: list[str] = []
            seen_options: list[list[str]] = []
            seen_findings: list[tuple[str, str]] = []
            seen_leads: list[str] = []

            runner = AgentRunner(
                notes_dir=notes_dir,
                bra_state_dir=bra_state_dir,
                on_text=seen_text.append,
                on_options=seen_options.append,
                on_finding=lambda severity, message: seen_findings.append((severity, message)),
                on_lead=seen_leads.append,
            )
            runner._findings_subagent_active = True

            assistant_text = (
                "Excellent output — and one item jumps out immediately.\n\n"
                "[INTEL] system_version:202505090939A | source: .bra/artifacts/raw/test.txt\n\n"
                "[FINDING] CRITICAL: Blind command injection in wifi_channel parameter via CGI endpoints | "
                "cvss: 9.8 | attack_surface: Web Service - Injection | capture_id: anon_20260307_094949_609107\n"
                "[LEAD] Test submition.cgi filename parameter for command injection | priority: High\n\n"
                "I now need to write up the full finding record before I can continue. Writing to FINDINGS.md now.\n\n"
                "What would you like to do?\n\n"
                "1. Let me write up the full finding record and then test `submition.cgi?filename=` for injection\n"
                "2. Let me write up the finding record and then verify the wifi_channel injection is live (send a payload)\n"
                "3. Write up the finding record only, then pause for direction\n"
                "4. Pause and review current findings"
            )

            with patch("bra.core.runner.write_debug_log"):
                await runner._process_message(self._make_assistant_message(assistant_text))

        self.assertEqual(len(seen_findings), 1)
        self.assertEqual(seen_findings[0][0], "CRITICAL")
        self.assertIn("wifi_channel parameter", seen_findings[0][1])
        self.assertEqual(len(seen_leads), 1)
        self.assertTrue(runner._finding_enforcer.pending_queue)
        self.assertFalse(
            any("I now need to write up the full finding record" in text for text in seen_text)
        )
        self.assertFalse(any("Writing to FINDINGS.md now" in text for text in seen_text))
        self.assertFalse(any("What would you like to do?" == text.strip() for text in seen_text))
        self.assertEqual(seen_options, [])
        self.assertTrue(
            any("Excellent output" in text for text in seen_text),
            "analytic lead-in should still be shown",
        )


if __name__ == "__main__":
    unittest.main()
