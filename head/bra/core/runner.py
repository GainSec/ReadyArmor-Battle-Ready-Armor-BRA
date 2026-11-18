"""Agent runner - integrates agent with UI.

This module provides the bridge between the agent (core/agent.py) and
the UI (ui/app.py or ui/minimal.py). It handles:

- Parsing agent messages into UI updates
- Managing the agent lifecycle
- Handling user input and options
- PRE-EXECUTION approval flow (mechanical human-in-the-loop)
- BLOCK DETECTION and approval handling

MECHANICAL ENFORCEMENT:
When an operation is blocked by hooks, this module detects the block
from the message stream and triggers the appropriate approval flow.
No operation proceeds without proper approval.
"""

import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Optional, Callable, Any, Awaitable
from dataclasses import dataclass
from enum import Enum

from bra.core.approval import (
    BlockDetector,
    BlockedOperation,
    ApprovalType,
    ApprovalManager,
)
from bra.config.settings import BRA_STATE, get_anthropic_api_key, get_proxy_config
from bra.debug_log import write_debug_log

# Phrases that trigger finding write-up enforcement
_WRITEUP_PATTERNS = [
    re.compile(r"write\s+up\s+findings", re.IGNORECASE),
    re.compile(r"document\s+findings", re.IGNORECASE),
    re.compile(r"findings\s+write-?up", re.IGNORECASE),
    re.compile(r"write\s+findings", re.IGNORECASE),
]

_FINDINGS_DOCUMENTATION_TOOLS = ["Write"]  # Write-only: agent writes output to reqs/finding-NNN-output.md
_FINDINGS_DOCUMENTATION_SYSTEM_PROMPT = (
    "You are a world-class offensive security operator writing detailed technical sections "
    "for a professional penetration testing report. "
    "Write 2-4 sentences of substantive technical content for each numbered field. "
    "Use a single Write call to output the file. Do not read any files."
)
_FINDINGS_SUBAGENT_MAX_ATTEMPTS = 2


def _is_writeup_trigger(text: str) -> bool:
    """Check if user input is a 'write up findings' trigger.

    Args:
        text: User input text

    Returns:
        True if the text matches a write-up trigger phrase
    """
    return any(p.search(text) for p in _WRITEUP_PATTERNS)


def _is_expected_stop_termination_error(error_text: str) -> bool:
    """True when error text matches expected signal-killed process teardown."""
    text = (error_text or "").lower()
    if not text:
        return False
    # Explicit signal names/numbers
    if any(k in text for k in ("sigterm", "sigkill", "sigint", "signal 15",
                                "signal 9", "signal 2", "cancelled")):
        return True
    # Any negative exit code = killed by signal
    if re.search(r"exit.code\s*-\d+", text.replace("_", " ")):
        return True
    return False


_FINDINGS_TAKEOVER_TRIGGER_PATTERNS = [
    re.compile(r"i now need to write up the full finding record", re.IGNORECASE),
    re.compile(r"writing to findings\.md now", re.IGNORECASE),
]

_FINDINGS_TAKEOVER_OPTION_PATTERNS = [
    re.compile(r"write up the full finding record", re.IGNORECASE),
    re.compile(r"write up the finding record", re.IGNORECASE),
]


class MessageType(Enum):
    """Types of messages from the agent."""
    TEXT = "text"
    COMMAND = "command"
    COMMAND_OUTPUT = "output"
    FINDING = "finding"
    LEAD = "lead"
    OPTIONS = "options"
    ERROR = "error"
    PHASE_CHANGE = "phase_change"
    TOOL_USE = "tool_use"
    TOOL_RESULT = "tool_result"
    APPROVAL_NEEDED = "approval_needed"


@dataclass
class AgentMessage:
    """Parsed message from agent for UI consumption."""
    type: MessageType
    content: str
    metadata: dict[str, Any] | None = None


class AgentRunner:
    """Runs the agent and dispatches messages to UI handlers.

    BLOCK DETECTION AND APPROVAL:
    The runner monitors agent messages for blocked operations.
    When a block is detected, it calls on_blocked_operation callback.
    The TUI should show the appropriate approval modal and handle retry.
    """

    def __init__(
        self,
        notes_dir: "Path | None" = None,
        bra_state_dir: "Path | None" = None,
        model: str | None = None,
        on_text: Optional[Callable[[str], None]] = None,
        on_command: Optional[Callable[[str], None]] = None,
        on_output: Optional[Callable[[str], None]] = None,
        on_finding: Optional[Callable[[str, str], None]] = None,
        on_lead: Optional[Callable[[str], None]] = None,
        on_service: Optional[Callable[[str, str, str, str, str], None]] = None,
        on_endpoint: Optional[Callable[[str, str, str, str, str, str], None]] = None,
        on_target: Optional[Callable[[str, str, str], None]] = None,
        on_suggestion: Optional[Callable[[str, str, str], None]] = None,
        on_options: Optional[Callable[[list[str]], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        on_phase_change: Optional[Callable[[str, int], None]] = None,
        on_approval_needed: Optional[Callable[[str, str], asyncio.Future]] = None,
        on_turn_complete: Optional[Callable[[], None]] = None,
        on_session_init: Optional[Callable[[str], None]] = None,
        on_first_assistant_output: Optional[Callable[[], None]] = None,
        on_blocked_operation: Optional[Callable[[BlockedOperation], Awaitable[bool]]] = None,
    ):
        """Initialize runner with UI callbacks.

        Args:
            on_text: Called with agent text output
            on_command: Called with command being executed
            on_output: Called with command output
            on_finding: Called with (severity, message) for findings
            on_lead: Called with lead message
            bra_state_dir: Optional override for .bra state directory.
                Defaults to configured BRA_STATE (body/.bra).
            on_options: Called with list of options
            on_error: Called with error message
            on_phase_change: Called with (phase, progress) on phase updates
            on_approval_needed: Called with (script_path, content), returns Future
            on_turn_complete: Called when agent turn completes (waiting for input)
            on_blocked_operation: CRITICAL - Called when a blocked operation is detected.
                Takes BlockedOperation and returns True if approved (triggers retry).
                This is how TUI handles approval modals for blocked operations.
        """
        self.on_text = on_text or (lambda x: None)
        self.on_command = on_command or (lambda x: None)
        self.on_output = on_output or (lambda x: None)
        self.on_finding = on_finding or (lambda s, m: None)
        self.on_lead = on_lead or (lambda x: None)
        self.on_service = on_service or (lambda p, st, sv, v, src: None)
        self.on_endpoint = on_endpoint or (lambda pa, m, f, r, s, src: None)
        self.on_target = on_target or (lambda p, v, src: None)
        self.on_suggestion = on_suggestion or (lambda d, p, r: None)
        self.on_options = on_options or (lambda x: None)
        self.on_error = on_error or (lambda x: None)
        self.on_phase_change = on_phase_change or (lambda p, pr: None)
        self.on_approval_needed = on_approval_needed
        self.on_turn_complete = on_turn_complete or (lambda: None)
        self.on_session_init = on_session_init or (lambda _sid: None)
        self.on_first_assistant_output = on_first_assistant_output or (lambda: None)
        self.on_blocked_operation = on_blocked_operation  # Handles blocked operations
        self._model = model

        # Internal IntelWriter for mechanical INTEL capture
        self._notes_dir = None
        self._intel_writer = None
        if notes_dir:
            from pathlib import Path
            nd = Path(notes_dir)
            if nd.exists():
                self._notes_dir = nd
                from bra.core.intel_writer import IntelWriter
                self._intel_writer = IntelWriter(nd)

        # Internal FindingEnforcer for mechanical finding documentation
        self._finding_enforcer = None
        if notes_dir:
            from pathlib import Path
            nd = Path(notes_dir)
            if nd.exists():
                bra_state = Path(bra_state_dir) if bra_state_dir else BRA_STATE
                bra_state.mkdir(parents=True, exist_ok=True)
                from bra.core.finding_enforcer import FindingEnforcer
                self._finding_enforcer = FindingEnforcer(nd, bra_state)

        # Approval manager for granting approvals
        self._approval_manager = ApprovalManager()

        self._running = False
        self._paused = False
        self._session_id: Optional[str] = None
        self._awaiting_input = False
        self._blocked_turn_interrupted = False
        self._run_generation = 0
        self._current_options: list[str] = []
        self._pending_input: asyncio.Event | None = None
        self._user_response: str = ""
        self._tools_used_this_turn: list[str] = []  # Track tools for post-turn summary
        self._last_blocked_operation: Optional[BlockedOperation] = None  # For retry
        self._findings_write_pending: bool = False  # Track Write/Edit to FINDINGS.md
        self._findings_subagent_task: asyncio.Task | None = None
        self._findings_subagent_active: bool = False
        self._findings_handoff_required: bool = False
        self._findings_handoff_ids: set[str] = set()
        self._last_reported_pending_findings: int | None = None
        self._tool_inputs_by_use_id: dict[str, dict[str, Any]] = {}
        self._last_tool_input_by_name: dict[str, dict[str, Any]] = {}
        self._last_tool_input_monotonic_by_name: dict[str, float] = {}
        self._stale_tool_input_fallback_seconds: float = 10.0
        # Captures log for resolving marker sources to artifact paths.
        # Keep the path even if the file does not exist yet; it may appear
        # later in the same session after first captured command output.
        from pathlib import Path
        self._bra_state_dir = Path(bra_state_dir) if bra_state_dir else BRA_STATE
        self._captures_log: "Path | None" = self._bra_state_dir / "logs" / "captures.log"
        self._findings_handoff_flag_file = self._bra_state_dir / "findings_handoff_active"

        # Command dedup: buffer Bash command emission until we know it won't be blocked
        self._pending_bash_command: str | None = None
        self._suppress_next_bash_command: bool = False
        self._first_assistant_output_seen = False
        self._last_tool_name: str = ""
        self._last_tool_use_id: str = ""
        self._latest_tool_capture_id: str = ""
        self._latest_tool_source_kind: str = ""
        self._set_findings_handoff_active(False)
        write_debug_log(
            "runner",
            "init",
            model=model or "",
            notes_dir=str(notes_dir) if notes_dir else "",
            has_block_callback=bool(on_blocked_operation),
        )

    def _set_findings_handoff_active(self, active: bool) -> None:
        """Persist findings handoff state for hook-level scope enforcement."""
        try:
            if active:
                self._findings_handoff_flag_file.parent.mkdir(parents=True, exist_ok=True)
                self._findings_handoff_flag_file.touch()
            else:
                self._findings_handoff_flag_file.unlink(missing_ok=True)
        except Exception as exc:
            write_debug_log(
                "runner",
                "findings_handoff_flag_update_error",
                active=active,
                error=str(exc),
            )

    @property
    def is_running(self) -> bool:
        """Check if agent is currently running."""
        return self._running

    @property
    def is_paused(self) -> bool:
        """Check if agent is paused."""
        return self._paused

    @property
    def session_id(self) -> Optional[str]:
        """Get current session ID for resumption."""
        return self._session_id

    @property
    def awaiting_input(self) -> bool:
        """Check if runner is waiting for user input."""
        return self._awaiting_input

    def pause(self) -> None:
        """Pause the agent."""
        self._paused = True

    def resume(self) -> None:
        """Resume the agent."""
        self._paused = False

    def stop(self) -> None:
        """Stop the agent."""
        self._running = False
        # Findings subagent runs in a separate background task and must be
        # cancelled explicitly; otherwise it can continue generating events
        # after operator Stop/Reset/Kill.
        task = self._findings_subagent_task
        if task and not task.done():
            task.cancel()
            write_debug_log("runner", "stop_cancel_findings_subagent")

        # Remove active flag immediately so policy hooks return to normal even
        # before task-finally cleanup runs.
        try:
            if self._finding_enforcer:
                (self._finding_enforcer.bra_state_dir / "findings_subagent_active").unlink(missing_ok=True)
        except Exception:
            pass

    def select_option(self, option_number: int) -> Optional[str]:
        """Select an option by number.

        Args:
            option_number: 1-based option number

        Returns:
            The selected option text, or None if invalid.
        """
        if 1 <= option_number <= len(self._current_options):
            return self._current_options[option_number - 1]
        return None

    def get_options(self) -> list[str]:
        """Get current options list."""
        return self._current_options.copy()

    def _resolve_source_to_artifact(self, source_hint: str) -> str:
        """Resolve a finding source hint to an artifact path via captures.log.

        Searches captures.log for commands matching the source hint and
        returns the relative artifact path from the most recent match.
        Falls back to the original hint if no match is found.
        """
        if not source_hint or not self._captures_log:
            return source_hint
        # Already looks like an artifact path
        if ".bra/artifacts/" in source_hint:
            return source_hint
        if not self._captures_log.exists():
            return source_hint
        try:
            lines = self._captures_log.read_text(errors="replace").splitlines()
        except Exception:
            return source_hint

        # Normalize hint for matching: "getversion.cgi" → search for that in commands
        hint_lower = source_hint.lower().strip()
        terms = [hint_lower] if hint_lower else []
        # Generic shorthand often emitted by models (e.g., "curl /").
        if hint_lower.startswith("curl"):
            terms.append("curl ")
        if hint_lower.startswith("nmap"):
            terms.append("nmap ")
        best_path: str = ""
        for line in reversed(lines):  # Most recent first
            parts = line.split(" | ", 3)
            command = ""
            artifact_path = ""
            if len(parts) >= 4:
                command = parts[2].strip()
                artifact_path = parts[3].strip()
            elif len(parts) >= 3:
                command = parts[1].strip()
                artifact_path = parts[2].strip()
            if not command or not artifact_path:
                continue
            cmd_lower = command.lower()
            if any(term and term in cmd_lower for term in terms):
                best_path = artifact_path
                break

        if not best_path:
            return source_hint

        # Convert absolute path to relative from BRA root
        try:
            from pathlib import Path
            abs_path = Path(best_path)
            if abs_path.is_absolute():
                return str(abs_path.relative_to(self._bra_state_dir.parent))
        except (ValueError, Exception):
            pass
        return best_path

    def _load_last_capture_context(self) -> tuple[str, str]:
        """Load latest capture provenance from .bra/last_capture.json when present."""
        sidecar = self._bra_state_dir / "last_capture.json"
        if not sidecar.exists():
            return "", ""
        try:
            payload = json.loads(sidecar.read_text())
            capture_id = str(payload.get("capture_id", "")).strip()
            if capture_id:
                source_kind = str(payload.get("source_kind", "")).strip()
                if not source_kind and capture_id.lower().startswith("anon_"):
                    source_kind = "anon_intercept"
                return capture_id, source_kind or "tool_capture"
        except Exception:
            return "", ""
        return "", ""

    def _infer_capture_id_from_source(self, source_text: str) -> str:
        """Infer capture_id from source metadata or artifact path tokens."""
        from bra.core.capture_provenance import extract_capture_candidates

        for candidate in extract_capture_candidates(str(source_text or "")):
            if self._is_valid_capture_id(candidate):
                return candidate
        return ""

    @staticmethod
    def _is_valid_capture_id(capture_id: str) -> bool:
        """Accept tool-use and anon-intercept capture IDs."""
        value = str(capture_id or "").strip()
        if not value or value.lower() == "provided_info":
            return False
        return bool(re.fullmatch(r"(toolu|anon)[-_][A-Za-z0-9_]+", value, re.IGNORECASE))

    def _resolve_capture_candidate(self, capture_id: str, source_kind: str = "") -> tuple[str, str, dict[str, Any] | None]:
        """Resolve a candidate capture id into usable provenance."""
        candidate = str(capture_id or "").strip()
        if not self._is_valid_capture_id(candidate):
            return "", "", None

        from bra.core.capture_provenance import resolve_capture

        record = resolve_capture(candidate, self._bra_state_dir)
        if record:
            resolved_kind = str(record.get("source_kind", "") or source_kind or "tool_capture").strip()
            return candidate, resolved_kind or "tool_capture", record

        sidecar = self._bra_state_dir / "last_capture.json"
        if candidate.lower().startswith("anon_") and sidecar.exists():
            try:
                payload = json.loads(sidecar.read_text())
            except Exception:
                payload = {}
            if str(payload.get("capture_id", "")).strip().lower() == candidate.lower():
                resolved_kind = str(payload.get("source_kind", "")).strip() or source_kind or "anon_intercept"
                synthetic = {
                    "capture_id": candidate,
                    "source_kind": resolved_kind,
                    "artifact_path": str(payload.get("path", "")).strip(),
                    "command": str(payload.get("command", "")).strip(),
                    "tool_name": "Bash",
                    "action": "bash",
                }
                return candidate, resolved_kind, synthetic

        return "", "", None

    @staticmethod
    def _provenance_rank(record: dict[str, Any] | None) -> int:
        """Score provenance records so origin captures beat derivative reads."""
        if not isinstance(record, dict):
            return -1
        score = 0
        source_kind = str(record.get("source_kind", "")).strip().lower()
        tool_name = str(record.get("tool_name", "")).strip().lower()
        action = str(record.get("action", "")).strip().lower()
        command = str(record.get("command", "")).strip()

        if source_kind == "anon_intercept":
            score += 100
        if tool_name == "bash" or action == "bash":
            score += 60
        if tool_name == "webfetch":
            score += 50
        if command:
            score += 30
        if tool_name in {"read", "grep", "glob"}:
            score -= 40
        return score

    def _promote_origin_capture(
        self,
        capture_id: str,
        source_kind: str,
        record: dict[str, Any] | None,
    ) -> tuple[str, str, dict[str, Any] | None]:
        """Upgrade low-rank inspection captures to a better origin capture for the same artifact."""
        if not capture_id or not isinstance(record, dict):
            return capture_id, source_kind, record

        current_rank = self._provenance_rank(record)

        target_path = str(record.get("target", "")).strip()
        artifact_path = str(record.get("artifact_path", "")).strip()
        if not target_path and not artifact_path:
            return capture_id, source_kind, record

        if current_rank >= 150:
            return capture_id, source_kind, record

        candidates = {
            value
            for value in (target_path, artifact_path)
            if value
        }
        if not candidates:
            return capture_id, source_kind, record

        index_path = self._bra_state_dir / "logs" / "evidence_index.jsonl"
        if not index_path.exists():
            return capture_id, source_kind, record

        best_id = capture_id
        best_kind = source_kind
        best_record = record
        best_rank = current_rank

        for line_no, line in enumerate(index_path.read_text(encoding="utf-8", errors="replace").splitlines()):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue

            row_targets = {
                str(row.get("target", "")).strip(),
                str(row.get("artifact_path", "")).strip(),
                str(row.get("command", "")).strip(),
            }
            row_targets.discard("")
            if not (row_targets & candidates):
                candidate_names = {Path(value).name for value in candidates if value}
                contains_candidate = any(
                    candidate and candidate in row_target
                    for candidate in candidates
                    for row_target in row_targets
                )
                contains_candidate_name = any(
                    name and name in row_target
                    for name in candidate_names
                    for row_target in row_targets
                )
                if not contains_candidate and not contains_candidate_name:
                    continue

            candidate_id, candidate_kind, candidate_record = self._resolve_capture_candidate(
                str(row.get("capture_id", "")).strip(),
                str(row.get("source_kind", "")).strip(),
            )
            if not candidate_id or not candidate_record:
                continue

            candidate_rank = self._provenance_rank(candidate_record)
            if candidate_rank > best_rank:
                best_id = candidate_id
                best_kind = candidate_kind or source_kind
                best_record = candidate_record
                best_rank = candidate_rank

        return best_id, best_kind, best_record

    def _select_best_provenance_for_hint(self, hint_text: str) -> tuple[str, str]:
        """Return best resolved capture for a source/evidence hint."""
        hint = str(hint_text or "").strip()
        if not hint:
            return "", ""

        index_path = self._bra_state_dir / "logs" / "evidence_index.jsonl"
        if not index_path.exists():
            return "", ""

        tokens = set(re.findall(r"[\w./:-]{3,}", hint.lower()))
        if not tokens:
            return "", ""

        best: tuple[int, int, int, str, str, dict[str, Any]] | None = None
        for line_no, line in enumerate(index_path.read_text(encoding="utf-8", errors="replace").splitlines()):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue

            capture_id = str(row.get("capture_id", "")).strip()
            resolved_id, resolved_kind, resolved_record = self._resolve_capture_candidate(
                capture_id,
                str(row.get("source_kind", "")).strip(),
            )
            if not resolved_id or not resolved_record:
                continue

            searchable = " ".join(
                str(row.get(key, "")).lower()
                for key in ("target", "url", "host", "command", "endpoint", "artifact_path")
            )
            match_score = sum(1 for token in tokens if token in searchable)
            if match_score <= 0:
                continue

            rank_score = self._provenance_rank(resolved_record)
            candidate = (rank_score, match_score, line_no, resolved_id, resolved_kind, resolved_record)
            if best is None or candidate[:3] > best[:3]:
                best = candidate

        if not best:
            return "", ""
        best_id, best_kind, best_record = best[3], best[4], best[5]
        best_id, best_kind, _ = self._promote_origin_capture(best_id, best_kind, best_record)
        return best_id, best_kind

    def _cache_resolved_provenance(self, capture_id: str, source_kind: str = "") -> bool:
        """Cache provenance only when it resolves to real evidence."""
        resolved_id, resolved_kind, record = self._resolve_capture_candidate(capture_id, source_kind)
        if not resolved_id:
            return False

        resolved_id, resolved_kind, record = self._promote_origin_capture(
            resolved_id,
            resolved_kind or source_kind or "tool_capture",
            record,
        )

        current_id, current_kind, current_record = self._resolve_capture_candidate(
            self._latest_tool_capture_id,
            self._latest_tool_source_kind,
        )
        if current_id and current_record:
            current_rank = self._provenance_rank(current_record)
            new_rank = self._provenance_rank(record)
            if new_rank < current_rank:
                return True

        self._latest_tool_capture_id = resolved_id
        self._latest_tool_source_kind = resolved_kind or source_kind or "tool_capture"
        return True

    def _refresh_provenance_from_result(
        self,
        result_text: str = "",
        *,
        tool_use_id: str = "",
    ) -> bool:
        """Refresh latest provenance from the current tool result before stale cache can win."""
        if tool_use_id and self._is_valid_capture_id(tool_use_id):
            self._last_tool_use_id = tool_use_id

        text_hint = str(result_text or "")
        inferred_capture_id = self._infer_capture_id_from_source(text_hint)
        if inferred_capture_id and self._cache_resolved_provenance(inferred_capture_id, "tool_capture"):
            return True

        if self._last_tool_use_id and self._is_valid_capture_id(self._last_tool_use_id):
            if self._cache_resolved_provenance(self._last_tool_use_id, "tool_capture"):
                return True

        sidecar_capture_id, sidecar_source_kind = self._load_last_capture_context()
        if sidecar_capture_id:
            return self._cache_resolved_provenance(sidecar_capture_id, sidecar_source_kind or "tool_capture")

        return False

    def _effective_provenance(self, fields: dict[str, str], source_text: str = "") -> tuple[str, str]:
        """Choose provenance with priority: marker > latest tool > synthetic."""
        marker_capture_id = str(fields.get("capture_id", "") or "").strip()
        marker_source_kind = str(fields.get("source_kind", "") or "").strip()
        from bra.core.capture_provenance import resolve_capture_hint

        source_hint = str(fields.get("source", "") or "").strip()
        if source_hint:
            source_hint = " ; ".join(
                part.strip()
                for part in re.split(r"\s*;\s*", source_hint)
                if part.strip()
                and not re.match(r"^(capture_id|source_kind)\s*:", part.strip(), re.IGNORECASE)
            ).strip()
        fallback_hint = source_text or source_hint
        source_candidate = resolve_capture_hint(self._bra_state_dir, source_hint)
        if source_candidate:
            resolved_id, resolved_kind, _record = self._resolve_capture_candidate(
                source_candidate,
                marker_source_kind or "tool_capture",
            )
            if resolved_id:
                self._cache_resolved_provenance(resolved_id, resolved_kind or "tool_capture")
                return self._latest_tool_capture_id, self._latest_tool_source_kind or "tool_capture"

        # Honor marker-provided capture IDs only when no better source-derived
        # provenance resolved. This prevents stale model-emitted capture_ids from
        # overriding a newer artifact/file source hint on the same marker line.
        resolved_id, resolved_kind, _record = self._resolve_capture_candidate(
            marker_capture_id,
            marker_source_kind or "tool_capture",
        )
        if resolved_id:
            self._cache_resolved_provenance(resolved_id, resolved_kind or "tool_capture")
            return self._latest_tool_capture_id, self._latest_tool_source_kind or "tool_capture"

        resolved_id, resolved_kind = self._select_best_provenance_for_hint(source_hint or fallback_hint)
        if resolved_id:
            self._cache_resolved_provenance(resolved_id, resolved_kind or "tool_capture")
            return self._latest_tool_capture_id, self._latest_tool_source_kind or "tool_capture"

        # Prefer explicit/source-derived capture hints on each marker line over
        # stale in-memory context from prior tool executions.
        inferred_capture_id = self._infer_capture_id_from_source(source_hint or fallback_hint)
        if inferred_capture_id:
            resolved_id, resolved_kind, _record = self._resolve_capture_candidate(
                inferred_capture_id,
                marker_source_kind or "tool_capture",
            )
            if resolved_id:
                self._cache_resolved_provenance(resolved_id, resolved_kind or "tool_capture")
                return self._latest_tool_capture_id, self._latest_tool_source_kind or "tool_capture"

        # Tier 1.5: Use _last_tool_use_id only when it resolves to evidence.
        if (
            not self._latest_tool_capture_id
            and self._last_tool_use_id
            and self._cache_resolved_provenance(self._last_tool_use_id, "tool_capture")
        ):
            return (
                self._latest_tool_capture_id,
                self._latest_tool_source_kind or "tool_capture",
            )

        if not self._latest_tool_capture_id:
            # New runner instances (or SDK message-shape drift) may parse markers
            # before a tool_result event is observed. Hydrate from sidecar so
            # capture_id propagation stays mechanical across turns.
            sidecar_capture_id, sidecar_source_kind = self._load_last_capture_context()
            self._cache_resolved_provenance(sidecar_capture_id, sidecar_source_kind or "tool_capture")

        if self._latest_tool_capture_id:
            cached_id, cached_kind, cached_record = self._resolve_capture_candidate(
                self._latest_tool_capture_id,
                self._latest_tool_source_kind,
            )
            if cached_id and cached_record:
                cached_id, cached_kind, _ = self._promote_origin_capture(
                    cached_id,
                    cached_kind or self._latest_tool_source_kind or "tool_capture",
                    cached_record,
                )
                self._latest_tool_capture_id = cached_id
                self._latest_tool_source_kind = cached_kind or self._latest_tool_source_kind or "tool_capture"
                return (
                    self._latest_tool_capture_id,
                    self._latest_tool_source_kind or "tool_capture",
                )

        # Fuzzy match against evidence index using marker/title text only when
        # stronger source-derived and cached provenance failed.
        hint = source_text or fields.get("source", "") or fields.get("title", "")
        resolved_id, resolved_kind = self._select_best_provenance_for_hint(hint)
        if resolved_id:
            self._cache_resolved_provenance(resolved_id, resolved_kind or "tool_capture")
            return self._latest_tool_capture_id, self._latest_tool_source_kind or "tool_capture"

        return "", marker_source_kind or "tool_capture"

    def _canonicalize_marker_provenance(
        self,
        capture_id: str,
        source_kind: str,
        source: str,
    ) -> tuple[str, str, str]:
        """Normalize marker provenance so persisted events keep canonical capture metadata."""
        resolved_id = str(capture_id or "").strip()
        resolved_kind = str(source_kind or "").strip() or "tool_capture"
        normalized_source = str(source or "").strip()

        record: dict[str, Any] | None = None
        if resolved_id:
            resolved_id, resolved_kind, record = self._resolve_capture_candidate(
                resolved_id,
                resolved_kind,
            )

        if not resolved_id and normalized_source:
            source_capture_id = self._infer_capture_id_from_source(normalized_source)
            if source_capture_id:
                resolved_id, resolved_kind, record = self._resolve_capture_candidate(
                    source_capture_id,
                    resolved_kind,
                )

        artifact_path = ""
        if isinstance(record, dict):
            artifact_path = str(record.get("artifact_path", "")).strip()

        if artifact_path:
            try:
                from pathlib import Path

                artifact_rel = str(Path(artifact_path).relative_to(self._bra_state_dir.parent))
            except (ValueError, TypeError):
                artifact_rel = artifact_path

            if not normalized_source or normalized_source == resolved_id:
                normalized_source = artifact_rel
            resolved_kind = str(record.get("source_kind", "") or resolved_kind or "tool_capture").strip()

        if resolved_id.lower().startswith("anon_") and resolved_kind == "tool_capture":
            resolved_kind = "anon_intercept"

        return resolved_id, resolved_kind or "tool_capture", normalized_source

    @staticmethod
    def _normalize_finding_source_marker(
        marker_line: str,
        capture_id: str,
        source_kind: str,
    ) -> str:
        """Return a finding marker with deterministic capture provenance tokens."""
        marker = str(marker_line or "").strip()
        if not marker:
            marker = "[FINDING]"

        if capture_id:
            if re.search(r"\bcapture_id\s*:", marker, re.IGNORECASE):
                marker = re.sub(
                    r"\bcapture_id\s*:\s*([A-Za-z0-9._-]+)",
                    f"capture_id: {capture_id}",
                    marker,
                    count=1,
                    flags=re.IGNORECASE,
                )
            else:
                marker += f" | capture_id: {capture_id}"

        if source_kind and source_kind != "provided_info":
            if re.search(r"\bsource_kind\s*:", marker, re.IGNORECASE):
                marker = re.sub(
                    r"\bsource_kind\s*:\s*([A-Za-z0-9._-]+)",
                    f"source_kind: {source_kind}",
                    marker,
                    count=1,
                    flags=re.IGNORECASE,
                )
            else:
                marker += f" | source_kind: {source_kind}"

        return marker

    def _materialize_notes_from_events(self) -> None:
        """Replay marker events into FINDINGS/INTEL/LEADS in deterministic order."""
        if not self._notes_dir:
            return
        try:
            from bra.core.findings_materializer import materialize_findings_from_events
            from bra.core.notes_materializer import replay_marker_events_to_notes

            materialize_findings_from_events(self._notes_dir, self._bra_state_dir)
            replay_marker_events_to_notes(self._notes_dir, self._bra_state_dir)
        except Exception as exc:
            write_debug_log("runner", "notes_materializer_error", error=str(exc))

    def _handle_writeup_trigger(self) -> None:
        """Check for undocumented findings and enqueue them.

        Called when user input matches a write-up trigger phrase.
        Uses FindingEnforcer.check_undocumented() to scan INTEL.md
        against FINDINGS.md and enqueue any gaps.
        """
        self._sync_undocumented_findings()

    def _sync_undocumented_findings(self) -> int:
        """Sync undocumented INTEL findings into the pending queue.

        Returns:
            Number of newly enqueued findings.
        """
        if not self._finding_enforcer:
            return 0

        before = len(self._finding_enforcer.pending_queue)
        undocumented = self._finding_enforcer.check_undocumented()
        for finding in undocumented:
            self._finding_enforcer.enqueue_finding(
                finding.id,
                finding.severity,
                finding.title,
                finding.source_marker,
            )
        after = len(self._finding_enforcer.pending_queue)
        return max(0, after - before)

    def _emit_findings_progress(
        self, pending_total: int, *, alert: bool = False, force_complete: bool = False
    ) -> None:
        """Emit user-facing finding progress in Engage chat."""
        previous = self._last_reported_pending_findings

        if pending_total > 0:
            if alert:
                if previous != pending_total:
                    self.on_text(f"Finding Alert! Pending Findings: {pending_total}")
            elif previous != pending_total:
                self.on_text(f"Pending Findings: {pending_total}")
        elif (previous and previous > 0) or force_complete:
            self.on_text("Findings write up complete. Blocker removed. Continuing.")

        self._last_reported_pending_findings = pending_total

    def _surface_subagent_message(
        self,
        message: Any,
        finding_id: str,
        *,
        schedule_blocked_check: bool = True,
    ) -> None:
        """Log findings subagent messages to debug log (not shown in UI)."""
        if isinstance(message, dict):
            msg_type = message.get("type", "")
            if msg_type == "error":
                write_debug_log(
                    "runner", "findings_subagent_message_error",
                    finding_id=finding_id, content=str(message.get("content", "")),
                )
            return

        msg_class = type(message).__name__

        if msg_class == "AssistantMessage":
            content = getattr(message, "content", []) or []
            for block in content:
                if hasattr(block, "text") and block.text:
                    write_debug_log(
                        "runner", "findings_subagent_text",
                        finding_id=finding_id, text=str(block.text).strip()[:500],
                    )
                    continue
                tool_name = str(getattr(block, "name", "") or "")
                if tool_name:
                    tool_input = getattr(block, "input", {}) or {}
                    write_debug_log(
                        "runner", "findings_subagent_tool_use",
                        finding_id=finding_id, tool=tool_name,
                        file_path=tool_input.get("file_path", "") if tool_name == "Write" else "",
                    )

        elif msg_class == "ResultMessage":
            is_error = bool(getattr(message, "is_error", False))
            result = str(getattr(message, "result", "") or "")
            if result:
                write_debug_log(
                    "runner", "findings_subagent_result",
                    finding_id=finding_id, is_error=is_error, result=result[:500],
                )
                if is_error and schedule_blocked_check:
                    asyncio.create_task(
                        self._check_for_blocked_operation(
                            result,
                            clear_pending_bash_command=False,
                        )
                    )

    async def _run_findings_subagent(self) -> None:
        """Background task: subagent documents all pending findings."""
        from bra.core.agent import run_agent

        FINDING_STALL_CHECK_SECONDS = 120
        enforcer = self._finding_enforcer
        if not enforcer:
            return

        self._findings_subagent_active = True
        # Write flag file so finding_guard hook allows main agent through
        flag_file = enforcer.bra_state_dir / "findings_subagent_active"
        try:
            flag_file.touch()
            write_debug_log("runner", "findings_subagent_start", pending=len(enforcer.pending_queue))

            while enforcer.pending_queue:
                if self._findings_handoff_required:
                    write_debug_log(
                        "runner",
                        "findings_subagent_handoff_skip",
                        pending=len(enforcer.pending_queue),
                    )
                    break
                if enforcer.is_fastpath_enabled():
                    preflight_dequeued = enforcer.check_and_dequeue_completed()
                    if preflight_dequeued:
                        ids = ", ".join(f"FINDING-{fid}" for fid in preflight_dequeued)
                        self.on_text(f"[dim]Findings fastpath: validated {ids}[/]")
                        self._emit_findings_progress(
                            len(enforcer.pending_queue),
                            force_complete=len(enforcer.pending_queue) == 0,
                        )
                        write_debug_log(
                            "runner",
                            "findings_fastpath_dequeued",
                            finding_ids=preflight_dequeued,
                        )
                        continue

                current = enforcer.pending_queue[0]
                pending = list(enforcer.pending_queue)

                doc_prompt = enforcer.get_documentation_prompt(current, all_pending=pending)
                self.on_text(f"[dim]Findings subagent: documenting FINDING-{current.id}...[/]")

                # Delete any leftover output file so the agent always writes fresh
                output_file = self._bra_state_dir / "artifacts" / f"{current.id}-output.md"
                if output_file.exists():
                    output_file.unlink(missing_ok=True)

                max_attempts = _FINDINGS_SUBAGENT_MAX_ATTEMPTS
                for attempt in range(max_attempts):
                    last_event_at = time.time()
                    event_count = 0
                    stalled = False
                    malformed_tool_approval = False
                    agent_stream = run_agent(
                        doc_prompt,
                        allowed_tools=_FINDINGS_DOCUMENTATION_TOOLS,
                        system_prompt=_FINDINGS_DOCUMENTATION_SYSTEM_PROMPT,
                        cwd=str(self._bra_state_dir / "artifacts"),
                        body_root_override=self._bra_state_dir.parent,
                    ).__aiter__()
                    while True:
                        try:
                            _message = await asyncio.wait_for(
                                agent_stream.__anext__(),
                                timeout=FINDING_STALL_CHECK_SECONDS,
                            )
                            last_event_at = time.time()
                            event_count += 1
                            msg_class = type(_message).__name__
                            if msg_class == "ResultMessage":
                                is_error = bool(getattr(_message, "is_error", False))
                                result = str(getattr(_message, "result", "") or "")
                                if is_error and result:
                                    _, malformed_tool_approval = await self._check_for_blocked_operation(
                                        result,
                                        clear_pending_bash_command=False,
                                    )
                            self._surface_subagent_message(
                                _message,
                                current.id,
                                schedule_blocked_check=False,
                            )
                            if malformed_tool_approval:
                                self.on_text(
                                    f"[yellow]Findings subagent: malformed tool approval for "
                                    f"FINDING-{current.id}; attempt {attempt + 1}/{max_attempts} failed[/]"
                                )
                                break
                        except StopAsyncIteration:
                            break
                        except TimeoutError:
                            last_event_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(last_event_at))
                            idle_seconds = max(0, int(time.time() - last_event_at))
                            self.on_text(
                                f"[yellow]Findings subagent idle: FINDING-{current.id} "
                                f"(last event {last_event_utc}, idle {idle_seconds}s)[/]"
                            )
                            write_debug_log(
                                "runner",
                                "findings_subagent_idle",
                                finding_id=current.id,
                                attempt=attempt + 1,
                                stall_check_seconds=FINDING_STALL_CHECK_SECONDS,
                                last_event_utc=last_event_utc,
                                idle_seconds=idle_seconds,
                                event_count=event_count,
                            )
                            self.on_text(
                                f"[yellow]Findings subagent stalled: FINDING-{current.id} "
                                f"idle {FINDING_STALL_CHECK_SECONDS}s; handing off to main agent[/]"
                            )
                            write_debug_log(
                                "runner",
                                "findings_subagent_handoff_idle",
                                finding_id=current.id,
                                attempt=attempt + 1,
                                idle_seconds=idle_seconds,
                                stall_check_seconds=FINDING_STALL_CHECK_SECONDS,
                                event_count=event_count,
                            )
                            self._findings_handoff_required = True
                            self._findings_handoff_ids.add(current.id)
                            self._set_findings_handoff_active(True)
                            stalled = True
                            break
                    if stalled:
                        break

                    # SLOWPATH: merge numbered output file into FINDINGS.md before validation
                    if enforcer.is_slowpath_enabled():
                        merged = enforcer.merge_finding_output(current.id)
                        write_debug_log(
                            "runner",
                            "findings_slowpath_merge",
                            finding_id=current.id,
                            merged=merged,
                        )
                        if merged:
                            self.on_text(
                                f"[dim]Findings subagent: merged output for FINDING-{current.id}[/]"
                            )
                        else:
                            self.on_text(
                                f"[yellow]Findings subagent: no output file found for FINDING-{current.id}[/]"
                            )

                    # Check if finding was written and is valid
                    dequeued = enforcer.check_and_dequeue_completed()
                    if dequeued:
                        ids = ", ".join(f"FINDING-{fid}" for fid in dequeued)
                        self.on_text(f"[dim]Findings subagent: validated {ids}[/]")
                        self._emit_findings_progress(
                            len(enforcer.pending_queue),
                            force_complete=len(enforcer.pending_queue) == 0,
                        )
                        write_debug_log("runner", "findings_subagent_dequeued", finding_ids=dequeued)
                        break
                    else:
                        # Validation failed — build feedback prompt for retry
                        result = enforcer.validate_finding_record(current.id)
                        if attempt < max_attempts - 1:
                            validation_feedback = (
                                "; ".join(result.errors).replace("LIKELIHOOD_RATIONALE", "LIKELIHOOD")
                                or ", ".join(result.missing_fields)
                            )
                            feedback = validation_feedback
                            if malformed_tool_approval:
                                allowed_flow_feedback = (
                                    "Malformed tool approval detected. Move on using only the allowed findings flow: "
                                    "use a single Write call, do not request approval, and do not use any tools "
                                    "other than Write."
                                )
                                if enforcer.is_slowpath_enabled():
                                    allowed_flow_feedback += (
                                        f" Write {current.id}-output.md in the current working directory."
                                    )
                                else:
                                    allowed_flow_feedback += (
                                        f" Write the required finding content into {enforcer.findings_path}."
                                    )
                                if validation_feedback:
                                    feedback = f"{allowed_flow_feedback} Remaining validation errors: {validation_feedback}"
                                else:
                                    feedback = allowed_flow_feedback
                                self.on_text(
                                    f"[yellow]Findings subagent: retrying FINDING-{current.id} using only the "
                                    f"allowed findings flow ({attempt + 2}/{max_attempts})[/]"
                                )
                            if enforcer.is_slowpath_enabled():
                                if malformed_tool_approval:
                                    doc_prompt = (
                                        f"Your previous attempt for FINDING-{current.id} triggered a malformed tool approval.\n"
                                        "Move on using only the allowed findings flow.\n"
                                        "- Allowed tool: Write only\n"
                                        "- Required action: Write the numbered fields into "
                                        f"{current.id}-output.md in the current working directory\n"
                                        "- Do not request approval\n"
                                        "- Do not use any tools other than Write\n"
                                        f"Validation errors: {feedback}\n\n"
                                        f"{enforcer.get_documentation_prompt(current, all_pending=pending)}"
                                    )
                                else:
                                    doc_prompt = (
                                        f"Your previous output for FINDING-{current.id} was incomplete or missing.\n"
                                        f"Validation errors: {feedback}\n\n"
                                        f"{enforcer.get_documentation_prompt(current, all_pending=pending)}"
                                    )
                            else:
                                if malformed_tool_approval:
                                    doc_prompt = (
                                        f"Your previous attempt for FINDING-{current.id} triggered a malformed tool approval.\n"
                                        "Move on using only the allowed findings flow.\n"
                                        "- Allowed tool: Write only\n"
                                        f"- Required action: Fix the record in {enforcer.findings_path}\n"
                                        "- Do not request approval\n"
                                        "- Do not use any tools other than Write\n"
                                        f"Validation errors: {feedback}\n\n"
                                        f"{enforcer.get_documentation_prompt(current, all_pending=pending)}"
                                    )
                                else:
                                    doc_prompt = (
                                        f"Your previous finding record for FINDING-{current.id} is incomplete.\n"
                                        f"Validation errors: {feedback}\n\n"
                                        f"Fix the record in {enforcer.findings_path} and ensure all fields are filled.\n"
                                        f"{enforcer.get_documentation_prompt(current, all_pending=pending)}"
                                    )
                            write_debug_log(
                                "runner", "findings_subagent_retry",
                                finding_id=current.id, attempt=attempt + 1, feedback=feedback,
                            )
                        else:
                            self.on_text(
                                f"[yellow]Findings subagent: FINDING-{current.id} incomplete "
                                f"after {max_attempts} attempts[/]"
                            )
                            self.on_text(
                                "[yellow]Findings handoff active: main agent must complete pending findings in "
                                "FINDINGS.md[/]"
                            )
                            write_debug_log(
                                "runner", "findings_subagent_max_attempts",
                                finding_id=current.id,
                                max_attempts=max_attempts,
                            )
                            write_debug_log(
                                "runner",
                                "findings_subagent_handoff",
                                finding_id=current.id,
                                pending_total=len(enforcer.pending_queue),
                            )
                            self._findings_handoff_required = True
                            self._findings_handoff_ids.add(current.id)
                            self._set_findings_handoff_active(True)
                            break
                if self._findings_handoff_required:
                    break

            if not enforcer.pending_queue:
                self.on_text("[dim]Findings subagent: all findings documented.[/]")
                write_debug_log("runner", "findings_subagent_complete")
        except BaseException as exc:
            # Collect all error texts (handles ExceptionGroup wrapping)
            error_texts = []
            if hasattr(exc, "exceptions"):  # ExceptionGroup
                for sub in exc.exceptions:
                    error_texts.append(str(sub))
            error_texts.append(str(exc))
            full_error = " ".join(error_texts)

            is_expected = (
                isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt))
                or _is_expected_stop_termination_error(full_error)
            )
            if is_expected:
                write_debug_log("runner", "findings_subagent_sigterm_suppressed", error=full_error)
            else:
                self.on_text(f"[red]Findings subagent error: {exc}[/]")
                write_debug_log("runner", "findings_subagent_error", error=full_error)
        finally:
            self._findings_subagent_active = False
            self._findings_subagent_task = None
            flag_file.unlink(missing_ok=True)

    def _clear_findings_handoff_if_resolved(self) -> None:
        """Disable handoff mode once no pending findings remain."""
        if not self._finding_enforcer or self._finding_enforcer.pending_queue:
            return
        if self._findings_handoff_required or self._findings_handoff_ids:
            write_debug_log(
                "runner",
                "findings_handoff_cleared",
                previous_ids=sorted(self._findings_handoff_ids),
            )
        self._findings_handoff_required = False
        self._findings_handoff_ids.clear()
        self._set_findings_handoff_active(False)

    def _build_findings_handoff_prompt(self, user_prompt: str) -> str:
        """Build forced findings-only prompt used after subagent handoff."""
        if not self._finding_enforcer:
            return user_prompt
        pending_ids = ", ".join(
            f"FINDING-{pf.id}" for pf in self._finding_enforcer.pending_queue
        ) or "none"
        findings_path = str(self._finding_enforcer.findings_path)
        reqs_dir = str(self._finding_enforcer.reqs_dir)
        bra_state = self._bra_state_dir
        evidence_index = str(bra_state / "logs" / "evidence_index.jsonl")
        captures_log = str(bra_state / "logs" / "captures.log")
        artifacts_raw = str(bra_state / "artifacts" / "raw")

        capture_rows: list[str] = []
        for pf in self._finding_enforcer.pending_queue:
            marker = pf.source_marker or ""
            match = re.search(r"capture_id:\s*([A-Za-z0-9._-]+)", marker, re.IGNORECASE)
            capture_id = match.group(1) if match else "unresolved"
            capture_rows.append(
                f"- FINDING-{pf.id}: capture_id={capture_id} | source_marker={marker or 'N/A'}"
            )
        capture_block = "\n".join(capture_rows) or "- none"
        return (
            "FINDINGS HANDOFF MODE\n"
            "The findings subagent did not finish required documentation.\n"
            f"Complete pending findings now: {pending_ids}\n"
            "Capture provenance for deterministic evidence lookup:\n"
            f"{capture_block}\n"
            "Resolve capture data using:\n"
            f"- evidence index: {evidence_index}\n"
            f"- capture commands: {captures_log}\n"
            f"- raw artifacts: {artifacts_raw}\n"
            f"Primary file: {findings_path}\n"
            f"Supporting files: {reqs_dir}\n"
            "Use only Read, Glob, Grep, Write, Edit. Do not run recon/testing tools.\n"
            "Finish pending findings until validator dequeues them.\n\n"
            f"Original user prompt:\n{user_prompt}"
        )

    async def run(self, prompt: str, resume_session: Optional[str] = None) -> None:
        """Run the agent with the given prompt.

        This runs a single turn. When options are detected and the turn
        completes, on_turn_complete is called and the runner waits for
        continue_with_input() to be called.

        Args:
            prompt: Initial prompt for the agent
            resume_session: Session ID to resume
        """
        api_key = get_anthropic_api_key()
        write_debug_log(
            "runner",
            "run_start",
            resume_session=resume_session or "",
            prompt_preview=prompt[:160],
            api_key_present=bool(api_key),
        )
        if not api_key:
            proxy_cfg = get_proxy_config()
            if proxy_cfg["proxy_enabled"]:
                api_key = "proxy-routed"
            else:
                self._running = False
                self._awaiting_input = False
                self.on_error("ANTHROPIC_API_KEY is required. Engagement launch blocked.")
                write_debug_log("runner", "run_abort_missing_api_key")
                return
        # Normalize to a non-empty key so downstream SDK/CLI never falls back.
        os.environ["ANTHROPIC_API_KEY"] = api_key

        from bra.core.agent import run_agent

        # Reconcile stale pending queue entries from prior sessions. If records
        # are already complete in FINDINGS.md, clear them before this turn.
        # First, sweep for unmerged output files left by SIGTERM'd subagents.
        if self._finding_enforcer and self._finding_enforcer.pending_queue:
            artifacts_dir = self._bra_state_dir / "artifacts"
            for pf in list(self._finding_enforcer.pending_queue):
                output_file = artifacts_dir / f"{pf.id}-output.md"
                if output_file.exists():
                    merged = self._finding_enforcer.merge_finding_output(pf.id)
                    if merged:
                        write_debug_log(
                            "runner",
                            "run_start_sweep_merged",
                            finding_id=pf.id,
                        )
            reconciled = self._finding_enforcer.check_and_dequeue_completed()
            if reconciled:
                write_debug_log(
                    "runner",
                    "run_reconciled_pending_findings",
                    dequeued=reconciled,
                    remaining=len(self._finding_enforcer.pending_queue),
                )
                self._emit_findings_progress(len(self._finding_enforcer.pending_queue))
            self._clear_findings_handoff_if_resolved()


        # Always sync undocumented findings before each turn so INTEL.md
        # entries (including compatibility sections) reliably trigger lock.
        newly_enqueued = self._sync_undocumented_findings()
        if newly_enqueued:
            write_debug_log(
                "runner",
                "run_undocumented_findings_enqueued",
                count=newly_enqueued,
                pending_total=len(self._finding_enforcer.pending_queue) if self._finding_enforcer else 0,
            )
            self._emit_findings_progress(len(self._finding_enforcer.pending_queue), alert=True)

        # Check for finding write-up trigger
        if _is_writeup_trigger(prompt):
            write_debug_log("runner", "run_writeup_trigger_detected")
            self._handle_writeup_trigger()

        effective_prompt = prompt
        allowed_tools: list[str] | None = None
        # Spawn findings subagent if pending findings exist (non-blocking)
        if self._finding_enforcer and self._finding_enforcer.pending_queue:
            self._emit_findings_progress(len(self._finding_enforcer.pending_queue), alert=True)
            if self._findings_handoff_required:
                allowed_tools = list(_FINDINGS_DOCUMENTATION_TOOLS)
                effective_prompt = self._build_findings_handoff_prompt(prompt)
                self.on_text(
                    "[yellow]Findings handoff active: main agent restricted to findings documentation tools.[/]"
                )
                write_debug_log(
                    "runner",
                    "findings_handoff_mode",
                    pending_total=len(self._finding_enforcer.pending_queue),
                    pending_ids=[pf.id for pf in self._finding_enforcer.pending_queue],
                    allowed_tools=allowed_tools,
                )
            elif not self._findings_subagent_active and not self._findings_subagent_task:
                self._findings_subagent_task = asyncio.create_task(
                    self._run_findings_subagent()
                )
                write_debug_log(
                    "runner",
                    "findings_subagent_spawned",
                    pending_total=len(self._finding_enforcer.pending_queue),
                )

        self._run_generation += 1
        run_generation = self._run_generation
        self._running = True
        self._awaiting_input = False
        self._blocked_turn_interrupted = False
        self._tools_used_this_turn = []  # Reset tool tracking
        self._first_assistant_output_seen = False

        try:
            async for message in run_agent(
                effective_prompt,
                allowed_tools=allowed_tools,
                resume_session=resume_session,
                model=self._model,
            ):
                write_debug_log("runner", "message_received", message_type=type(message).__name__)
                if run_generation != self._run_generation or not self._running:
                    break

                while self._paused:
                    await asyncio.sleep(0.1)
                    if run_generation != self._run_generation or not self._running:
                        break

                await self._process_message(message)

            # Turn complete - pause for user input
            # Only set if not already set by options detection
            if (
                run_generation == self._run_generation
                and not self._awaiting_input
                and not self._blocked_turn_interrupted
            ):
                self._awaiting_input = True
                self._emit_fallback_options_if_missing()

                # Show turn summary
                if self._tools_used_this_turn:
                    self.on_text(f"\n[dim]── Turn complete ({len(self._tools_used_this_turn)} tools executed) ──[/]")
                else:
                    self.on_text("\n[dim]── Turn complete ──[/]")

                self.on_turn_complete()

        except asyncio.CancelledError:
            write_debug_log("runner", "run_cancelled")
            raise
        except Exception as e:
            error_text = str(e)
            if _is_expected_stop_termination_error(error_text):
                write_debug_log(
                    "runner",
                    "run_exception_suppressed_expected_stop",
                    error=error_text,
                )
            else:
                write_debug_log("runner", "run_exception", error=error_text)
                self.on_error(f"Agent error: {error_text}")
        finally:
            if not self._awaiting_input:
                self._running = False
            write_debug_log(
                "runner",
                "run_finish",
                awaiting_input=self._awaiting_input,
                running=self._running,
                tools_this_turn=len(self._tools_used_this_turn),
            )

    async def continue_with_input(self, user_input: str) -> None:
        """Continue the session with user's input.

        Call this after user selects an option or provides custom input.
        Resumes the session using the stored session_id.

        Args:
            user_input: The user's selection or custom input text
        """
        if not self._session_id:
            write_debug_log("runner", "continue_fail_no_session", input_preview=user_input[:120])
            self.on_error("No session to resume. Start a new session first.")
            return

        self._awaiting_input = False
        self._current_options = []

        # Run new turn with user's input, resuming the session
        await self.run(user_input, resume_session=self._session_id)
        write_debug_log(
            "runner",
            "continue_with_input",
            session_id=self._session_id,
            input_preview=user_input[:120],
        )

    async def _process_message(self, message: Any) -> None:
        """Process a message from the agent.

        Args:
            message: Message from agent SDK
        """
        # Handle our custom dict messages
        if isinstance(message, dict):
            msg_type = message.get("type")
            write_debug_log("runner", "process_dict_message", msg_type=msg_type or "")
            if msg_type == "session_init":
                self._session_id = message.get("session_id")
                write_debug_log("runner", "session_init", session_id=self._session_id or "")
                self._emit_session_init_callback(self._session_id)
                return
            if msg_type == "error":
                content = str(message.get("content", "Unknown error"))
                await self._check_for_blocked_operation(content)
                self.on_error(content)
                return
            if msg_type in ("assistant_text", "text"):
                content = str(message.get("content", ""))
                if content.strip():
                    self._mark_first_assistant_output_seen()
                await self._check_for_blocked_operation(content)
                self._parse_and_dispatch_text(content)
                return
            if msg_type == "tool_use":
                tool_name = str(message.get("name", ""))
                tool_input = message.get("input", {}) or {}
                tool_use_id = str(message.get("id", "") or message.get("tool_use_id", "") or "")
                self._handle_tool_use(tool_name, tool_input, tool_use_id=tool_use_id)
                return
            if msg_type == "tool_result":
                output = str(message.get("content", ""))
                await self._handle_tool_result(output)
                return
            return

        # Get the class name to determine message type
        msg_class = type(message).__name__
        write_debug_log("runner", "process_message_class", msg_class=msg_class)

        # Handle AssistantMessage - main response from Claude
        if msg_class == "AssistantMessage":
            content = getattr(message, "content", [])
            # content is a list of TextBlock objects
            for block in content:
                if hasattr(block, "text"):
                    if str(block.text).strip():
                        self._mark_first_assistant_output_seen()
                    self._parse_and_dispatch_text(block.text)
                    continue

                # Tool-use block shape varies by SDK versions. Some provide
                # block.type == "tool_use"; others only expose name/input.
                tool_name = str(getattr(block, "name", "") or "")
                tool_input = getattr(block, "input", None)
                if tool_name and isinstance(tool_input, dict):
                    tool_use_id = str(getattr(block, "id", "") or getattr(block, "tool_use_id", "") or "")
                    self._handle_tool_use(tool_name, tool_input, tool_use_id=tool_use_id)
            return

        # Handle SystemMessage - usually init/session info
        if msg_class == "SystemMessage":
            subtype = getattr(message, "subtype", "")
            if subtype == "init":
                data = getattr(message, "data", {})
                if "session_id" in data:
                    self._session_id = data["session_id"]
                    self._emit_session_init_callback(self._session_id)
            return

        # Handle ResultMessage - completion info
        if msg_class == "ResultMessage":
            result = getattr(message, "result", "")
            is_error = bool(getattr(message, "is_error", False))
            if result:
                result_text = str(result)
                await self._check_for_blocked_operation(result_text)
                if is_error:
                    self.on_error(result_text)
                else:
                    # ResultMessage.result carries the agent's final text for
                    # the turn — including numbered options. When the SDK has
                    # already streamed AssistantMessage text for this turn,
                    # replaying ResultMessage.result duplicates the entire UI
                    # response. Use ResultMessage.result only as a fallback for
                    # SDKs / flows that did not stream assistant text.
                    if self._first_assistant_output_seen:
                        write_debug_log(
                            "runner",
                            "result_message_replay_skipped",
                            chars=len(result_text),
                        )
                    else:
                        self._mark_first_assistant_output_seen()
                        self._parse_and_dispatch_text(result_text)
            return

        # Handle UserMessage - contains tool results (including blocked operations)
        if msg_class == "UserMessage":
            content = getattr(message, "content", [])
            for block in content:
                is_error = getattr(block, "is_error", False)
                block_content = getattr(block, "content", "") or getattr(block, "text", "")
                block_text = str(block_content) if block_content else ""
                tool_use_id = str(getattr(block, "tool_use_id", "") or "")
                if block_text and is_error:
                    # SDK may return a generic hook denial string like:
                    # "Hook PreToolUse:Read denied this tool"
                    # Normalize this into BRA's TOOL_APPROVAL_REQUIRED shape so
                    # BlockDetector can trigger inline approval UI.
                    hook_match = re.search(
                        r"Hook\s+PreToolUse:([A-Za-z0-9_+\-]+)\s+denied this tool",
                        block_text,
                        re.IGNORECASE,
                    )
                    if hook_match:
                        tool_name = hook_match.group(1)
                        pending = self._tool_inputs_by_use_id.get(tool_use_id, {}) if tool_use_id else {}
                        pending_input = pending.get("tool_input", {}) if isinstance(pending, dict) else {}
                        if not pending_input:
                            fallback = self._last_tool_input_by_name.get(tool_name, {})
                            fallback_at = self._last_tool_input_monotonic_by_name.get(tool_name)
                            fallback_age = (
                                time.monotonic() - fallback_at
                                if fallback_at is not None
                                else float("inf")
                            )
                            if fallback and fallback_age <= self._stale_tool_input_fallback_seconds:
                                pending_input = fallback
                                write_debug_log(
                                    "runner",
                                    "hook_denial_fallback_tool_input",
                                    tool_name=tool_name,
                                    age_seconds=round(fallback_age, 3),
                                )
                            else:
                                write_debug_log(
                                    "runner",
                                    "hook_denial_stale_tool_input_ignored",
                                    tool_name=tool_name,
                                    age_seconds=(
                                        round(fallback_age, 3)
                                        if fallback_age != float("inf")
                                        else -1.0
                                    ),
                                )


                        command = self._derive_tool_command(tool_name, pending_input)
                        if not tool_name and not (command or pending_input):
                            self._handle_malformed_tool_approval(block_text)
                            continue

                        normalized_lines = [
                            "TOOL_APPROVAL_REQUIRED",
                            f"TOOL_NAME={tool_name}",
                        ]
                        if tool_use_id:
                            normalized_lines.append(f"TOOL_USE_ID={tool_use_id}")
                        normalized_lines.extend(
                            [
                                f"Command: {command}",
                                f"Reason: {block_text}",
                            ]
                        )
                        normalized = "\n".join(normalized_lines)
                        await self._check_for_blocked_operation(normalized)
                        continue

                    await self._check_for_blocked_operation(block_text)
                    continue

                if block_text:
                    self._refresh_provenance_from_result(block_text, tool_use_id=tool_use_id)
                    await self._check_for_blocked_operation(block_text)
            return

        # Handle legacy Message types (backwards compatibility)
        msg_type = getattr(message, "type", None)

        if msg_type == "text":
            text = getattr(message, "content", "")
            if str(text).strip():
                self._mark_first_assistant_output_seen()
            self._parse_and_dispatch_text(text)

        elif msg_type == "tool_use":
            tool_name = getattr(message, "name", "")
            tool_input = getattr(message, "input", {})
            tool_use_id = str(getattr(message, "id", "") or getattr(message, "tool_use_id", "") or "")
            self._handle_tool_use(tool_name, tool_input, tool_use_id=tool_use_id)

            # Check for legacy approval-needed shape
            if hasattr(message, "approval_needed") and message.approval_needed and self.on_approval_needed:
                script_path = tool_input.get("script_path", "")
                script_content = tool_input.get("content", "")
                await self.on_approval_needed(script_path, script_content)

        elif msg_type == "tool_result":
            output = getattr(message, "content", "")
            await self._handle_tool_result(output)

    def _handle_tool_use(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        tool_use_id: str = "",
    ) -> None:
        """Handle a tool-use event from any provider shape."""
        self._last_tool_name = tool_name or ""
        self._last_tool_use_id = tool_use_id or ""
        self._mark_first_assistant_output_seen()
        write_debug_log(
            "runner",
            "tool_use",
            tool_name=tool_name,
            tool_use_id=tool_use_id,
            has_input=isinstance(tool_input, dict),
        )
        if tool_use_id and isinstance(tool_input, dict):
            self._tool_inputs_by_use_id[tool_use_id] = {
                "tool_name": tool_name,
                "tool_input": dict(tool_input),
            }

            # Keep the cache bounded for long-running sessions.
            if len(self._tool_inputs_by_use_id) > 256:
                oldest_id = next(iter(self._tool_inputs_by_use_id))
                self._tool_inputs_by_use_id.pop(oldest_id, None)

        if tool_name and isinstance(tool_input, dict):
            self._last_tool_input_by_name[tool_name] = dict(tool_input)
            self._last_tool_input_monotonic_by_name[tool_name] = time.monotonic()

        if tool_name:
            if tool_name == "Bash":
                cmd = str(tool_input.get("command", ""))[:30]
                self._tools_used_this_turn.append(f"Bash({cmd}...)")
            else:
                self._tools_used_this_turn.append(tool_name)

        if tool_name == "Bash":
            command = str(tool_input.get("command", ""))
            if self._suppress_next_bash_command:
                # Retry after approval — suppress duplicate command card
                self._suppress_next_bash_command = False
            else:
                # Buffer the command; emit only if tool completes without blocking
                self._pending_bash_command = command

        if tool_name in ("Write", "Edit"):
            file_path = str(tool_input.get("file_path", ""))
            if "FINDINGS.md" in file_path:
                self._findings_write_pending = True

    def _derive_tool_command(self, tool_name: str, tool_input: Any) -> str:
        """Extract a user-facing command/path from tool input."""
        if not isinstance(tool_input, dict):
            return ""
        if tool_name == "Bash":
            return str(tool_input.get("command", "") or "")
        if tool_name in ("Read", "Write", "Edit"):
            return str(tool_input.get("file_path", "") or "")
        if tool_name in ("Glob", "Grep"):
            return str(tool_input.get("pattern", "") or "")
        for key in ("command", "file_path", "pattern", "value"):
            value = tool_input.get(key, "")
            if value:
                return str(value)
        return ""

    def _handle_malformed_tool_approval(
        self,
        text: str,
        blocked: Optional[BlockedOperation] = None,
    ) -> None:
        """Surface malformed tool approvals as errors, not approval cards."""
        tool_name = str(getattr(blocked, "tool_name", "") or "")
        tool_use_id = str(getattr(blocked, "tool_use_id", "") or "")
        command = str(getattr(blocked, "command", "") or "")

        message = "Malformed tool approval"
        if tool_name and tool_name.lower() != "unknown":
            if command:
                message += f" for {tool_name}: could not validate command '{command}'"
            else:
                message += f" for {tool_name}: could not recover actionable input"
        else:
            message += ": missing tool identity or actionable input"

        write_debug_log(
            "runner",
            "malformed_tool_approval",
            tool_name=tool_name,
            tool_use_id=tool_use_id,
            command=command,
            text_preview=text[:200],
            raw_event=text,
        )
        self.on_error(message)

    async def _handle_tool_result(self, output: str) -> None:
        """Handle a tool-result event from any provider shape."""
        write_debug_log("runner", "tool_result", has_output=bool(output), output_preview=output[:240])
        if output:
            self._refresh_provenance_from_result(output)

            await self._check_for_blocked_operation(output)
            # Flush buffered command if no block was detected.
            # If a block was detected, _check_for_blocked_operation already
            # cleared the buffer (the approval card carries the command).
            if self._pending_bash_command is not None:
                self.on_command(self._pending_bash_command)
                self._pending_bash_command = None
            self.on_output(output)

        if self._findings_write_pending and self._finding_enforcer:
            self._findings_write_pending = False
            dequeued = self._finding_enforcer.check_and_dequeue_completed()
            if dequeued:
                ids = ", ".join(f"FINDING-{fid}" for fid in dequeued)
                self.on_text(f"[dim]Finding record validated: {ids}[/]")
                self._emit_findings_progress(
                    len(self._finding_enforcer.pending_queue),
                    force_complete=len(self._finding_enforcer.pending_queue) == 0,
                )
                self._clear_findings_handoff_if_resolved()
                write_debug_log("runner", "findings_dequeued", finding_ids=dequeued)
            elif self._finding_enforcer.pending_queue:
                current = self._finding_enforcer.pending_queue[0]
                self._emit_findings_progress(len(self._finding_enforcer.pending_queue))
                result = self._finding_enforcer.validate_finding_record(current.id)
                missing = ", ".join(result.missing_fields)
                missing_msg = f"missing fields: {missing}" if missing else ""
                error_msg = "; ".join(result.errors).replace("LIKELIHOOD_RATIONALE", "LIKELIHOOD")
                detail = " | ".join(part for part in (missing_msg, error_msg) if part)
                if detail:
                    self.on_text(
                        f"[yellow]Finding record still incomplete for FINDING-{current.id}:[/] {detail}"
                    )
                else:
                    self.on_text(
                        f"[yellow]Finding record still incomplete for FINDING-{current.id}:[/] "
                        "requires finding-specific updates beyond auto-filled scaffolding."
                    )
                write_debug_log(
                    "runner",
                    "findings_validation_incomplete",
                    finding_id=current.id,
                    missing_fields=result.missing_fields,
                    errors=result.errors,
                )

    def _emit_session_init_callback(self, session_id: Optional[str]) -> None:
        if not session_id:
            return
        try:
            self.on_session_init(session_id)
        except Exception as exc:
            write_debug_log("runner", "session_init_callback_error", error=str(exc))

    def _mark_first_assistant_output_seen(self) -> None:
        if self._first_assistant_output_seen:
            return
        self._first_assistant_output_seen = True
        write_debug_log("runner", "first_assistant_output_seen")
        try:
            self.on_first_assistant_output()
        except Exception as exc:
            write_debug_log("runner", "first_output_callback_error", error=str(exc))

    def _suppress_findings_takeover_lines(self, lines: list[str]) -> list[str]:
        """Hide main-agent findings-writeup narration while subagent path is active."""
        if (
            not self._finding_enforcer
            or self._findings_handoff_required
        ):
            return lines

        takeover_seen = any(
            pattern.search(line)
            for line in lines
            for pattern in _FINDINGS_TAKEOVER_TRIGGER_PATTERNS
        )
        if not takeover_seen:
            return lines

        filtered: list[str] = []
        for line in lines:
            stripped = line.strip()
            lowered = stripped.lower()
            if any(pattern.search(stripped) for pattern in _FINDINGS_TAKEOVER_TRIGGER_PATTERNS):
                continue
            if lowered == "what would you like to do?":
                continue
            option_match = re.match(r"^\s*\d+\.\s+(.*)$", stripped)
            if option_match and any(
                pattern.search(option_match.group(1))
                for pattern in _FINDINGS_TAKEOVER_OPTION_PATTERNS
            ):
                continue
            filtered.append(line)
        return filtered

    def _parse_and_dispatch_text(self, text: str) -> None:
        """Parse text for findings, leads, options and dispatch to handlers.

        Args:
            text: Text from agent
        """
        from bra.core.markers import parse_marker, MarkerType
        from bra.core.marker_events import append_marker_event

        text_body = (text or "").strip()
        if not text_body:
            return

        markers_emitted = False

        lines = self._suppress_findings_takeover_lines(text_body.split("\n"))
        if not any(line.strip() for line in lines):
            return
        text_lower = "\n".join(lines).lower()
        has_options_marker = any(marker in text_lower for marker in [
            "what would you like to do",
            "which option",
            "please choose",
            "select an option",
            "choose one",
            "your options",
            "[options]",
            "in scope?",
            "how would you like to proceed",
            "what should i do",
        ])
        joined_lines = "\n".join(lines)
        has_numbered_options = "1." in joined_lines and "2." in joined_lines

        # Keep the rendered inline option text aligned with the selectable 1-4 menu.
        display_lines = (
            self._limit_displayed_option_lines(lines, max_options=4)
            if has_options_marker and has_numbered_options
            else lines
        )

        # Strip backtick fences that wrap structured markers.  Agents sometimes
        # wrap markers in code blocks (```\n[MARKER]\n```) which leaves orphan
        # fence lines after the marker is extracted — these render as empty code
        # boxes and corrupt the accumulated text bubble's markdown.
        fence_re = re.compile(r"^\s*`{3,}\w*\s*$")
        marker_indices = {
            i for i, ln in enumerate(display_lines)
            if parse_marker(ln.strip())
        }
        if marker_indices:
            fence_skip: set[int] = set()
            for mi in marker_indices:
                for adj in (mi - 1, mi + 1):
                    if 0 <= adj < len(display_lines) and fence_re.match(display_lines[adj]):
                        fence_skip.add(adj)
            if fence_skip:
                display_lines = [ln for i, ln in enumerate(display_lines) if i not in fence_skip]

        for line in display_lines:
            stripped = line.strip()

            # Try to parse as structured marker first
            marker = parse_marker(stripped)
            if marker:
                finding_id_text = ""
                raw_capture = str(marker.fields.get("capture_id", "")).strip()
                if raw_capture.lower() == "provided_info":
                    self.on_text(
                        "capture_id: provided_info is not valid. "
                        "Use the actual tool_use_id (toolu_...) from the tool call that produced the evidence, "
                        "or omit capture_id entirely and it will be auto-resolved."
                    )
                source_hint = str(marker.fields.get("source", "") or "").strip()
                if source_hint:
                    source_hint = " ; ".join(
                        part.strip()
                        for part in re.split(r"\s*;\s*", source_hint)
                        if part.strip()
                        and not re.match(r"^(capture_id|source_kind)\s*:", part.strip(), re.IGNORECASE)
                    ).strip()
                source = self._resolve_source_to_artifact(source_hint)
                provenance_hint = " ".join(filter(None, [
                    source, marker.description or "", marker.path or "",
                    marker.port or "", marker.service or "", marker.raw_line,
                ]))
                capture_id, source_kind = self._effective_provenance(marker.fields, provenance_hint)
                capture_id, source_kind, source = self._canonicalize_marker_provenance(
                    capture_id,
                    source_kind,
                    source,
                )
                corrected_fields = dict(marker.fields)
                if capture_id:
                    corrected_fields["capture_id"] = capture_id
                else:
                    corrected_fields.pop("capture_id", None)
                if source_kind:
                    corrected_fields["source_kind"] = source_kind
                if source:
                    corrected_fields["source"] = source
                finding_source_marker = marker.raw_line
                if marker.type == MarkerType.FINDING:
                    finding_source_marker = self._normalize_finding_source_marker(
                        marker.raw_line,
                        capture_id,
                        source_kind,
                    )
                if marker.type == MarkerType.FINDING and self._finding_enforcer:
                    finding_id_text = f"{self._finding_enforcer.next_finding_id():03d}"
                try:
                    append_marker_event(
                        self._bra_state_dir,
                        {
                            "category": marker.category or marker.type.value.upper(),
                            "marker_type": marker.type.value,
                            "raw_fields": marker.raw_fields,
                            "fields": corrected_fields,
                            "capture_id": capture_id,
                            "source_kind": source_kind,
                            "source": source,
                            "artifact_path": source,
                            "line_start": marker.fields.get("line_start"),
                            "line_end": marker.fields.get("line_end"),
                            "excerpt_sha256": marker.fields.get("excerpt_sha256"),
                            "match_type": marker.fields.get("match_type"),
                            "title": marker.description or "",
                            "finding_id": finding_id_text,
                            "severity": marker.severity or "",
                            "cvss": marker.fields.get("cvss", ""),
                            "cwe": marker.fields.get("cwe", ""),
                            "attack_surface": marker.fields.get("attack_surface", ""),
                            "status": marker.fields.get("status", ""),
                            "risk": marker.fields.get("risk", ""),
                            "priority": marker.fields.get("priority", ""),
                            "state": marker.fields.get("state", ""),
                            "endpoint": marker.path or "",
                            "method": marker.method or "",
                            "port": marker.port or "",
                            "service": marker.service or "",
                            "version": marker.version or "",
                            "credential": marker.fields.get("credential", ""),
                        },
                    )
                except Exception as exc:
                    write_debug_log("runner", "marker_event_append_error", error=str(exc), marker=marker.raw_line)

                # Mechanical FINDING enforcement — enqueue for documentation
                if self._finding_enforcer and marker.type == MarkerType.FINDING:
                    fid = finding_id_text or f"{self._finding_enforcer.next_finding_id():03d}"
                    self._finding_enforcer.enqueue_finding(
                        fid,
                        marker.severity or "INFO",
                        marker.description or "",
                        finding_source_marker,
                    )
                    # Capture only a lightweight provenance snapshot at emission time.
                    self._finding_enforcer.write_context_file(
                        fid,
                        text_body,
                        source_marker=finding_source_marker,
                    )
                    self._emit_findings_progress(len(self._finding_enforcer.pending_queue), alert=True)
                    # Spawn findings subagent if not already running
                    if not self._findings_subagent_active and not self._findings_subagent_task:
                        try:
                            asyncio.get_running_loop()
                            self._findings_subagent_task = asyncio.create_task(
                                self._run_findings_subagent()
                            )
                        except RuntimeError:
                            pass  # No event loop — subagent will spawn on next run()

                markers_emitted = True

                if marker.type == MarkerType.FINDING:
                    self.on_finding(marker.severity or "INFO", marker.description or "")
                elif marker.type == MarkerType.SERVICE and marker.category == "SERVICE":
                    port = (marker.port or "").strip()
                    service_name = (marker.service or "").strip()
                    version = (marker.version or "").strip()
                    if not any((port, service_name, version)):
                        continue
                    state = (marker.fields.get("state", "") or "").strip() or "open"
                    self.on_service(
                        port,
                        state,
                        service_name,
                        version,
                        source,
                    )
                elif marker.type == MarkerType.ENDPOINT:
                    path = (marker.path or "").strip()
                    method = (marker.method or "").strip()
                    function = (marker.function or "").strip()
                    risk = (marker.fields.get("risk", "") or "").strip()
                    status = (marker.fields.get("status", "") or "").strip()
                    if not any((path, method, function, risk, status)):
                        continue
                    self.on_endpoint(
                        path,
                        method,
                        function,
                        risk or "Unknown",
                        status or "Untested",
                        source,
                    )
                elif marker.type == MarkerType.TARGET:
                    self.on_target(marker.property or "", marker.value or "", source)
                elif marker.type == MarkerType.LEAD:
                    self.on_lead(marker.description or "")
                continue

            # Legacy pattern support for backwards compatibility
            if "[FINDING]" in stripped or stripped.startswith("FINDING:"):
                self.on_text(
                    "Invalid [FINDING] marker. Required format: "
                    "[FINDING] <SEVERITY>: <title> | cvss: <0.0-10.0> | "
                    "attack_surface: <category>\n"
                    "Optional: append | capture_id: <tool_use_id> to link specific evidence "
                    "(auto-resolved from last tool use if omitted)."
                )
                continue

            if "[SUGGESTION]" in stripped or stripped.startswith("SUGGESTION:"):
                self.on_text("Unsupported marker [SUGGESTION]; use [LEAD] or [FINDING].")
                continue

            if "[LEAD]" in stripped or stripped.startswith("LEAD:"):
                lead_text = stripped.replace("[LEAD]", "").replace("LEAD:", "").strip()
                if lead_text:
                    lead_capture_id, lead_source_kind = self._effective_provenance({}, lead_text)
                    try:
                        append_marker_event(
                            self._bra_state_dir,
                            {
                                "category": "LEAD",
                                "marker_type": "lead",
                                "capture_id": lead_capture_id,
                                "source_kind": lead_source_kind,
                                "title": lead_text,
                                "raw_fields": [lead_text],
                                "fields": {},
                            },
                        )
                    except Exception as exc:
                        write_debug_log("runner", "marker_event_append_error", error=str(exc), marker=stripped)
                    markers_emitted = True
                self.on_lead(lead_text)
                continue

            # Regular text — skip blank lines so structured-marker gaps
            # don't produce empty chat bubbles.
            if not stripped:
                continue

            # Skip option-4+ catch-all lines even when the full-text options
            # detection didn't trigger (e.g. text arrives per-line from SDK).
            _opt_match = re.match(r"^\s*(\d+)\.\s+", stripped)
            if _opt_match and int(_opt_match.group(1)) >= 4:
                _opt_text = stripped[_opt_match.end():].strip().lower()
                # Only suppress recognized catch-all labels, not legitimate steps
                if any(kw in _opt_text for kw in (
                    "something else", "suggest", "other", "ask me",
                )):
                    continue

            self.on_text(line)

        # Materialize notes ONCE after all markers in this text block are processed.
        # This avoids dedup-hash drift from partial provenance causing duplicates.
        if markers_emitted:
            self._materialize_notes_from_events()

        # Only parse options if there's a clear marker AND numbered list.
        if has_options_marker and has_numbered_options:
            self._parse_options(lines)

    def _limit_displayed_option_lines(self, lines: list[str], max_options: int = 4) -> list[str]:
        """Clamp inline numbered option rendering to 1..max_options.

        This keeps assistant prose consistent with the selectable UI options.
        """
        if max_options < 1:
            return lines

        limited: list[str] = []
        option_line_re = re.compile(r"^\s*(\d+)\.\s+")

        for line in lines:
            match = option_line_re.match(line)
            if match:
                number = int(match.group(1))
                if number > max_options:
                    continue
            limited.append(line)

        return limited

    def _parse_finding(self, line: str) -> None:
        """Parse and dispatch a finding.

        Args:
            line: Line containing finding
        """
        # Try to extract severity
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        severity = "INFO"
        message = line.replace("[FINDING]", "").replace("FINDING:", "").strip()

        for sev in severities:
            if sev in line.upper():
                severity = sev
                # Remove severity from message
                message = message.replace(sev + ":", "").replace(sev, "").strip()
                break

        self.on_finding(severity, message)

    async def _check_for_blocked_operation(
        self,
        text: str,
        *,
        clear_pending_bash_command: bool = True,
    ) -> tuple[Optional[BlockedOperation], bool]:
        """Check if text indicates a blocked operation.

        If detected, triggers the approval flow via callback.

        Args:
            text: Text from agent (tool result, error message, etc.)
        """
        if not text:
            return None, False

        # Use BlockDetector to parse the text
        blocked = BlockDetector.detect(text)
        write_debug_log(
            "runner",
            "blocked_check",
            blocked=bool(blocked),
            text_preview=text[:200],
        )
        if blocked is None:
            return None, False

        # Enrich tool_input from the cached full input so the retry
        # approval hash matches the actual SDK tool_input (which may
        # contain fields like description/timeout that the block
        # message omits or truncates).
        if blocked.approval_type == ApprovalType.TOOL:
            parsed_has_tool_name = bool(
                blocked.tool_name and blocked.tool_name.lower() != "unknown"
            )
            parsed_has_actionable_input = bool(blocked.command) or (
                isinstance(blocked.tool_input, dict) and bool(blocked.tool_input)
            )
            if not parsed_has_tool_name and not parsed_has_actionable_input:
                if clear_pending_bash_command:
                    self._pending_bash_command = None
                self._handle_malformed_tool_approval(text, blocked)
                return None, True

            cached: dict[str, Any] = {}
            if blocked.tool_use_id and blocked.tool_use_id.lower() != "unknown":
                cached_value = self._tool_inputs_by_use_id.get(blocked.tool_use_id, {})
                if isinstance(cached_value, dict):
                    cached = cached_value

            cached_tool_name = str(cached.get("tool_name", "") or "")
            cached_tool_input = cached.get("tool_input", {})
            if (
                (not blocked.tool_name or blocked.tool_name.lower() == "unknown")
                and cached_tool_name
            ):
                blocked.tool_name = cached_tool_name
            if isinstance(cached_tool_input, dict) and cached_tool_input:
                blocked.tool_input = dict(cached_tool_input)
            if not blocked.command:
                blocked.command = self._derive_tool_command(blocked.tool_name, blocked.tool_input)

            has_tool_name = bool(blocked.tool_name and blocked.tool_name.lower() != "unknown")
            has_actionable_input = bool(blocked.command) or (
                isinstance(blocked.tool_input, dict) and bool(blocked.tool_input)
            )
            if not (has_tool_name and has_actionable_input):
                if clear_pending_bash_command:
                    self._pending_bash_command = None
                self._handle_malformed_tool_approval(text, blocked)
                return None, True

        if clear_pending_bash_command:
            # Discard buffered command once a valid block has been parsed.
            self._pending_bash_command = None

        # Store for potential retry
        self._last_blocked_operation = blocked
        write_debug_log(
            "runner",
            "blocked_detected",
            approval_type=blocked.approval_type.value,
            token_name=blocked.token_name or "",
            target=blocked.target or "",
            tool_name=blocked.tool_name or "",
            tool_use_id=blocked.tool_use_id or "",
            script_path=blocked.script_path or "",
            command=blocked.command or "",
        )

        # If we have a callback, trigger it
        if self.on_blocked_operation:
            self._blocked_turn_interrupted = True
            try:
                approved = await self.on_blocked_operation(blocked)
                write_debug_log("runner", "blocked_callback_result", approved=approved)
                if approved:
                    # Approval granted - the callback should have:
                    # 1. Created the appropriate token/approval
                    # 2. Notified user
                    # Auto-retry happens through agent's normal retry loop
                    pass
            except Exception as e:
                write_debug_log("runner", "blocked_callback_error", error=str(e))
                self.on_error(f"Approval handling failed: {e}")
        else:
            # No callback - just show the block message
            self.on_text(f"[bold red]BLOCKED:[/] {blocked.reason}")
            write_debug_log("runner", "blocked_without_callback", reason=blocked.reason)
        return blocked, False

    async def handle_approval_result(
        self,
        blocked: BlockedOperation,
        approved: bool,
        scope_level: Optional[str] = None,
        one_time: bool = False,
    ) -> bool:
        """Handle the result of an approval modal.

        Creates the appropriate approval and queues retry if approved.

        Args:
            blocked: The blocked operation
            approved: Whether user approved
            scope_level: For scope approvals, the selected level
            one_time: For token approvals, whether one-time

        Returns:
            True if approval was granted and retry should happen
        """
        if not approved:
            write_debug_log("runner", "approval_result", approved=False, approval_type=blocked.approval_type.value)
            return False
        write_debug_log(
            "runner",
            "approval_result",
            approved=True,
            approval_type=blocked.approval_type.value,
            one_time=one_time,
            scope_level=scope_level or "",
        )

        if blocked.approval_type == ApprovalType.TOKEN:
            # Grant token
            if blocked.token_name:
                self._approval_manager.grant_token(blocked.token_name, one_time=one_time)
                write_debug_log("runner", "approval_grant_token", token_name=blocked.token_name, one_time=one_time)
                return True

        elif blocked.approval_type == ApprovalType.SCOPE_ADD:
            # Add target to scope
            if blocked.target and scope_level:
                success = self._approval_manager.grant_scope(
                    blocked.target,
                    scope_level,
                    "UI approval",
                    target_type=blocked.target_type,
                )
                write_debug_log("runner", "approval_grant_scope_add", target=blocked.target, level=scope_level, target_type=blocked.target_type or "", success=success)
                return success

        elif blocked.approval_type == ApprovalType.SCOPE_UPGRADE:
            # Upgrade scope level
            if blocked.target and scope_level:
                success = self._approval_manager.grant_scope(
                    blocked.target,
                    scope_level,
                    "UI upgrade",
                    target_type=blocked.target_type,
                )
                write_debug_log("runner", "approval_grant_scope_upgrade", target=blocked.target, level=scope_level, target_type=blocked.target_type or "", success=success)
                return success

        elif blocked.approval_type == ApprovalType.SCRIPT:
            # Grant script approval
            if blocked.script_path:
                from bra.core.approval import grant_script_approval
                grant_script_approval(blocked.script_path)
                write_debug_log("runner", "approval_grant_script", script_path=blocked.script_path)
                return True

        elif blocked.approval_type == ApprovalType.TOOL:
            # Grant one-time tool approval (id-keyed for direct match)
            if blocked.tool_use_id:
                self._approval_manager.grant_tool_execution(
                    blocked.tool_name or "unknown",
                    blocked.tool_use_id
                )
                write_debug_log("runner", "approval_grant_tool_id", tool_name=blocked.tool_name or "unknown", tool_use_id=blocked.tool_use_id)
            # Grant retry approval so a new tool_use_id from the SDK retry
            # still passes the hook.
            if blocked.tool_name and blocked.tool_input:
                if one_time:
                    # allow_once: in-memory TTL-based retry (expires in 30s)
                    from bra.hooks.tool_approval_hook import grant_one_time_retry
                    grant_one_time_retry(blocked.tool_name, blocked.tool_input)
                    write_debug_log("runner", "approval_grant_tool_retry_onetime", tool_name=blocked.tool_name)
                else:
                    # allow_override: persistent session-level approval.
                    # For Bash: approve the exact command (not the tool type).
                    # For other tools: approve the tool type for the session.
                    from bra.hooks.tool_approval_hook import grant_retry_approval, grant_session_tool_approval, grant_session_bash_command
                    grant_retry_approval(blocked.tool_name, blocked.tool_input)
                    if blocked.tool_name == "Bash" and blocked.tool_input:
                        cmd = blocked.tool_input.get("command", "") if isinstance(blocked.tool_input, dict) else ""
                        if cmd:
                            grant_session_bash_command(cmd)
                    else:
                        grant_session_tool_approval(blocked.tool_name)
                    write_debug_log("runner", "approval_grant_tool_retry", tool_name=blocked.tool_name, has_tool_input=True)
            return True

        return False

    def get_approval_manager(self) -> ApprovalManager:
        """Get the approval manager for external use."""
        return self._approval_manager

    async def retry_blocked_operation(self, blocked: BlockedOperation) -> None:
        """Retry a blocked operation after approval was granted.

        Sends a message to the agent to retry the operation.
        The approval token/scope should already be in place.

        Args:
            blocked: The blocked operation to retry
        """
        if not self._session_id:
            write_debug_log("runner", "retry_blocked_fail_no_session", approval_type=blocked.approval_type.value)
            self.on_error("No session to retry in")
            return

        # Build retry message based on block type
        retry_message = self._build_retry_message(blocked)
        write_debug_log(
            "runner",
            "retry_blocked",
            approval_type=blocked.approval_type.value,
            retry_message=retry_message,
        )

        # Suppress the next Bash command card — the approval card already showed it
        if blocked.approval_type == ApprovalType.TOOL and blocked.tool_name == "Bash":
            self._suppress_next_bash_command = True

        # Continue the session with the retry instruction
        await self.continue_with_input(retry_message)

    def _build_retry_message(self, blocked: BlockedOperation) -> str:
        """Build a retry message for the agent.

        Args:
            blocked: The blocked operation

        Returns:
            Message instructing agent to retry
        """
        # Build base message per approval type
        if blocked.approval_type == ApprovalType.TOKEN:
            msg = (
                f"I have granted the {blocked.token_name} token. "
                f"Please retry the command: {blocked.command}"
            )
        elif blocked.approval_type == ApprovalType.SCOPE_ADD:
            level = getattr(blocked, "_approved_scope_level", None) or "approved"
            msg = (
                f"I have added {blocked.target} to scope at {level} level. "
                f"Please retry the command: {blocked.command}"
            )
        elif blocked.approval_type == ApprovalType.SCOPE_UPGRADE:
            level = getattr(blocked, "_approved_scope_level", None) or "FULL"
            msg = (
                f"I have upgraded {blocked.target} to {level} scope. "
                f"Please retry the command: {blocked.command}"
            )
        elif blocked.approval_type == ApprovalType.SCRIPT:
            msg = (
                f"I have approved the script {blocked.script_path}. "
                f"Please execute it now."
            )
        elif blocked.approval_type == ApprovalType.TOOL:
            msg = (
                f"I have approved the {blocked.tool_name} tool use. "
                f"Please retry the operation."
            )
        else:
            msg = "Approval granted. Please retry the operation."

        # Append operator guidance if provided
        operator_message = getattr(blocked, "_approval_message", "")
        if operator_message:
            msg += f" Operator guidance: {operator_message}"

        return msg

    def _parse_options(self, lines: list[str]) -> None:
        """Parse numbered options from text.

        Args:
            lines: All lines from text
        """
        options = []
        max_options = 4  # _normalize_operator_options keeps first 4; "Suggest something else" lives in the input field
        option_line_re = re.compile(r"^(\d+)\.\s+(.+)$")
        for line in lines:
            stripped = line.strip()
            # Match canonical numbered choices like "1. Option text".
            match = option_line_re.match(stripped)
            if not match:
                continue
            option_text = match.group(2).strip()
            if option_text:
                options.append(option_text)
                if len(options) >= max_options:
                    break

        if options:
            normalized = self._normalize_operator_options(options)
            self._current_options = normalized
            self.on_options(normalized)
            write_debug_log("runner", "options_parsed", options_count=len(normalized))
            # CRITICAL: When agent presents options, it's waiting for input
            # Set awaiting_input NOW, don't wait for stream to end
            self._awaiting_input = True
            self.on_turn_complete()

    @staticmethod
    def _strip_option_markup(text: str) -> str:
        """Strip lightweight markdown decoration from selectable option labels."""
        cleaned = str(text or "").strip()
        cleaned = re.sub(r"\*\*(.*?)\*\*", r"\1", cleaned)
        cleaned = re.sub(r"__(.*?)__", r"\1", cleaned)
        cleaned = re.sub(r"`([^`]*)`", r"\1", cleaned)
        return cleaned.strip()

    @staticmethod
    def _normalize_operator_options(options: list[str]) -> list[str]:
        """Normalize model-provided choice lists for a consistent 1-4 loop.

        Keep first four operator-specific choices. "Suggest something else"
        is now surfaced via the input field placeholder instead of a button.
        """
        cleaned = [
            AgentRunner._strip_option_markup(str(opt).strip())
            for opt in options
            if str(opt).strip()
        ]
        if not cleaned:
            return []
        base = cleaned[:4]
        fillers = [
            "Ask a clarifying question before continuing",
            "Show alternative approaches",
            "Pause and review current findings",
        ]
        while len(base) < 4:
            base.append(fillers[len(base) - 1])
        return base

    def _emit_fallback_options_if_missing(self) -> None:
        """Show default selectable options if the model did not provide any."""
        if self._current_options:
            return

        fallback_options = [
            "Continue with your proposed next step",
            "Ask a clarifying question before continuing",
            "Show alternative approaches",
            "Pause and review current findings",
        ]
        self._current_options = fallback_options
        self.on_options(fallback_options)
        write_debug_log("runner", "fallback_options_emitted", options_count=len(fallback_options))

    def transition_to_awaiting_input(self, options: Optional[list[str]] = None) -> None:
        """Force runner into awaiting-input mode and surface selectable options.

        Used by UI layers when an inline approval is denied and the current
        turn should return to the normal 1-4 operator loop immediately.
        """
        self._running = False
        self._paused = False
        self._awaiting_input = True

        if options:
            normalized = self._normalize_operator_options(list(options))
            if normalized:
                self._current_options = normalized
                self.on_options(normalized)
                write_debug_log("runner", "manual_options_emitted", options_count=len(normalized))
        else:
            self._emit_fallback_options_if_missing()

        self.on_turn_complete()
        write_debug_log("runner", "transition_to_awaiting_input", has_custom_options=bool(options))


def create_tui_runner(
    app: Any,
    notes_dir: "Path | None" = None,
    model: str | None = None,
) -> AgentRunner:
    """Create an AgentRunner configured for the TUI app.

    Args:
        app: BRAApp instance
        notes_dir: Path to NOTES directory for mechanical INTEL capture

    Returns:
        Configured AgentRunner
    """
    return AgentRunner(
        notes_dir=notes_dir,
        model=model,
        on_text=app.write_agent_text,
        on_command=app.write_command,
        on_output=app.write_command_output,
        on_finding=app.write_finding,
        on_lead=app.write_lead,
        on_service=getattr(app, 'write_service', None),
        on_endpoint=getattr(app, 'write_endpoint', None),
        on_target=getattr(app, 'write_target', None),
        on_suggestion=getattr(app, 'write_suggestion', None),
        on_options=app.show_options,
        on_error=lambda msg: app.write_agent_text(f"[bold red]ERROR:[/] {msg}"),
        on_phase_change=app.update_phase,
    )


def create_minimal_runner(
    renderer: Any,
    notes_dir: "Path | None" = None,
    model: str | None = None,
) -> AgentRunner:
    """Create an AgentRunner configured for minimal mode.

    Args:
        renderer: MinimalRenderer instance
        notes_dir: Path to NOTES directory for mechanical INTEL capture

    Returns:
        Configured AgentRunner
    """
    return AgentRunner(
        notes_dir=notes_dir,
        model=model,
        on_text=renderer.text,
        on_command=renderer.command,
        on_output=renderer.command_output,
        on_finding=renderer.finding,
        on_lead=renderer.lead,
        on_service=getattr(renderer, 'service', None),
        on_endpoint=getattr(renderer, 'endpoint', None),
        on_target=getattr(renderer, 'target', None),
        on_suggestion=getattr(renderer, 'suggestion', None),
        on_options=lambda opts: renderer.prompt_options(opts),
        on_error=renderer.error,
        on_phase_change=renderer.phase,
    )
