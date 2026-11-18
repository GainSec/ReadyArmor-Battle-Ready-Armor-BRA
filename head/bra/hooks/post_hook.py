"""Post tool use hook for audit trail.

Logs all tool executions to .bra/logs/ for audit purposes.
Captures intel command outputs to .bra/artifacts/raw/.
Each session gets its own JSONL log file with one entry per tool use.

Log entry format:
{
    "timestamp": "ISO8601",
    "tool_name": "Bash",
    "tool_input": {...},
    "tool_result": "...",
    "tool_use_id": "...",
    "session_id": "..."
}
"""

import json
import os
import re
import hashlib
import shlex
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from bra.core.capture_provenance import append_record
from bra.hooks.types import (
    PostToolUseHookInput,
    HookContext,
    SyncHookJSONOutput,
)

from bra.config.settings import LOGS_DIR, APPROVALS_DIR, ARTIFACTS_DIR

# Maximum size for tool_result in log entries (prevents huge logs)
MAX_RESULT_SIZE = 10000
MAX_TRACK_OUTPUT_SIZE = 4000

# List of intel-relevant commands to capture
INTEL_COMMANDS = [
    "nmap", "curl", "wget", "hcitool", "btmgmt", "nikto",
    "gobuster", "ffuf", "dirb", "sqlmap", "nuclei", "httpx",
]


def _is_token_enabled(token_name: str) -> bool:
    """Return True when a governance token is enabled."""
    env_name = token_name.replace("-", "_")
    env_value = (os.environ.get(env_name) or "").strip()
    if env_value == "1":
        return True
    if env_value == "0":
        return False

    disabled_markers = [
        APPROVALS_DIR / f"{token_name}_DISABLED",
        APPROVALS_DIR / f"{token_name}-DISABLED",
    ]
    if any(marker.exists() for marker in disabled_markers):
        return False

    return (APPROVALS_DIR / token_name).exists()


def _summarize_tool_input(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Create a short, human-readable summary of tool input."""
    if tool_name == "Bash":
        return str(tool_input.get("command", ""))[:240]
    if tool_name in {"Read", "Write", "Edit"}:
        return str(tool_input.get("file_path", ""))[:240]
    if tool_name == "Glob":
        return str(tool_input.get("pattern", ""))[:240]
    if tool_name == "Grep":
        pattern = str(tool_input.get("pattern", ""))[:120]
        path = str(tool_input.get("path", ""))[:120]
        return f"pattern={pattern} path={path}".strip()
    if tool_name == "WebFetch":
        return str(tool_input.get("url", ""))[:240]
    if tool_name == "WebSearch":
        return str(tool_input.get("query", ""))[:240]
    keys = ", ".join(sorted(str(k) for k in tool_input.keys()))
    return keys[:240]


_URL_IN_TEXT_RE = re.compile(r"https?://[^\s'\"`|>]+", re.IGNORECASE)


def _first_url_in_text(text: str) -> str:
    """Return the first URL token from text, trimmed of trailing punctuation."""
    match = _URL_IN_TEXT_RE.search(str(text or ""))
    if not match:
        return ""
    return match.group(0).rstrip(".,);")


def _infer_http_method_from_command(command: str) -> str:
    """Best-effort HTTP method inference for shell command captures."""
    text = str(command or "").strip()
    if not text:
        return ""
    try:
        parts = shlex.split(text)
    except Exception:
        parts = text.split()
    if not parts:
        return ""

    for idx, part in enumerate(parts):
        if part in ("-X", "--request") and idx + 1 < len(parts):
            return parts[idx + 1].upper()
        if part.startswith("--request="):
            return part.split("=", 1)[1].upper()
        if part.startswith("-X") and len(part) > 2:
            return part[2:].upper()

    # Curl payload flags imply non-GET unless an explicit method already exists.
    payload_flags = {"-d", "--data", "--data-raw", "--data-binary", "-F", "--form", "-T", "--upload-file"}
    if any(part in payload_flags for part in parts):
        return "POST"

    tool = parts[0].lower()
    if tool in {"curl", "wget", "http", "httpie"}:
        return "GET"
    return ""


def _build_capture_correlation(tool_name: str, tool_input: dict[str, Any]) -> dict[str, str]:
    """Build normalized capture metadata so capture_id can resolve endpoint context."""
    target = _summarize_tool_input(tool_name, tool_input)[:240]
    command = ""
    url = ""
    method = ""
    target_kind = "input"

    if tool_name == "Bash":
        command = str(tool_input.get("command", "")).strip()
        target = command[:240]
        url = _first_url_in_text(command)
        method = _infer_http_method_from_command(command)
        target_kind = "url" if url else "command"
    elif tool_name == "WebFetch":
        url = str(tool_input.get("url", "")).strip()
        method = str(tool_input.get("method", "")).strip().upper() or "GET"
        target = url[:240] if url else target
        target_kind = "url" if url else "input"
    elif tool_name in {"Read", "Write", "Edit"}:
        target_kind = "file"
    elif tool_name == "WebSearch":
        target_kind = "query"

    host = ""
    endpoint = ""
    if url:
        parsed = urlparse(url)
        host = (parsed.netloc or parsed.hostname or "").strip()
        endpoint = (parsed.path or "/").strip() or "/"
        if parsed.query:
            endpoint = f"{endpoint}?{parsed.query}"

    return {
        "target": target,
        "command": command,
        "url": url,
        "method": method,
        "host": host,
        "endpoint": endpoint,
        "target_kind": target_kind,
    }


def _trim_track_output(text: str, max_chars: int = MAX_TRACK_OUTPUT_SIZE) -> str:
    """Trim track output to avoid unbounded growth per entry."""
    if len(text) <= max_chars:
        return text
    kept = max_chars - 64
    return text[:kept] + f"\n... (truncated from {len(text)} to {kept} chars)"


def _log_watch(
    *,
    tool_name: str,
    tool_input: dict[str, Any],
    tool_use_id: str,
    capture_id: str,
    session_id: str,
) -> None:
    """Append one human-readable WATCH audit entry."""
    if not _is_token_enabled("WATCH"):
        return

    summary = _summarize_tool_input(tool_name, tool_input) or "(no input summary)"
    now = datetime.now(timezone.utc)
    time_str = now.strftime("%H:%M:%S")
    line = (
        f"[{time_str}] [TOOL    ] {tool_name} | {summary} | "
        f"id={tool_use_id} capture={capture_id} session={session_id}"
    )

    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        with (LOGS_DIR / "watch.log").open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except Exception:
        # Never fail hook flow because auxiliary logging failed.
        pass


def _log_track(
    *,
    tool_name: str,
    tool_input: dict[str, Any],
    tool_result: str,
    tool_use_id: str,
    capture_id: str,
    session_id: str,
) -> None:
    """Append one detailed TRACK audit entry."""
    if not _is_token_enabled("TRACK"):
        return

    summary = _summarize_tool_input(tool_name, tool_input) or "(no input summary)"
    now = datetime.now(timezone.utc)
    time_str = now.strftime("%H:%M:%S")
    output = _trim_track_output(_truncate_result(str(tool_result) if tool_result else ""))
    output_lines = output.splitlines()[:30] if output else []

    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        with (LOGS_DIR / "track.log").open("a", encoding="utf-8") as handle:
            handle.write("┌─ TOOL ─────────────────────────────────────────────────────────────────────┐\n")
            handle.write(f"│ Time:    {time_str}\n")
            handle.write(f"│ Action:  {tool_name}\n")
            handle.write("│ Reason:  PostToolUse event\n")
            handle.write(f"│ Input:   {summary}\n")
            handle.write(f"│ Tool ID: {tool_use_id}\n")
            handle.write(f"│ Capture: {capture_id}\n")
            handle.write(f"│ Session: {session_id}\n")
            if output_lines:
                handle.write("├───────────────────────────────────────────────────────────────────────────┤\n")
                handle.write("│ Output:\n")
                for line in output_lines:
                    handle.write(f"│   {line[:72]}\n")
            handle.write("└───────────────────────────────────────────────────────────────────────────┘\n")
    except Exception:
        # Never fail hook flow because auxiliary logging failed.
        pass


def _truncate_result(result: str, max_size: int = MAX_RESULT_SIZE) -> str:
    """Truncate large results for logging.

    Args:
        result: Tool result string
        max_size: Maximum size to keep

    Returns:
        Truncated result with "(truncated)" marker if needed
    """
    if len(result) <= max_size:
        return result

    # Keep first portion and add truncation marker
    keep_size = max_size - 50  # Leave room for marker
    return result[:keep_size] + f"\n\n... (truncated from {len(result)} to {keep_size} bytes)"


def _get_log_file(session_id: str) -> str:
    """Get the log file path for a session.

    Args:
        session_id: Session identifier

    Returns:
        Path to the log file
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # Use date + session_id for the log filename
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    # Sanitize session_id for filename
    safe_session = "".join(c if c.isalnum() or c in "-_" else "_" for c in session_id)
    safe_session = safe_session[:50]  # Limit length

    return LOGS_DIR / f"{date_str}_{safe_session}.jsonl"


def _log_tool_use(
    tool_name: str,
    tool_input: dict[str, Any],
    tool_result: str,
    tool_use_id: str,
    capture_id: str,
    session_id: str,
) -> None:
    """Log a tool use to the audit file.

    Args:
        tool_name: Name of the tool
        tool_input: Tool input parameters
        tool_result: Tool execution result
        tool_use_id: Unique tool use identifier
        session_id: Session identifier
    """
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_result": _truncate_result(str(tool_result)),
        "tool_use_id": tool_use_id,
        "capture_id": capture_id,
        "session_id": session_id,
    }

    log_file = _get_log_file(session_id)

    try:
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception:
        # Don't fail on logging errors - audit is best-effort
        pass


def _should_capture(command: str) -> bool:
    """Check if command output should be captured to INTEL.md.

    Args:
        command: Command string

    Returns:
        True if this is an intel-relevant command
    """
    cmd_lower = command.lower()
    return any(rc in cmd_lower for rc in INTEL_COMMANDS)


def _sanitize_token(value: str, fallback: str) -> str:
    """Sanitize token for filesystem-safe artifact names."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", (value or "").strip().lower()).strip("-._")
    return cleaned[:80] if cleaned else fallback


def _capture_label_and_target(tool_name: str, tool_input: dict[str, Any]) -> tuple[str, str]:
    """Derive artifact name components from tool metadata."""
    tool = _sanitize_token(tool_name or "tool", "tool")

    if tool_name == "Bash":
        command = str(tool_input.get("command", "") or "")
        if command:
            try:
                from bra.core.intel_writer import IntelWriter

                parsed_tool, parsed_target = IntelWriter._extract_tool_and_target(command)
                if parsed_tool:
                    tool = _sanitize_token(parsed_tool, tool)
                if parsed_target:
                    return tool, _sanitize_token(parsed_target, "task")
            except Exception:
                pass
        return tool, "task"

    for key in ("file_path", "path"):
        if key in tool_input and tool_input.get(key):
            return tool, _sanitize_token(Path(str(tool_input[key])).name, "task")

    if tool_input.get("url"):
        url = str(tool_input["url"])
        host = urlparse(url).hostname or url
        return tool, _sanitize_token(host, "task")

    if tool_input.get("query"):
        query = str(tool_input["query"]).split()
        return tool, _sanitize_token("-".join(query[:6]), "task")

    if tool_input.get("pattern"):
        return tool, _sanitize_token(str(tool_input["pattern"]), "task")

    if tool_input.get("task"):
        return tool, _sanitize_token(str(tool_input["task"]), "task")

    return tool, "task"


def _mask_for_artifact(output: str) -> str:
    """Best-effort masking of real values in persisted artifacts."""
    try:
        from bra.config.settings import BRA_STATE

        map_path = BRA_STATE / "anon_map.json"
        if not map_path.is_file():
            return output

        data = json.loads(map_path.read_text(encoding="utf-8"))
        mappings = data.get("mappings", [])
        if not mappings:
            return output

        masked = output
        for mapping in sorted(mappings, key=lambda item: len(item.get("real", "")), reverse=True):
            real = mapping.get("real", "")
            anon = mapping.get("anon", "")
            if real and anon and real in masked:
                masked = masked.replace(real, anon)
        return masked
    except Exception:
        return output


def _capture_raw_artifact(
    tool_name: str,
    tool_input: dict[str, Any],
    output: str,
    capture_id: str,
) -> Path | None:
    """Capture any tool output to .bra/artifacts/raw/."""
    if not output:
        return None
    try:
        raw_dir = ARTIFACTS_DIR / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        label, target = _capture_label_and_target(tool_name, tool_input)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        capture_prefix = _sanitize_token(capture_id, "capture")
        base_name = f"{capture_prefix}_{label}_{target}_{timestamp}"
        artifact = raw_dir / f"{base_name}.txt"

        # Avoid overwrite when multiple captures land in the same second.
        suffix = 1
        while artifact.exists():
            artifact = raw_dir / f"{base_name}_{suffix:02d}.txt"
            suffix += 1

        artifact.write_text(_mask_for_artifact(output), encoding="utf-8")
        return artifact
    except Exception:
        # Best-effort capture should never block tool flow.
        return None


def _capture_to_intel(command: str, output: str, capture_id: str) -> Path | None:
    """Capture command output to .bra/artifacts/raw/.

    Args:
        command: Command that was executed
        output: Command output
    """
    from bra.config.settings import LAYER3, ARTIFACTS_DIR, LOGS_DIR, BRA_STATE
    from bra.core.intel_writer import IntelWriter

    notes_dir = LAYER3 / "NOTES"
    if not notes_dir.exists():
        return None

    try:
        writer = IntelWriter(notes_dir, bra_dir=BRA_STATE)
        return writer.append_raw_capture(
            command,
            output,
            artifacts_dir=ARTIFACTS_DIR,
            logs_dir=LOGS_DIR,
            bra_dir=BRA_STATE,
            capture_id=capture_id,
        )
    except Exception:
        # Don't fail on capture errors
        return None


def _append_evidence_index(
    *,
    session_id: str,
    tool_use_id: str,
    tool_name: str,
    tool_input: dict[str, Any],
    capture_id: str,
    artifact_path: Path,
) -> None:
    """Append provenance metadata to the canonical evidence index."""
    try:
        sha = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        capture = _build_capture_correlation(tool_name, tool_input)
        append_record(
            LOGS_DIR.parent,
            {
                "capture_id": capture_id,
                "session_id": session_id,
                "tool_use_id": tool_use_id,
                "tool_name": tool_name,
                "action": tool_name.lower(),
                "target": capture["target"],
                "command": capture["command"],
                "url": capture["url"],
                "method": capture["method"],
                "host": capture["host"],
                "endpoint": capture["endpoint"],
                "target_kind": capture["target_kind"],
                "artifact_path": str(artifact_path),
                "artifact_sha256": sha,
                "source_kind": "tool_capture",
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )
    except Exception:
        # Best-effort provenance index write.
        pass


async def post_tool(
    hook_input: PostToolUseHookInput,
    tool_use_id: str | None,
    context: HookContext,
) -> SyncHookJSONOutput:
    """PostToolUse hook for audit trail and raw output capture.

    Logs all tool executions to .bra/logs/ for audit and replay purposes.
    Captures all non-empty tool outputs to .bra/artifacts/raw/.
    Bash intel commands also use the INTEL capture path (captures.log + sidecar).

    Args:
        hook_input: Hook input from SDK (contains tool_name, tool_input, tool_result)
        tool_use_id: Unique tool use identifier
        context: Hook context with signal for cancellation

    Returns:
        Empty dict (post hooks don't modify or block)
    """
    tool_name = hook_input.get("tool_name", "unknown")
    tool_input = hook_input.get("tool_input", {})
    tool_result = hook_input.get("tool_response", "")
    session_id = hook_input.get("session_id", "unknown")

    if not isinstance(tool_input, dict):
        tool_input = {"raw": str(tool_input)}
    tool_result_text = str(tool_result) if tool_result else ""
    capture_id = _sanitize_token(tool_use_id or "", "")
    if not capture_id:
        session_token = _sanitize_token(session_id, "session")
        capture_id = f"cap_{session_token}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}"

    _log_tool_use(
        tool_name=tool_name,
        tool_input=tool_input,
        tool_result=tool_result_text,
        tool_use_id=tool_use_id or "unknown",
        capture_id=capture_id,
        session_id=session_id,
    )
    _log_watch(
        tool_name=tool_name,
        tool_input=tool_input,
        tool_use_id=tool_use_id or "unknown",
        capture_id=capture_id,
        session_id=session_id,
    )
    _log_track(
        tool_name=tool_name,
        tool_input=tool_input,
        tool_result=tool_result_text,
        tool_use_id=tool_use_id or "unknown",
        capture_id=capture_id,
        session_id=session_id,
    )

    # Capture Bash intel commands with captures.log + sidecar handoff.
    captured_artifact: Path | None = None
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if _should_capture(command) and tool_result_text:
            captured_artifact = _capture_to_intel(command, tool_result_text, capture_id)

    # Capture all other tool outputs to raw artifacts.
    if tool_result_text and not captured_artifact:
        captured_artifact = _capture_raw_artifact(tool_name, tool_input, tool_result_text, capture_id)

    if tool_result_text and captured_artifact is not None:
        _append_evidence_index(
            session_id=session_id,
            tool_use_id=tool_use_id or "unknown",
            tool_name=tool_name,
            tool_input=tool_input,
            capture_id=capture_id,
            artifact_path=captured_artifact,
        )

    return {}
