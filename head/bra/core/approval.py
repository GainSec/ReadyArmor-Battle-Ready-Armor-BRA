"""Comprehensive approval system for BRA TUI.

Handles ALL approval flows with mechanical enforcement and no bypasses:

1. SCRIPT APPROVAL - Review code before execution
   - Direct execution: ./script.sh, /path/to/script.sh
   - Shell invocation: bash script.sh, sh script.sh
   - Interpreter execution: python script.py, perl script.pl

2. TOKEN-BASED APPROVALS - Grant token, retry operation
   - DESTRUCTIVE-APPROVAL: Dangerous commands (rm -rf, etc.)
   - PUSH-APPROVAL: Git push operations
   - LAYER2-WRITE-APPROVAL: Write to layer2-templates/
   - ACTIVE-TESTING-APPROVAL: Active scanning/probing
   - OFFENSIVE-TESTING-APPROVAL: Exploit attempts
   - FRAMEWORK-DEV-APPROVAL: Edit scripts/, .claude/
   - SYSTEM-INSTALL-APPROVAL: Package installs

3. SCOPE APPROVALS - Add/modify target scope
   - SCOPE_ADD: Target not in scope, add with level
   - SCOPE_UPGRADE: Upgrade target scope level

4. TOOL APPROVALS - Approve each tool execution
   - Every tool requires explicit user approval
   - No bypass possible - mechanical enforcement

MECHANICAL ENFORCEMENT:
- All approvals go through this system
- Hooks block operations, TUI shows approval modal
- User approves, system grants approval, retries operation
- One-time approvals are consumed after use
"""

import hashlib
import importlib.util
import os
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Any

from bra.config import settings as _settings
from bra.debug_log import write_debug_log


def _approvals_dir() -> Path:
    """Dynamically resolve the approvals directory."""
    return _settings.APPROVALS_DIR


def _body_root() -> Path:
    """Dynamically resolve the body root directory."""
    return _settings.BODY_ROOT


def _bra_state() -> Path:
    """Dynamically resolve the BRA state directory."""
    return _settings.BRA_STATE


# =============================================================================
# APPROVAL TYPES AND DATA STRUCTURES
# =============================================================================

class ApprovalType(Enum):
    """Types of approvals that can be requested."""
    TOKEN = "token"                    # Token-based (DESTRUCTIVE, PUSH, etc.)
    SCOPE_ADD = "scope_add"            # Add target to scope
    SCOPE_UPGRADE = "scope_upgrade"    # Upgrade target scope level
    SCRIPT = "script"                  # Script execution review
    TOOL = "tool"                      # Individual tool execution


@dataclass
class BlockedOperation:
    """Represents a blocked operation that needs approval."""
    approval_type: ApprovalType

    # Common fields
    command: str = ""
    reason: str = ""

    # Token approval fields
    token_name: Optional[str] = None

    # Scope approval fields
    target: Optional[str] = None
    target_type: Optional[str] = None  # "network" or "local"
    current_level: Optional[str] = None  # For upgrades

    # Script approval fields
    script_path: Optional[str] = None
    script_content: Optional[str] = None

    # Tool approval fields
    tool_name: Optional[str] = None
    tool_input: dict = field(default_factory=dict)
    tool_use_id: Optional[str] = None


# =============================================================================
# BLOCK DETECTOR - Parses messages to identify blocked operations
# =============================================================================

class BlockDetector:
    """Detects blocked operations from agent messages.

    Parses error messages and tool results to identify:
    - Token requirements
    - Scope check failures
    - Script execution attempts
    - Tool approval needs

    MECHANICAL: This detection drives the approval flow.
    No operation proceeds without going through detection.
    """

    # Token patterns - maps regex to token name
    TOKEN_PATTERNS = {
        r"DESTRUCTIVE[_-]?APPROVAL": "DESTRUCTIVE-APPROVAL",
        r"PUSH[_-]?APPROVAL": "PUSH-APPROVAL",
        r"LAYER2[_-]?WRITE[_-]?APPROVAL": "LAYER2-WRITE-APPROVAL",
        r"ACTIVE[_-]?TESTING[_-]?APPROVAL": "ACTIVE-TESTING-APPROVAL",
        r"OFFENSIVE[_-]?TESTING[_-]?APPROVAL": "OFFENSIVE-TESTING-APPROVAL",
        r"FRAMEWORK[_-]?DEV[_-]?APPROVAL": "FRAMEWORK-DEV-APPROVAL",
        r"SYSTEM[_-]?INSTALL[_-]?APPROVAL": "SYSTEM-INSTALL-APPROVAL",
        r"OVERRIDE[_-]?APPROVAL": "OVERRIDE-APPROVAL",
        r"2X4[_-]?ENABLED": "2x4-ENABLED",
        r"2X4[_-]?DEBUG": "2x4-DEBUG",
        r"2X4[_-]?UNRESTRICTED": "2x4-UNRESTRICTED",
        r"2X4[_-]?CONTROL": "2x4-CONTROL",
        r"2X4[_-]?TAKEOVER": "2x4-TAKEOVER",
        r"2X4[_-]?VOICE[_-]?CALL": "2x4-VOICE-CALL",
    }

    # Block signal patterns
    SCOPE_CHECK_PATTERN = r"SCOPE_CHECK_REQUIRED"
    SCOPE_LEVEL_PATTERN = r"OPERATION_NOT_ALLOWED_FOR_SCOPE_LEVEL"
    SCRIPT_APPROVAL_PATTERN = r"SCRIPT_APPROVAL_REQUIRED"
    TOOL_APPROVAL_PATTERN = r"TOOL_APPROVAL_REQUIRED"

    @staticmethod
    def _looks_like_token_block(message: str) -> bool:
        """Return True when message shape indicates a real token block.

        Avoids false positives from plain narrative text that references
        approval tokens (for example option labels in assistant prose).
        """
        upper = message.upper()
        if "BLOCKED" in upper or "APPROVAL_REQUIRED" in upper:
            return True
        return bool(
            re.search(
                r"(?im)^\s*(?:reason:\s*)?(?:operation|command|action)\s+requires\b",
                message,
            )
        )

    @staticmethod
    def _extract_command_line(message: str) -> str:
        """Extract only the value on a literal 'Command:' line.

        This avoids accidentally consuming the next line (e.g. "Reason: ...")
        when Command is blank.
        """
        cmd_match = re.search(
            r"^(?:\[[^\]]+\][ \t]*)*Command:[ \t]*(.*)$",
            message,
            re.MULTILINE,
        )
        return cmd_match.group(1).strip() if cmd_match else ""

    @classmethod
    def detect(cls, message: str) -> Optional[BlockedOperation]:
        """Detect if a message indicates a blocked operation.

        Args:
            message: Text from agent (error message, tool result, etc.)

        Returns:
            BlockedOperation if detected, None otherwise
        """
        if not message:
            return None
        write_debug_log("approval", "detect_start", message_preview=message[:220])

        # Check for scope check required
        if re.search(cls.SCOPE_CHECK_PATTERN, message):
            write_debug_log("approval", "detect_match", match_type="scope_add")
            return cls._parse_scope_check(message)

        # Check for scope level insufficient
        if re.search(cls.SCOPE_LEVEL_PATTERN, message):
            write_debug_log("approval", "detect_match", match_type="scope_upgrade")
            return cls._parse_scope_level(message)

        # Check for script approval
        if re.search(cls.SCRIPT_APPROVAL_PATTERN, message):
            write_debug_log("approval", "detect_match", match_type="script")
            return cls._parse_script_approval(message)

        # Check for tool approval
        if re.search(cls.TOOL_APPROVAL_PATTERN, message):
            write_debug_log("approval", "detect_match", match_type="tool")
            return cls._parse_tool_approval(message)

        # Check for token requirements
        for pattern, token_name in cls.TOKEN_PATTERNS.items():
            if re.search(pattern, message, re.IGNORECASE):
                # Verify it's actually a block message (not narrative text).
                if cls._looks_like_token_block(message):
                    write_debug_log("approval", "detect_match", match_type="token", token_name=token_name)
                    return cls._parse_token_block(message, token_name)

        write_debug_log("approval", "detect_no_match")
        return None

    @staticmethod
    def _classify_target_type(target: str) -> str:
        """Classify target as 'network' or 'local'.

        Mirrors classify_target_type() in target_scope.py.
        """
        if not target:
            return "network"
        # Bluetooth MAC (must check before IPv6 — MACs are all hex+colons)
        if re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', target):
            return "local"
        # IPv4 / CIDR
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', target):
            return "network"
        # IPv6
        if ':' in target and re.match(r'^[0-9a-fA-F:]+$', target):
            return "network"
        # URL
        if target.startswith("http://") or target.startswith("https://"):
            return "network"
        if target.startswith("BT-") or target.startswith("BT_"):
            return "local"
        # File path
        if target.startswith("/") or target.startswith("./"):
            return "local"
        # USB
        if target.startswith("/dev/") or target.startswith("usb:"):
            return "local"
        # Domain (contains dot, not IP)
        if '.' in target:
            return "network"
        return "network"

    @classmethod
    def _parse_scope_check(cls, message: str) -> BlockedOperation:
        """Parse scope check required message."""
        target_match = re.search(r"TARGET=([^\s\n]+)", message)
        target = target_match.group(1) if target_match else "unknown"

        # Reject shell variable/subshell artifacts from source code
        # e.g. TARGET=$(extract_target_from_command "$COMMAND")
        if target.startswith("$(") or target.startswith("${"):
            write_debug_log("approval", "parse_scope_reject_shell_artifact", raw_target=target)
            target = "unknown"

        command = cls._extract_command_line(message)

        target_type = cls._classify_target_type(target)

        op = BlockedOperation(
            approval_type=ApprovalType.SCOPE_ADD,
            target=target,
            target_type=target_type,
            command=command,
            reason=f"Target '{target}' is not in approved scope",
        )
        write_debug_log("approval", "parse_scope_add", target=target, target_type=target_type, command=command)
        return op

    @classmethod
    def _parse_scope_level(cls, message: str) -> BlockedOperation:
        """Parse scope level insufficient message."""
        target_match = re.search(r"TARGET=([^\s\n]+)", message)
        target = target_match.group(1) if target_match else "unknown"

        # Reject shell variable/subshell artifacts from source code
        if target.startswith("$(") or target.startswith("${"):
            target = "unknown"

        level_match = re.search(r"SCOPE_LEVEL=([^\s\n]+)", message)
        current_level = level_match.group(1) if level_match else "LIMITED"

        command = cls._extract_command_line(message)

        op = BlockedOperation(
            approval_type=ApprovalType.SCOPE_UPGRADE,
            target=target,
            current_level=current_level,
            command=command,
            reason=f"Operation not allowed for scope level '{current_level}'",
        )
        write_debug_log("approval", "parse_scope_upgrade", target=target, current_level=current_level, command=command)
        return op

    @classmethod
    def _parse_script_approval(cls, message: str) -> BlockedOperation:
        """Parse script approval required message."""
        path_match = re.search(r"SCRIPT_PATH=([^\s\n]+)", message)
        script_path = path_match.group(1) if path_match else ""

        command = cls._extract_command_line(message)

        script_content = ""
        if script_path:
            script_content = read_script_content(script_path)

        op = BlockedOperation(
            approval_type=ApprovalType.SCRIPT,
            script_path=script_path,
            script_content=script_content,
            command=command,
            reason=f"Script execution requires approval: {script_path}",
        )
        write_debug_log("approval", "parse_script", script_path=script_path, command=command)
        return op

    @classmethod
    def _parse_tool_approval(cls, message: str) -> BlockedOperation:
        """Parse tool approval required message."""
        tool_match = re.search(r"TOOL_NAME=([^\s\n]+)", message)
        tool_name = tool_match.group(1) if tool_match else "unknown"

        id_match = re.search(r"TOOL_USE_ID=([^\s\n]+)", message)
        tool_use_id = id_match.group(1) if id_match else None

        command = cls._extract_command_line(message)

        tool_input: dict[str, Any] = {}
        if command:
            if tool_name == "Bash":
                tool_input = {"command": command}
            elif tool_name in ("Read", "Write", "Edit"):
                tool_input = {"file_path": command}
            elif tool_name in ("Glob", "Grep"):
                tool_input = {"pattern": command}
            else:
                tool_input = {"value": command}

        op = BlockedOperation(
            approval_type=ApprovalType.TOOL,
            tool_name=tool_name,
            tool_input=tool_input,
            tool_use_id=tool_use_id,
            command=command,
            reason=f"Tool '{tool_name}' requires approval",
        )
        write_debug_log(
            "approval",
            "parse_tool",
            tool_name=tool_name,
            tool_use_id=tool_use_id or "",
            command=command,
        )
        return op

    @classmethod
    def _parse_token_block(cls, message: str, token_name: str) -> BlockedOperation:
        """Parse token-based block message."""
        command = cls._extract_command_line(message)

        if not command:
            cmd_match = re.search(r"command[:\s]+['\"]?([^'\"\n]+)", message, re.IGNORECASE)
            if cmd_match:
                command = cmd_match.group(1).strip()

        op = BlockedOperation(
            approval_type=ApprovalType.TOKEN,
            token_name=token_name,
            command=command,
            reason=f"Operation requires {token_name} token",
        )
        write_debug_log("approval", "parse_token", token_name=token_name, command=command)
        return op


# =============================================================================
# APPROVAL MANAGER - Grants approvals and manages retries
# =============================================================================

class ApprovalManager:
    """Manages approval grants and one-time tokens.

    MECHANICAL ENFORCEMENT:
    - Creates approval files in .bra/approvals/
    - Supports one-time approvals that are consumed after use
    - No bypass possible - approvals are checked by hooks
    """

    def __init__(self):
        """Initialize approval manager."""
        self._ensure_dirs()
        self._pending_retries: list[BlockedOperation] = []

    def _ensure_dirs(self):
        """Ensure approval directories exist."""
        _approvals_dir().mkdir(parents=True, exist_ok=True)
        (_bra_state() / "one-time-approvals").mkdir(parents=True, exist_ok=True)
        write_debug_log("approval", "ensure_dirs", approvals_dir=str(_approvals_dir()))

    def grant_token(self, token_name: str, one_time: bool = False) -> bool:
        """Grant a token approval.

        Args:
            token_name: Name of token (e.g., "DESTRUCTIVE-APPROVAL")
            one_time: If True, token is consumed after one use

        Returns:
            True if granted successfully
        """
        self._ensure_dirs()
        write_debug_log("approval", "grant_token_start", token_name=token_name, one_time=one_time)

        if one_time:
            token_id = str(uuid.uuid4())[:8]
            token_file = _bra_state() / "one-time-approvals" / f"{token_name}-{token_id}"
        else:
            token_file = _approvals_dir() / token_name

        try:
            token_file.touch()
            write_debug_log("approval", "grant_token_ok", token_name=token_name, path=str(token_file))
            return True
        except Exception:
            write_debug_log("approval", "grant_token_fail", token_name=token_name, path=str(token_file))
            return False

    def revoke_token(self, token_name: str) -> bool:
        """Revoke a token approval.

        Args:
            token_name: Name of token to revoke

        Returns:
            True if revoked successfully
        """
        token_file = _approvals_dir() / token_name
        write_debug_log("approval", "revoke_token_start", token_name=token_name, exists=token_file.exists())
        if token_file.exists():
            try:
                token_file.unlink()
                write_debug_log("approval", "revoke_token_ok", token_name=token_name)
                return True
            except Exception:
                write_debug_log("approval", "revoke_token_fail", token_name=token_name)
                return False
        return True

    def has_token(self, token_name: str) -> bool:
        """Check if a token is granted.

        Args:
            token_name: Name of token to check

        Returns:
            True if token exists
        """
        env_name = token_name.replace("-", "_")
        if os.environ.get(env_name) == "1":
            write_debug_log("approval", "has_token_env", token_name=token_name, env_name=env_name)
            return True

        token_file = _approvals_dir() / token_name
        exists = token_file.exists()
        write_debug_log("approval", "has_token_file", token_name=token_name, exists=exists)
        return exists

    @staticmethod
    def _sanitize_target(target: str) -> str:
        """Sanitize target for use as a filename component.

        Replaces /, :, . with - for safe filenames.
        """
        return re.sub(r'[/:.]+', '-', target).strip('-')

    def grant_scope(
        self,
        target: str,
        level: str,
        source: str = "UI approval",
        target_type: Optional[str] = None,
    ) -> bool:
        """Add or upgrade a target in scope.

        Creates a one-time SCOPE-GRANT token, then calls approve-target.py
        which consumes the token and syncs to SCOPE.md.

        Args:
            target: Target hostname/IP
            level: Scope level (FULL, LIMITED, NONE, CUSTOM)
            source: Source of approval
            target_type: Optional "network" or "local" classification

        Returns:
            True if granted successfully
        """
        approve_script = _body_root() / "layer1" / "scripts" / "approve-target.py"
        write_debug_log(
            "approval",
            "grant_scope_start",
            target=target,
            level=level,
            source=source,
            target_type=target_type or "",
            script=str(approve_script),
            mode="python",
        )

        if not approve_script.exists():
            write_debug_log("approval", "grant_scope_fail_missing_script", script=str(approve_script))
            return False

        direct_helper = self._load_scope_direct_helper(approve_script)
        if direct_helper is not None:
            try:
                ok = bool(direct_helper(target, level, source, "", target_type or ""))
                write_debug_log(
                    "approval",
                    "grant_scope_direct_result",
                    target=target,
                    level=level,
                    ok=ok,
                )
                return ok
            except Exception as exc:
                write_debug_log(
                    "approval",
                    "grant_scope_direct_error",
                    target=target,
                    level=level,
                    error=str(exc),
                )

        # Create one-time SCOPE-GRANT token
        self._ensure_dirs()
        sanitized = self._sanitize_target(target)
        token_file = _bra_state() / "one-time-approvals" / f"SCOPE-GRANT-{sanitized}"
        try:
            token_file.parent.mkdir(parents=True, exist_ok=True)
            token_content = (
                f"target={target}\n"
                f"level={level}\n"
                f"source={source}\n"
                f"created={datetime.now(timezone.utc).isoformat()}\n"
            )
            token_file.write_text(token_content, encoding="utf-8")
            write_debug_log("approval", "grant_scope_token_created", token=str(token_file))
        except Exception as exc:
            write_debug_log("approval", "grant_scope_token_fail", token=str(token_file), error=str(exc))
            return False

        try:
            cmd = [(os.environ.get("BRA_PYTHON_EXECUTABLE") or "python3"), str(approve_script), target, level, source]
            if target_type:
                cmd.append(target_type)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(_body_root()),
                env={**os.environ, "BRA_LAYER1_PORT": "python"},
            )
            ok = result.returncode == 0
            write_debug_log("approval", "grant_scope_result", target=target, level=level, returncode=result.returncode, ok=ok)
            if not ok:
                # Clean up token on failure
                token_file.unlink(missing_ok=True)
            return ok
        except Exception:
            # Clean up token on error
            token_file.unlink(missing_ok=True)
            write_debug_log("approval", "grant_scope_error", target=target, level=level)
            return False

    @staticmethod
    def _load_scope_direct_helper(approve_script: Path):
        """Load direct UI scope-registration helper from approve-target.py when available."""
        try:
            spec = importlib.util.spec_from_file_location(
                "bra_approve_target_direct",
                str(approve_script),
            )
            if spec is None or spec.loader is None:
                return None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            helper = getattr(module, "grant_target_from_ui", None)
            return helper if callable(helper) else None
        except BaseException:
            return None

    def grant_tool_execution(self, tool_name: str, tool_use_id: str) -> bool:
        """Grant one-time tool execution approval.

        Args:
            tool_name: Name of tool
            tool_use_id: Unique tool use ID

        Returns:
            True if granted
        """
        approval_file = _bra_state() / "one-time-approvals" / f"TOOL-{tool_use_id}"
        write_debug_log("approval", "grant_tool_execution_start", tool_name=tool_name, tool_use_id=tool_use_id)

        self._ensure_dirs()
        try:
            approval_file.write_text(tool_name)
            write_debug_log("approval", "grant_tool_execution_ok", tool_name=tool_name, path=str(approval_file))
            return True
        except Exception:
            write_debug_log("approval", "grant_tool_execution_fail", tool_name=tool_name, path=str(approval_file))
            return False

    def consume_one_time(self, approval_type: str, identifier: str) -> bool:
        """Consume (delete) a one-time approval.

        Args:
            approval_type: Type prefix (SCRIPT, TOOL, token name)
            identifier: Unique identifier

        Returns:
            True if consumed
        """
        approval_dir = _bra_state() / "one-time-approvals"
        write_debug_log("approval", "consume_one_time_start", approval_type=approval_type, identifier=identifier)

        for f in approval_dir.glob(f"{approval_type}-{identifier}*"):
            try:
                f.unlink()
                write_debug_log("approval", "consume_one_time_ok", path=str(f))
                return True
            except Exception:
                pass

        write_debug_log("approval", "consume_one_time_not_found", approval_type=approval_type, identifier=identifier)
        return False

    # Valid token names — union of governance tokens and operational tokens
    VALID_TOKENS: set[str] = {
        *BlockDetector.TOKEN_PATTERNS.values(),
        "WATCH", "TRACK", "BRA-DEBUG", "BRA_VERBOSE", "NEGATIVE-RESULTS", "IGNORE-BACKUP",
        "FINDINGS-FASTPATH",
        "SLOWPATH-FINDINGS",
    }

    def list_active_tokens(self) -> list[str]:
        """List all currently active tokens.

        Only returns tokens with known names — unknown files in
        approvals/ are ignored to prevent ghost tokens.

        Returns:
            List of active token names
        """
        tokens = []

        if _approvals_dir().exists():
            for f in _approvals_dir().iterdir():
                if f.is_file() and f.name in self.VALID_TOKENS:
                    tokens.append(f.name)

        for pattern, token_name in BlockDetector.TOKEN_PATTERNS.items():
            env_name = token_name.replace("-", "_")
            if os.environ.get(env_name) == "1":
                if token_name not in tokens:
                    tokens.append(token_name)

        out = sorted(tokens)
        write_debug_log("approval", "list_active_tokens", count=len(out), tokens=out)
        return out

    def queue_retry(self, operation: BlockedOperation) -> None:
        """Queue a blocked operation for retry after approval.

        Args:
            operation: The blocked operation
        """
        self._pending_retries.append(operation)
        write_debug_log("approval", "queue_retry", approval_type=operation.approval_type.value)

    def get_pending_retry(self) -> Optional[BlockedOperation]:
        """Get next pending retry operation.

        Returns:
            BlockedOperation if any pending, None otherwise
        """
        if self._pending_retries:
            op = self._pending_retries.pop(0)
            write_debug_log("approval", "dequeue_retry", approval_type=op.approval_type.value)
            return op
        return None

    def clear_pending_retries(self) -> None:
        """Clear all pending retries."""
        self._pending_retries.clear()
        write_debug_log("approval", "clear_pending_retries")


# =============================================================================
# SCRIPT APPROVAL - Original functions (preserved for compatibility)
# =============================================================================

# Patterns that indicate script execution
SCRIPT_PATTERNS = [
    # Direct execution with ./ prefix
    r"^\./[^\s]+\.sh\b",
    r"^\./[^\s]+\.bash\b",
    # Absolute path to shell script
    r"^/[^\s]+\.sh\b",
    r"^/[^\s]+\.bash\b",
    # Shell invocation
    r"^(?:bash|sh|zsh)\s+[^\s]+\.sh\b",
    r"^(?:bash|sh|zsh)\s+[^\s]+\.bash\b",
    r"^/bin/(?:bash|sh|zsh)\s+",
    r"^/usr/bin/(?:bash|sh|zsh)\s+",
    # Python scripts
    r"^(?:python3?|python3\.\d+)\s+[^\s]+\.py\b",
    # Perl scripts
    r"^perl\s+[^\s]+\.pl\b",
]

# Compiled patterns for efficiency
_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SCRIPT_PATTERNS]


def is_script_execution(command: str) -> bool:
    """Check if command appears to execute a script.

    Args:
        command: The command string to check

    Returns:
        True if command looks like script execution
    """
    command = command.strip()

    for pattern in _COMPILED_PATTERNS:
        if pattern.search(command):
            write_debug_log("approval", "script_execution_detected", command=command[:200], pattern=pattern.pattern)
            return True

    write_debug_log("approval", "script_execution_not_detected", command=command[:200])
    return False


def extract_script_path(command: str) -> Optional[str]:
    """Extract the script path from a command.

    Args:
        command: The command string

    Returns:
        Script path if found, None otherwise
    """
    command = command.strip()

    # Direct execution (./script.sh or /path/to/script.sh)
    if command.startswith("./") or command.startswith("/"):
        # First token is the script
        parts = command.split()
        if parts:
            write_debug_log("approval", "extract_script_path_direct", script_path=parts[0])
            return parts[0]

    # Shell invocation (bash script.sh)
    shell_match = re.match(
        r"^(?:/(?:usr/)?bin/)?(?:bash|sh|zsh)\s+(\S+)",
        command,
        re.IGNORECASE,
    )
    if shell_match:
        write_debug_log("approval", "extract_script_path_shell", script_path=shell_match.group(1))
        return shell_match.group(1)

    # Python invocation
    python_match = re.match(
        r"^(?:python3?|python3\.\d+)\s+(\S+)",
        command,
        re.IGNORECASE,
    )
    if python_match:
        write_debug_log("approval", "extract_script_path_python", script_path=python_match.group(1))
        return python_match.group(1)

    # Perl invocation
    perl_match = re.match(r"^perl\s+(\S+)", command, re.IGNORECASE)
    if perl_match:
        write_debug_log("approval", "extract_script_path_perl", script_path=perl_match.group(1))
        return perl_match.group(1)

    write_debug_log("approval", "extract_script_path_none", command=command[:200])
    return None


def read_script_content(
    script_path: str,
    max_lines: int = 200,
    max_chars: int = 10000,
) -> str:
    """Read script content for display to user.

    Args:
        script_path: Path to the script
        max_lines: Maximum lines to return
        max_chars: Maximum characters to return

    Returns:
        Script content (possibly truncated)
    """
    # Resolve path relative to BODY_ROOT if not absolute
    path = Path(script_path)
    if not path.is_absolute():
        path = _body_root() / path
    write_debug_log("approval", "read_script_start", script_path=script_path, resolved_path=str(path))

    try:
        content = path.read_text()
    except FileNotFoundError:
        write_debug_log("approval", "read_script_not_found", script_path=script_path)
        return f"Script not found: {script_path}"
    except PermissionError:
        write_debug_log("approval", "read_script_permission_denied", script_path=script_path)
        return f"Permission denied: {script_path}"
    except Exception as e:
        write_debug_log("approval", "read_script_error", script_path=script_path, error=str(e))
        return f"Error reading script: {e}"

    lines = content.splitlines()

    # Truncate by lines
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines.append(f"\n... (truncated, showing {max_lines} of {len(content.splitlines())} lines)")

    result = "\n".join(lines)

    # Truncate by characters
    if len(result) > max_chars:
        result = result[:max_chars] + f"\n... (truncated at {max_chars} characters)"

    write_debug_log("approval", "read_script_done", script_path=script_path, output_chars=len(result))
    return result


def _get_approval_token_name(script_path: str) -> str:
    """Generate approval token name from script path.

    Uses a hash to ensure valid filename regardless of script path.

    Args:
        script_path: Path to the script

    Returns:
        Token name (safe for use as filename)
    """
    # Normalize the path
    normalized = str(Path(script_path).resolve()) if Path(script_path).exists() else script_path

    # Create hash
    path_hash = hashlib.sha256(normalized.encode()).hexdigest()[:16]

    # Include sanitized basename for readability
    basename = Path(script_path).name
    safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in basename)
    safe_name = safe_name[:30]

    return f"SCRIPT-{safe_name}-{path_hash}"


def has_script_approval(script_path: str) -> bool:
    """Check if script has been approved for execution.

    Args:
        script_path: Path to the script

    Returns:
        True if script is approved
    """
    token_name = _get_approval_token_name(script_path)
    token_file = _approvals_dir() / token_name

    exists = token_file.exists()
    write_debug_log("approval", "has_script_approval", script_path=script_path, token_name=token_name, exists=exists)
    return exists


def grant_script_approval(script_path: str) -> str:
    """Grant approval for script execution.

    Args:
        script_path: Path to the script

    Returns:
        Token name that was created
    """
    _approvals_dir().mkdir(parents=True, exist_ok=True)

    token_name = _get_approval_token_name(script_path)
    token_file = _approvals_dir() / token_name

    # Store script path in the token file for reference
    token_file.write_text(f"Approved script: {script_path}\n")
    write_debug_log("approval", "grant_script_approval", script_path=script_path, token_name=token_name)

    return token_name


def revoke_script_approval(script_path: str) -> bool:
    """Revoke approval for script execution.

    Args:
        script_path: Path to the script

    Returns:
        True if token was revoked, False if it didn't exist
    """
    token_name = _get_approval_token_name(script_path)
    token_file = APPROVALS_DIR / token_name

    if token_file.exists():
        token_file.unlink()
        write_debug_log("approval", "revoke_script_approval_ok", script_path=script_path, token_name=token_name)
        return True

    write_debug_log("approval", "revoke_script_approval_missing", script_path=script_path, token_name=token_name)
    return False


def list_approved_scripts() -> list[tuple[str, str]]:
    """List all approved scripts.

    Returns:
        List of (token_name, script_path) tuples
    """
    if not _approvals_dir().exists():
        write_debug_log("approval", "list_approved_scripts_empty", reason="approvals_dir_missing")
        return []

    approved = []
    for token_file in _approvals_dir().iterdir():
        if token_file.name.startswith("SCRIPT-"):
            try:
                content = token_file.read_text()
                # Extract script path from content
                if content.startswith("Approved script: "):
                    script_path = content.split("Approved script: ", 1)[1].strip()
                    approved.append((token_file.name, script_path))
            except Exception:
                pass

    write_debug_log("approval", "list_approved_scripts_done", count=len(approved))
    return approved
