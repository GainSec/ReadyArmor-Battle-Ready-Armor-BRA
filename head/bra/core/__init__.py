"""Core module for BRA."""

from bra.core.bridge import run_script, detect_session_state
from bra.core.filesystem import read, write, append, ProtectedPathError, has_token
from bra.core.agent import (
    run_agent,
    SDK_AVAILABLE,
)
from bra.core.approval import (
    is_script_execution,
    extract_script_path,
    read_script_content,
    has_script_approval,
    grant_script_approval,
    revoke_script_approval,
    list_approved_scripts,
)
from bra.core.runner import AgentRunner, create_tui_runner, create_minimal_runner
from bra.core.data_loaders import (
    load_health,
    load_intel,
    load_summary,
    load_report,
    load_growth,
    load_loadout,
    load_logs,
)

__all__ = [
    "run_script",
    "detect_session_state",
    "read",
    "write",
    "append",
    "ProtectedPathError",
    "has_token",
    "run_agent",
    "SDK_AVAILABLE",
    # Approval
    "is_script_execution",
    "extract_script_path",
    "read_script_content",
    "has_script_approval",
    "grant_script_approval",
    "revoke_script_approval",
    "list_approved_scripts",
    # Runner
    "AgentRunner",
    "create_tui_runner",
    "create_minimal_runner",
    # Data loaders
    "load_health",
    "load_intel",
    "load_summary",
    "load_report",
    "load_growth",
    "load_loadout",
    "load_logs",
]
