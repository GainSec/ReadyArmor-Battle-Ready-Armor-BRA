"""Bridge module for calling body scripts.

This module provides Python wrappers for calling body layer1 scripts.
All scripts are Python — shell fallbacks have been removed.

It handles:
- Script path resolution (.py in body/layer1/scripts/)
- Working directory setup
- Result capture

Note: Governance enforcement happens in hooks/, not here.
This module is for non-governance script calls (status, scope reading, etc.)
"""

import subprocess
import os
import json
import sys
from pathlib import Path
from typing import Optional

from bra.config import settings


def _scripts_dir() -> Path:
    return settings.SCRIPTS_DIR


def _body_root() -> Path:
    return settings.BODY_ROOT


def _bra_state() -> Path:
    return settings.BRA_STATE


def _layer3() -> Path:
    return settings.LAYER3


def _artifacts_dir() -> Path:
    return settings.ARTIFACTS_DIR


def _pipeline_state_file() -> Path:
    return _bra_state() / "pipeline_state.json"


def _resolve_script_path(name: str) -> Path:
    """Resolve script name to its Python path.

    Only ``.py`` layer1 ports are supported.
    """
    path = Path(name)
    if path.suffix and path.suffix != ".py":
        raise FileNotFoundError(f"Unsupported non-Python script request: {name}")
    stem = path.stem if path.suffix else path.name
    return _scripts_dir() / f"{stem}.py"


def run_script(
    name: str,
    *args: str,
    capture_output: bool = True,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess:
    """Run a Python script from body/layer1/scripts/ directory.

    Args:
        name: Script name (e.g., "status.py" or "status")
        *args: Arguments to pass to the script
        capture_output: Whether to capture stdout/stderr
        timeout: Timeout in seconds (None for no timeout)

    Returns:
        subprocess.CompletedProcess with returncode, stdout, stderr
    """
    python_path = _resolve_script_path(name)

    if not python_path.exists():
        raise FileNotFoundError(f"Script not found: {python_path}")

    python_exec = (os.environ.get("BRA_PYTHON_EXECUTABLE") or sys.executable or "python3").strip()
    cmd = [python_exec, str(python_path)] + list(args)
    return subprocess.run(
        cmd,
        capture_output=capture_output,
        text=True,
        cwd=str(_body_root()),
        timeout=timeout,
        env={**os.environ, "BRA_CALLER": "head", "BRA_LAYER1_PORT": "python"},
    )


def get_script_path(name: str) -> Path:
    """Get full path to a script.

    Args:
        name: Script name (e.g., "status.py")

    Returns:
        Path to the script
    """
    return _resolve_script_path(name)


def detect_session_state() -> str:
    """Detect current session state.

    Returns one of:
        FRESH - No .bra/ directory
        NEEDS_SCOPE - .bra exists but scope not defined
        READY - Scope defined, pipeline not started
        IN_PROGRESS - Active session or some phases complete
        ENDED - End engagement ran, report generated
        COMPLETE - Growth proposals reviewed, lifecycle complete
    """
    # FRESH - No .bra/ directory
    if not _bra_state().exists():
        return "FRESH"

    # Check for active session first
    state = _load_pipeline_state()
    if state.get("active_session_id") and state.get("status") == "in_progress":
        return "IN_PROGRESS"

    artifacts = _artifacts_dir()

    # Check phase completion markers
    intel_done = (artifacts / ".intel_complete").exists()
    static_done = (artifacts / ".static_complete").exists()
    dynamic_done = (artifacts / ".dynamic_complete").exists()
    report_done = (artifacts / ".report_complete").exists()

    # COMPLETE - Growth reviewed (all phases done + growth marker)
    if intel_done and static_done and dynamic_done and report_done:
        if (artifacts / ".growth_complete").exists():
            return "COMPLETE"
        return "ENDED"

    # IN_PROGRESS - Some phases complete
    if intel_done or static_done or dynamic_done:
        return "IN_PROGRESS"

    # Check scope status
    scope_file = _layer3() / "SCOPE.md"
    scope_defined = False

    if scope_file.exists():
        content = scope_file.read_text()
        if "_TBD_" not in content and "Populate from scope-intake" not in content:
            if len(content.splitlines()) > 10:
                scope_defined = True

    # NEEDS_SCOPE - .bra exists but scope not defined
    if not scope_defined:
        return "NEEDS_SCOPE"

    # READY - Scope defined, pipeline not started
    return "READY"


def is_scope_configured() -> bool:
    """Check if scope is already configured (not template)."""
    scope_file = _layer3() / "SCOPE.md"
    if not scope_file.exists():
        return False

    content = scope_file.read_text()
    # Check if it's still a template
    if "_TBD_" in content or "Populate from scope-intake" in content:
        return False
    # Must have meaningful content
    if len(content.splitlines()) < 10:
        return False
    return True


def get_scope_summary() -> dict:
    """Get summary of configured scope."""
    scope_file = _layer3() / "SCOPE.md"
    if not scope_file.exists():
        return {}

    content = scope_file.read_text()
    summary = {}

    # Extract target name - handle both "**Name:**" and "- **Name:**" formats
    for line in content.splitlines():
        line_stripped = line.lstrip("- ").strip()
        if line_stripped.startswith("**Name:**"):
            summary["name"] = line_stripped.replace("**Name:**", "").strip()
        elif line_stripped.startswith("**Type:**") or line_stripped.startswith("**Target Type:**"):
            value = line_stripped.replace("**Target Type:**", "").replace("**Type:**", "").strip()
            summary["type"] = value
        elif "ACTIVE-TESTING-APPROVAL:" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                summary["active_testing"] = parts[-1].strip()

    return summary


def get_current_phase() -> str:
    """Get current engagement phase from markers."""
    artifacts = _artifacts_dir()

    if (artifacts / ".report_complete").exists():
        return "Report"
    elif (artifacts / ".dynamic_complete").exists():
        return "Dynamic"
    elif (artifacts / ".static_complete").exists():
        return "Static"
    elif (artifacts / ".intel_complete").exists():
        return "Intel"
    else:
        return "Initial"


def _load_pipeline_state() -> dict:
    """Load pipeline state from file."""
    pipeline_state_file = _pipeline_state_file()
    if pipeline_state_file.exists():
        try:
            return json.loads(pipeline_state_file.read_text())
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _save_pipeline_state(state: dict) -> None:
    """Save pipeline state to file."""
    bra_state = _bra_state()
    bra_state.mkdir(parents=True, exist_ok=True)
    _pipeline_state_file().write_text(json.dumps(state, indent=2))


def update_session_state(
    session_id: Optional[str] = None,
    phase: Optional[str] = None,
    status: Optional[str] = None,
    update_turn: bool = False,
    clear_session: bool = False,
) -> None:
    """Update session state in pipeline_state.json.

    Args:
        session_id: Active session ID to set
        phase: Current phase to set
        status: Status to set (in_progress, complete, etc.)
        update_turn: If True, update last_turn_at timestamp
        clear_session: If True, clear active_session_id
    """
    from datetime import datetime, timezone

    state = _load_pipeline_state()

    if clear_session:
        state.pop("active_session_id", None)
        state["status"] = "complete"
    else:
        if session_id is not None:
            state["active_session_id"] = session_id
            state["phase_started_at"] = datetime.now(timezone.utc).isoformat()

        if phase is not None:
            state["current_phase"] = phase

        if status is not None:
            state["status"] = status

        if update_turn:
            state["last_turn_at"] = datetime.now(timezone.utc).isoformat()

    _save_pipeline_state(state)


def get_active_session() -> Optional[str]:
    """Get active session ID if any.

    Returns:
        Session ID or None
    """
    state = _load_pipeline_state()
    return state.get("active_session_id")
