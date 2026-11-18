"""INTEL report cleanup via SDK session.

On-demand cleanup: user triggers from TUI/GUI, a new SDK session
reads INTEL.md, removes junk, tightens formatting. Original is
versioned before overwrite.
"""

import shutil
from pathlib import Path

from bra.core.agent import run_agent


_INTEL_FILENAME = "INTEL.md"


def _version_intel(notes_dir: Path) -> Path:
    """Copy current INTEL file to v{N} version, return versioned path.

    Runs before every cleanup — non-negotiable.
    """
    intel = notes_dir / _INTEL_FILENAME
    n = 1
    while (notes_dir / f"v{n}.{_INTEL_FILENAME}").exists():
        n += 1
    versioned = notes_dir / f"v{n}.{_INTEL_FILENAME}"
    shutil.copy2(intel, versioned)
    return versioned


def _build_cleanup_prompt(notes_dir: Path) -> str:
    """Build the cleanup prompt with current INTEL content."""
    intel = notes_dir / _INTEL_FILENAME
    intel_path = str(intel.resolve())
    content = intel.read_text() if intel.exists() else ""

    return f"""You are cleaning up an intelligence report from a security engagement.

Below is the current content of {_INTEL_FILENAME}. Your task:

1. Remove entries that contain no actionable intelligence (failed connections, N/A fields, test markers, placeholder data)
2. Fix column headers for any tables that have generic headers (Col 1, Col 2, etc.) — infer better names from the data
3. Preserve ALL entries that contain real data — err on the side of keeping
4. Maintain the markdown table/section structure
5. Do NOT add new data — only clean what exists
6. Write the cleaned version to {intel_path}

Current content:

```markdown
{content}
```

Read the file, clean it, write the cleaned version back to {intel_path}. Do not create any other files."""


async def run_cleanup(
    notes_dir: Path,
    model: str | None = None,
) -> Path:
    """Run INTEL cleanup as a provider-routed agent turn.

    Versions the current file, then runs cleanup via run_agent().

    Args:
        notes_dir: Path to NOTES directory

    Returns:
        Path to the versioned (pre-cleanup) file
    """
    intel = notes_dir / _INTEL_FILENAME
    if not intel.exists():
        raise FileNotFoundError(f"{_INTEL_FILENAME} not found in {notes_dir}")

    # Version before cleanup — non-negotiable
    versioned = _version_intel(notes_dir)

    # Run cleanup session
    prompt = _build_cleanup_prompt(notes_dir)
    error = None
    async for message in run_agent(
        prompt=prompt,
        allowed_tools=["Read", "Write"],
        model=model,
    ):
        if isinstance(message, dict) and message.get("type") == "error":
            error = str(message.get("content", "Unknown error"))

    if error:
        raise RuntimeError(f"INTEL cleanup failed: {error}")

    return versioned
