"""Protected filesystem operations for head module.

All file operations within head should use this module to ensure
the same governance rules apply to head's own code as to the agent.

Rules enforced:
- layer1/: NEVER writable during engagement
- layer2-templates/: Requires LAYER2-WRITE-APPROVAL token
- layer3-engagement/NOTES/: Append-only (content can only grow)
- layer3-engagement/ reporting outputs: Append-only per ROE:16
  (REPORT.md, CNA-SUBMISSION.md, DISCLOSURE-PACKAGE.md, VENDOR-SUBMISSION.md, IMPROVEMENTS.md)
- layer3-engagement/: Allowlisted files and subdirectories only
- .bra/: Schema-enforced access control (see bra_schema.py)
- Everything else: Blocked
"""

from pathlib import Path
from typing import Union

from bra.config.settings import LAYER1, LAYER2, LAYER3, BRA_STATE

# Tier 2 — append-only reporting outputs (ROE:16, self-improvement.md:59)
_APPEND_ONLY_FILES = {
    "REPORT.md", "CNA-SUBMISSION.md", "DISCLOSURE-PACKAGE.md",
    "VENDOR-SUBMISSION.md", "IMPROVEMENTS.md",
}

# layer3-engagement/ allowlist — subdirectories (anything underneath is allowed)
_ALLOWED_SUBDIRS = {"NOTES", "disclosure", "pitches", "ingest"}

# layer3-engagement/ allowlist — root-level files
_ALLOWED_ROOT_FILES = {
    "SCOPE.md", "ROE.md", "PLAN.md", "REPORT.md", "REVIEW.md", "RETRO.md",
    "README-PROJECTOVERVIEW.md", "BACKUPS.md", "TOOLSUITES.md", "SKILLSUITES.md",
    "CNA-SUBMISSION.md", "DISCLOSURE-PACKAGE.md", "VENDOR-SUBMISSION.md",
    "IMPROVEMENTS.md", "STATS.md", "LESSONS-LEARNED.md",
    "SCRIPTS-AUDIT-REPORT.md", "README.md",
}


class ProtectedPathError(Exception):
    """Raised when attempting to write to a protected path."""
    pass


def has_token(token_name: str) -> bool:
    """Check if an approval token is set.

    Args:
        token_name: Token name (e.g., "LAYER2-WRITE-APPROVAL")

    Returns:
        True if token is set
    """
    import os
    from bra.config.settings import APPROVALS_DIR

    # Check environment variable (TOKEN_NAME with underscores)
    env_name = token_name.replace("-", "_")
    if os.environ.get(env_name) == "1":
        return True

    # Check approval file
    token_file = APPROVALS_DIR / token_name
    if token_file.exists():
        return True

    return False


def _is_under(path: Path, parent: Path) -> bool:
    """Check if path is under parent directory."""
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _enforce_write_rules(path: Path, content: str) -> None:
    """Enforce write rules - same logic as file-guard.py.

    Raises:
        ProtectedPathError: If write is not allowed
    """
    resolved = path.resolve()

    # Layer 1 - NEVER writable
    if _is_under(resolved, LAYER1):
        raise ProtectedPathError(
            f"layer1 is immutable during engagement. Cannot write to: {path}"
        )

    # Layer 2 - requires LAYER2-WRITE-APPROVAL token
    if _is_under(resolved, LAYER2):
        if not has_token("LAYER2-WRITE-APPROVAL"):
            raise ProtectedPathError(
                f"layer2-templates requires LAYER2-WRITE-APPROVAL token. "
                f"Cannot write to: {path}"
            )
        return  # Token present, allow write to layer2

    # NOTES - append-only (content can only grow)
    notes_dir = LAYER3 / "NOTES"
    if _is_under(resolved, notes_dir):
        if resolved.exists():
            existing_size = resolved.stat().st_size
            new_size = len(content.encode("utf-8"))
            if new_size < existing_size:
                raise ProtectedPathError(
                    f"NOTES directory is append-only. "
                    f"New content ({new_size} bytes) smaller than existing ({existing_size} bytes). "
                    f"Cannot shrink: {path}"
                )

    # .bra/ — schema-enforced access control
    if _is_under(resolved, BRA_STATE):
        from bra.core.bra_schema import resolve_access
        try:
            rel = str(resolved.relative_to(BRA_STATE.resolve()))
        except ValueError:
            raise ProtectedPathError(
                f".bra/ path resolution error: {path}"
            )
        access = resolve_access(rel)
        if access is None:
            raise ProtectedPathError(
                f"Path not in .bra/ schema: {path}. "
                f"Only declared paths are writable."
            )
        if access == "agent-writable":
            return  # No restrictions
        if access == "system-only":
            return  # System code (filesystem.py callers) allowed
        if access == "append-only":
            if resolved.exists():
                existing_size = resolved.stat().st_size
                new_size = len(content.encode("utf-8"))
                if new_size < existing_size:
                    raise ProtectedPathError(
                        f".bra/logs/ is append-only. "
                        f"Current: {existing_size} bytes, New: {new_size} bytes. "
                        f"Content can only grow, not shrink."
                    )
            return  # Append-only, size OK or new file
        if access == "operator-only":
            raise ProtectedPathError(
                f".bra/ operator-only path: {path}. "
                f"Approval tokens are managed by the operator via TUI."
            )
        raise ProtectedPathError(f"Unknown access level for .bra/ path: {path}")

    # layer3-engagement/ — Tier 2 append-only + allowlist
    if _is_under(resolved, LAYER3):
        try:
            rel = resolved.relative_to(LAYER3.resolve())
        except ValueError:
            return  # Shouldn't happen but don't block on path math

        parts = rel.parts

        if parts and parts[0] == "artifacts":
            raise ProtectedPathError(
                f"{path} is not an allowed runtime artifact location. "
                "Use .bra/artifacts/ for governed runtime artifacts or "
                ".bra/artifacts/raw/ for captured evidence."
            )

        # Tier 2: append-only reporting outputs
        if (len(parts) == 1 and parts[0] in _APPEND_ONLY_FILES
                and resolved.exists()):
            existing_size = resolved.stat().st_size
            new_size = len(content.encode("utf-8"))
            if new_size < existing_size:
                raise ProtectedPathError(
                    f"{resolved.name} is append-only (ROE:16 — reporting outputs). "
                    f"Current: {existing_size} bytes, New: {new_size} bytes. "
                    f"Content can only grow, not shrink."
                )
            return  # Tier 2 file, size OK

        # Allowlist: known subdirectories
        if parts and parts[0] in _ALLOWED_SUBDIRS:
            return  # Allowed

        # Allowlist: known root-level files
        if len(parts) == 1 and parts[0] in _ALLOWED_ROOT_FILES:
            # SCOPE.md: locked after scope intake (SCOPE-CONFIRMED token).
            if parts[0] == "SCOPE.md":
                scope_confirmed = BRA_STATE / "approvals" / "SCOPE-CONFIRMED"
                if scope_confirmed.exists():
                    raise ProtectedPathError(
                        "SCOPE.md is locked after scope intake (SCOPE-CONFIRMED). "
                        "Target scope changes must go through the approval modal."
                    )
            return  # Allowed

        # Not in allowlist — block
        raise ProtectedPathError(
            f"Not in layer3-engagement/ allowlist: {path}. "
            f"Known subdirectories: {', '.join(sorted(_ALLOWED_SUBDIRS))}. "
            f"Finding records belong in NOTES/FINDINGS.md."
        )

    # Everything else - blocked
    raise ProtectedPathError(
        f"Write outside allowed paths (.bra/, layer3-engagement/). "
        f"Cannot write to: {path}"
    )


def read(path: Path) -> str:
    """Read a file.

    Args:
        path: Path to read

    Returns:
        File contents as string
    """
    with open(path, "r") as f:
        return f.read()


def write(path: Path, content: str) -> None:
    """Write to a file with protection rules.

    Args:
        path: Path to write
        content: Content to write

    Raises:
        ProtectedPathError: If write is not allowed
    """
    _enforce_write_rules(path, content)

    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as f:
        f.write(content)


def append(path: Path, content: str) -> None:
    """Append to a file with protection rules.

    Args:
        path: Path to append to
        content: Content to append

    Raises:
        ProtectedPathError: If write is not allowed
    """
    existing = ""
    if path.exists():
        existing = read(path)

    new_content = existing + content
    _enforce_write_rules(path, new_content)

    with open(path, "a") as f:
        f.write(content)
