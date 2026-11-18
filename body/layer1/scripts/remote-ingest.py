#!/usr/bin/env python3
"""Native remote ingest helper (sshfs command planner/executor).

Mounts remote Linux filesystem via SSHFS and generates path config for ingestion.
Platform: macOS (primary), Linux (secondary).
Invariant: Remote filesystem mounted read-only.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import os
import platform
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


# Excluded directories for recursive listing
EXCLUDED_DIRS = frozenset({
    "node_modules", "venv", ".venv", "__pycache__", "target",
    "dist", "build", ".git", "rootfs", "squashfs-root", "filesystem",
    "firmware", "extracted",
})

# Default SSHFS mount options (read-only + resilience)
DEFAULT_MOUNT_OPTS: list[tuple[str, str | None]] = [
    ("ro", None),                    # Read-only mount
    ("reconnect", None),             # Auto-reconnect on disconnect
    ("ServerAliveInterval", "15"),    # Keep connection alive
    ("ServerAliveCountMax", "3"),     # Retry 3 times before failing
    ("follow_symlinks", None),       # Follow symlinks on remote
    ("cache", "yes"),                # Enable caching for performance
    ("auto_cache", None),            # Invalidate cache on file change
]


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_body_root(script_path: Path) -> Path:
    script_root = script_path.resolve().parents[2]
    for candidate in (Path.cwd().resolve(), script_root):
        if (candidate / ".bra").exists() or (candidate / "layer3-engagement").exists():
            return candidate
    return script_root


def _append_log(log_file: Path, level: str, message: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(f"[{_utc_now()}] [{level}] {message}\n")


def _safe_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=path.name + ".", delete=False) as tmp:
        json.dump(payload, tmp, indent=2)
        tmp.write("\n")
        temp_path = Path(tmp.name)
    temp_path.replace(path)


def _resolve_mount_point(body_root: Path, value: str | None) -> Path:
    if value is None:
        return body_root / ".mnt" / "remote-ingest"
    mount = Path(value).expanduser()
    return mount if mount.is_absolute() else body_root / mount


def _is_macos() -> bool:
    return platform.system() == "Darwin"


def _print_install_instructions() -> None:
    """Print platform-specific sshfs install instructions."""
    print("", file=sys.stderr)
    if _is_macos():
        print("Install on macOS (FUSE-T - recommended, no kernel extension):", file=sys.stderr)
        print("  brew tap macos-fuse-t/homebrew-cask", file=sys.stderr)
        print("  brew install fuse-t", file=sys.stderr)
        print("  brew install fuse-t-sshfs", file=sys.stderr)
        print("", file=sys.stderr)
        print("Or with macFUSE (requires Recovery Mode + security approval):", file=sys.stderr)
        print("  brew install --cask macfuse", file=sys.stderr)
        print("  brew install gromgit/fuse/sshfs-mac", file=sys.stderr)
    else:
        print("Install on Linux:", file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt install sshfs", file=sys.stderr)
        print("  Fedora/RHEL:   sudo dnf install fuse-sshfs", file=sys.stderr)
        print("  Arch:          sudo pacman -S sshfs", file=sys.stderr)


def _check_sshfs_installed() -> bool:
    """Check if sshfs is installed. Print install instructions if not."""
    if shutil.which("sshfs") is not None:
        path = shutil.which("sshfs")
        print(f"[INFO] sshfs found: {path}")
        return True
    print("[ERROR] sshfs is not installed", file=sys.stderr)
    _print_install_instructions()
    return False


def _check_ssh_access(target: str) -> bool:
    """Verify SSH access to target. Returns True if accessible or user confirms."""
    print(f"[STEP] Checking SSH access to {target}...")

    ssh_cmd: list[str] = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]

    identity = os.environ.get("SSH_IDENTITY_FILE", "").strip()
    if identity:
        ssh_cmd.extend(["-i", identity])

    ssh_cmd.extend([target, "echo", "SSH OK"])

    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            print("[INFO] SSH access verified")
            return True
    except (subprocess.TimeoutExpired, OSError):
        pass

    print("[WARN] SSH connection test failed (this may be okay if using password auth)", file=sys.stderr)
    print("", file=sys.stderr)
    print("If you're using password authentication, the mount will prompt for password.", file=sys.stderr)
    print("For unattended operation, configure SSH key authentication:", file=sys.stderr)
    print(f"  ssh-copy-id {target}", file=sys.stderr)
    print("", file=sys.stderr)

    # Non-interactive: allow if password auth enabled
    password_auth = os.environ.get("SSH_PASSWORD_AUTH", "false").lower()
    if password_auth in ("true", "1", "yes"):
        print("[INFO] Password authentication enabled, continuing")
        return True

    try:
        reply = input("Continue anyway? [y/N] ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    return reply.lower() in ("y", "yes")


def _check_already_mounted(mount_point: Path) -> bool:
    """Check if mount point is already in use."""
    try:
        result = subprocess.run(
            ["mount"], capture_output=True, text=True, timeout=5,
        )
        return str(mount_point) in result.stdout
    except (subprocess.TimeoutExpired, OSError):
        return False


def _validate_identity_file() -> str | None:
    """Validate SSH identity file if specified. Returns path or None."""
    identity = os.environ.get("SSH_IDENTITY_FILE", "").strip()
    if not identity:
        return None
    path = Path(identity).expanduser()
    if path.is_file():
        print(f"[INFO] Using identity file: {path}")
        return str(path)
    print(f"[ERROR] Identity file not found: {identity}", file=sys.stderr)
    sys.exit(1)


def _build_sshfs_command(target: str, remote_path: str, mount_point: Path) -> list[str]:
    """Build sshfs command with read-only mount options."""
    command: list[str] = ["sshfs"]

    # Add default mount options
    for opt_name, opt_val in DEFAULT_MOUNT_OPTS:
        if opt_val is not None:
            command.extend(["-o", f"{opt_name}={opt_val}"])
        else:
            command.extend(["-o", opt_name])

    # Add identity file if specified and valid
    identity = _validate_identity_file()
    if identity:
        command.extend(["-o", f"IdentityFile={identity}"])

    # Password auth note
    password_auth = os.environ.get("SSH_PASSWORD_AUTH", "false").lower()
    if password_auth in ("true", "1", "yes"):
        print("[INFO] Password authentication enabled (will prompt)")

    # Extra options from environment
    extra = os.environ.get("SSHFS_OPTS", "").strip()
    if extra:
        command.extend(shlex.split(extra))

    # Source and destination
    command.extend([f"{target}:{remote_path}", str(mount_point)])
    return command


def _unmount_command() -> list[str] | None:
    for candidate in (("umount",), ("fusermount", "-u"), ("diskutil", "unmount")):
        if shutil.which(candidate[0]):
            return list(candidate)
    return None


def _run_command(command: list[str]) -> int:
    result = subprocess.run(command)
    return result.returncode


def _execute_mount(command: list[str], mount_point: Path, log_file: Path) -> int:
    if not _check_sshfs_installed():
        return 1

    # Check if already mounted
    if _check_already_mounted(mount_point):
        print(f"[WARN] Mount point already in use: {mount_point}", file=sys.stderr)
        try:
            reply = input("Unmount existing mount? [y/N] ").strip()
        except (EOFError, KeyboardInterrupt):
            return 1
        if reply.lower() in ("y", "yes"):
            _execute_unmount(mount_point, log_file)
        else:
            print("[ERROR] Cannot proceed with existing mount", file=sys.stderr)
            return 1

    _append_log(log_file, "INFO", f"Executing mount: {' '.join(shlex.quote(p) for p in command)}")
    print(f"[INFO] Executing: {' '.join(shlex.quote(p) for p in command)}")
    return _run_command(command)


def _execute_unmount(mount_point: Path, log_file: Path) -> int:
    """Unmount with platform-specific fallbacks."""
    print(f"[STEP] Unmounting {mount_point}...")

    if _is_macos():
        # macOS: try umount first, then diskutil
        rc = subprocess.run(["umount", str(mount_point)], capture_output=True).returncode
        if rc != 0:
            rc = subprocess.run(["diskutil", "unmount", str(mount_point)], capture_output=True).returncode
            if rc != 0:
                print("[WARN] Could not unmount cleanly, trying force unmount...", file=sys.stderr)
                subprocess.run(["umount", "-f", str(mount_point)], capture_output=True)
    else:
        # Linux: try fusermount first
        rc = subprocess.run(["fusermount", "-u", str(mount_point)], capture_output=True).returncode
        if rc != 0:
            print("[WARN] Could not unmount cleanly, trying force unmount...", file=sys.stderr)
            rc2 = subprocess.run(["fusermount", "-uz", str(mount_point)], capture_output=True).returncode
            if rc2 != 0:
                subprocess.run(["umount", "-l", str(mount_point)], capture_output=True)

    _append_log(log_file, "INFO", f"Unmounted {mount_point}")
    print(f"[INFO] Unmounted {mount_point}")
    return 0


def _list_directories(mount_point: Path) -> list[str]:
    """List immediate subdirectories, excluding hidden and common non-project dirs."""
    dirs: list[str] = []
    try:
        for entry in sorted(mount_point.iterdir()):
            if not entry.is_dir():
                continue
            name = entry.name
            if name.startswith("."):
                continue
            if name in EXCLUDED_DIRS:
                continue
            dirs.append(name)
    except OSError:
        pass
    return dirs


def _interactive_select(mount_point: Path) -> list[str]:
    """Interactive directory selection with toggle, range, all/none/done/quit."""
    print(f"[STEP] Scanning directories in {mount_point}...", file=sys.stderr)

    dirs = _list_directories(mount_point)
    if not dirs:
        print("[WARN] No directories found in mount point", file=sys.stderr)
        print("", file=sys.stderr)
        print("The mount point contains no subdirectories.", file=sys.stderr)
        print("Use -d (direct) mode to ingest the mounted path itself.", file=sys.stderr)
        return []

    is_selected = [False] * len(dirs)

    print("", file=sys.stderr)
    print("========================================", file=sys.stderr)
    print("  Select Directories to Ingest", file=sys.stderr)
    print("========================================", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"Found {len(dirs)} directories.", file=sys.stderr)
    print("Enter numbers separated by commas (e.g., 1,3,5) or ranges (e.g., 1-5)", file=sys.stderr)
    print("Commands: [a]ll, [n]one, [d]one, [q]uit", file=sys.stderr)
    print("", file=sys.stderr)

    while True:
        print("----------------------------------------", file=sys.stderr)
        for i, dirname in enumerate(dirs):
            marker = "*" if is_selected[i] else " "
            print(f"  {marker} {i+1:2d}) {dirname}", file=sys.stderr)
        print("----------------------------------------", file=sys.stderr)

        count = sum(is_selected)
        print(f"  Selected: {count} of {len(dirs)}", file=sys.stderr)
        print("", file=sys.stderr)

        try:
            choice = input("Enter choice: ").strip()
        except (EOFError, KeyboardInterrupt):
            return []

        lower = choice.lower()
        if lower in ("a", "all"):
            is_selected = [True] * len(dirs)
        elif lower in ("n", "none"):
            is_selected = [False] * len(dirs)
        elif lower in ("d", "done"):
            break
        elif lower in ("q", "quit"):
            print("[INFO] Selection cancelled", file=sys.stderr)
            return []
        elif choice:
            # Parse comma-separated values and/or ranges
            for part in choice.split(","):
                part = part.strip()
                if not part:
                    continue
                # Range: e.g. 1-5
                range_match = re.match(r"^(\d+)-(\d+)$", part)
                if range_match:
                    start = int(range_match.group(1)) - 1
                    end = int(range_match.group(2))
                    for idx in range(max(0, start), min(end, len(dirs))):
                        is_selected[idx] = True
                elif part.isdigit():
                    # Single number - toggle
                    idx = int(part) - 1
                    if 0 <= idx < len(dirs):
                        is_selected[idx] = not is_selected[idx]
                    else:
                        print(f"[WARN] Invalid number: {part}", file=sys.stderr)
                else:
                    print(f"[WARN] Invalid input: {part}", file=sys.stderr)
        print("", file=sys.stderr)

    selected = [dirs[i] for i in range(len(dirs)) if is_selected[i]]
    if not selected:
        print("[WARN] No directories selected", file=sys.stderr)
    return selected


def _generate_paths_config(
    body_root: Path,
    mount_point: Path,
    target: str,
    remote_path: str,
    mode: str,
    selected_paths: list[str],
) -> Path:
    """Generate .bra/paths-remote.md with ingest inputs, outputs, crawl constraints."""
    paths_config = body_root / ".bra" / "paths-remote.md"
    timestamp = _utc_now()

    lines = [
        "# Remote Ingest Paths (Auto-Generated)",
        "",
        f"> **Remote Host:** {target}",
        f"> **Remote Path:** {remote_path}",
        f"> **Mount Point:** {mount_point}",
        f"> **Mode:** {mode}",
        f"> **Generated:** {timestamp}",
        "> **Status:** ACTIVE (mount in progress)",
        "",
        "## Ingest Inputs (READONLY)",
        "",
        f"Root: {mount_point}/",
        "",
        "### Selected Paths",
    ]

    if selected_paths:
        for p in selected_paths:
            lines.append(f"- {mount_point}/{p}/")
    else:
        lines.append(f"- {mount_point}/")

    lines.extend([
        "",
        "## Ingest Outputs (WRITE ALLOWED)",
        "",
        "Root: layer3-engagement/ingest/",
        "",
        "## Crawl Constraints",
        "- do_not_traverse_outside_mount: true",
        "- do_not_follow_symlinks_outside_mount: true",
        "- never_write_to_mount: true",
        "",
        "## Default Excluded Subtrees",
    ])
    for excluded in sorted(EXCLUDED_DIRS):
        lines.append(f"- {excluded}")

    lines.extend([
        "",
        "## Usage",
        "",
        "To ingest from this remote mount, use the standard ingestion workflow",
        "with paths from this config file.",
        "",
        "To unmount when done:",
        "```bash",
        f"umount {mount_point}",
        "```",
        "",
        "Or run the cleanup command:",
        "```bash",
        f"./layer1/scripts/remote-ingest.py --unmount {mount_point}",
        "```",
    ])

    paths_config.parent.mkdir(parents=True, exist_ok=True)
    paths_config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[INFO] Generated {paths_config}")
    return paths_config


def _update_paths_config_status(body_root: Path) -> None:
    """Update paths-remote.md status to UNMOUNTED if it exists."""
    paths_config = body_root / ".bra" / "paths-remote.md"
    if not paths_config.is_file():
        return
    try:
        text = paths_config.read_text(encoding="utf-8")
        updated = text.replace("Status:** ACTIVE", "Status:** UNMOUNTED")
        if updated != text:
            paths_config.write_text(updated, encoding="utf-8")
            print(f"[INFO] Updated {paths_config} status to UNMOUNTED")
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Mount remote filesystem via SSHFS and generate path config for ingestion.",
        epilog=(
            "Environment Variables:\n"
            "  SSHFS_OPTS          Additional sshfs options (e.g., \"-p 2222\")\n"
            "  SSH_IDENTITY_FILE   Path to SSH private key\n"
            "  SSH_PASSWORD_AUTH   Set to \"true\" for password prompting\n"
            "\n"
            "Prerequisites (macOS):\n"
            "  Option A - FUSE-T (recommended, no kernel extension):\n"
            "    brew tap macos-fuse-t/homebrew-cask\n"
            "    brew install fuse-t\n"
            "    brew install fuse-t-sshfs\n"
            "\n"
            "  Option B - macFUSE (requires Recovery Mode + security approval):\n"
            "    brew install --cask macfuse\n"
            "    brew install gromgit/fuse/sshfs-mac\n"
            "\n"
            "Prerequisites (Linux):\n"
            "  1. sudo apt install sshfs  (or equivalent for your distro)\n"
            "  2. User in 'fuse' group or /etc/fuse.conf allows user mounts\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-d", "--direct", action="store_true", help="Direct mode: mount the provided remote path")
    mode.add_argument("-r", "--recursive", action="store_true", help="Recursive mode: browse and select directories")
    mode.add_argument("--unmount", action="store_true", help="Unmount mount-point and clear ingest state")

    parser.add_argument("target", nargs="?", help="Remote target in user@host form")
    parser.add_argument("remote_path", nargs="?", help="Remote path to mount")
    parser.add_argument("mount_point", nargs="?", help="Local mount path (default: .mnt/remote-ingest)")
    parser.add_argument("--select", metavar="SUBPATH", help="Subpath selection for --recursive mode (non-interactive)")
    parser.add_argument("--mount", action="store_true", help="Execute sshfs/umount command instead of dry-run")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    body_root = _find_body_root(Path(__file__))
    log_file = body_root / ".bra" / "logs" / "remote-ingest.log"
    state_file = body_root / ".bra" / "artifacts" / "remote-ingest.json"
    mount_point = _resolve_mount_point(body_root, args.mount_point)

    # --- Unmount mode ---
    if args.unmount:
        if not _check_already_mounted(mount_point):
            print(f"[WARN] No mount found at {mount_point}")
            _update_paths_config_status(body_root)
            return 0

        rc = 0
        if args.mount:
            rc = _execute_unmount(mount_point, log_file)
        else:
            cmd = _unmount_command() or ["umount"]
            print("Dry-run unmount command:")
            print(" ".join(shlex.quote(part) for part in [*cmd, str(mount_point)]))

        _update_paths_config_status(body_root)
        state_file.unlink(missing_ok=True)
        _append_log(log_file, "INFO", f"Unmount requested for {mount_point}")
        return rc

    # --- Mount modes ---
    if not args.target or not args.remote_path:
        parser.error("target and remote_path are required unless --unmount is used")

    remote_path = args.remote_path
    mode_name = "recursive" if args.recursive else "direct"

    print("")
    print("========================================")
    print("  Remote Filesystem Ingestion Setup")
    print("========================================")
    print("")
    print(f"  Mode:        {mode_name}")
    print(f"  Target:      {args.target}")
    print(f"  Remote Path: {remote_path}")
    print(f"  Mount Point: {mount_point}")
    print("")

    # Prerequisites
    print("[STEP] Checking prerequisites...")
    if not _check_sshfs_installed():
        return 1
    if not _check_ssh_access(args.target):
        return 1

    # Handle recursive subpath selection (non-interactive)
    if args.recursive and args.select:
        remote_path = f"{remote_path.rstrip('/')}/{args.select.lstrip('/')}"

    mount_point.mkdir(parents=True, exist_ok=True)
    command = _build_sshfs_command(args.target, remote_path, mount_point)

    # Execute or dry-run the mount
    if args.mount:
        rc = _execute_mount(command, mount_point, log_file)
        if rc != 0:
            return rc
        print(f"[INFO] Successfully mounted {args.target}:{remote_path} at {mount_point}")
    else:
        print("Dry-run mount command:")
        print(" ".join(shlex.quote(part) for part in command))

    # Interactive selection for recursive mode (after mount is up)
    selected_dirs: list[str] = []
    if args.recursive and not args.select and args.mount:
        selected_dirs = _interactive_select(mount_point)
        if not selected_dirs:
            print("[ERROR] No directories selected, aborting", file=sys.stderr)
            _execute_unmount(mount_point, log_file)
            return 1
        print(f"[INFO] Selected {len(selected_dirs)} directories for ingestion")

    # Generate paths config
    paths_config = _generate_paths_config(
        body_root, mount_point, args.target, remote_path, mode_name, selected_dirs,
    )

    # Save state
    payload = {
        "timestamp": _utc_now(),
        "mode": mode_name,
        "target": args.target,
        "remote_path": remote_path,
        "mount_point": str(mount_point),
        "command": command,
        "executed": bool(args.mount),
        "selected_dirs": selected_dirs,
        "paths_config": str(paths_config),
    }
    _safe_write_json(state_file, payload)
    _append_log(log_file, "INFO", f"Configured remote ingest: target={args.target} mode={mode_name}")

    # Summary
    print("")
    print("========================================")
    print("  Mount Ready")
    print("========================================")
    print("")
    print("  Remote filesystem mounted at:")
    print(f"    {mount_point}")
    print("")
    print("  Paths config generated at:")
    print(f"    {paths_config}")
    print("")
    if selected_dirs:
        print("  Selected directories:")
        for d in selected_dirs:
            print(f"    - {d}")
        print("")
    print("  To list mounted contents:")
    print(f"    ls -la {mount_point}")
    print("")
    print("  To unmount when done:")
    print("    ./layer1/scripts/remote-ingest.py --unmount")
    print("")
    print("  Claude will orchestrate ingestion using:")
    print("    .bra/paths-remote.md")
    print("")

    if not args.mount:
        print(f"State file written: {state_file}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
