# remote-ingest.py

## Purpose

The script prepares a read-only SSHFS connection to a remote filesystem.
It supports direct paths or interactive project selection.
It writes input paths, output paths, and crawl limits to `.bra/paths-remote.md`.
Run the commands below from `body/`.

The default mode shows the mount command without executing it.
Add `--mount` to execute the mount or unmount command.
For a custom unmount, supply the original target, remote path, and mount path as the three positional arguments.
Use `--select SUBPATH` for recursive selection without interaction.

## Location

`layer1/scripts/remote-ingest.py`

## Usage

```bash
python3 layer1/scripts/remote-ingest.py -d <user@host> <remote_path> [mount_point]  # Direct mode
python3 layer1/scripts/remote-ingest.py -r <user@host> <remote_path> [mount_point]  # Recursive/interactive mode
python3 layer1/scripts/remote-ingest.py --unmount --mount                     # Unmount
python3 layer1/scripts/remote-ingest.py --help                                      # Show help
```

## Dependencies

### Prerequisites

**macOS (Option A - FUSE-T, recommended):**
```bash
brew tap macos-fuse-t/homebrew-cask
brew install fuse-t
brew install fuse-t-sshfs
```

**macOS (Option B - macFUSE):**
```bash
brew install --cask macfuse
brew install gromgit/fuse/sshfs-mac
```
Complete the macFUSE installation steps required by the operating system.

**Linux:**
```bash
# Ubuntu/Debian
sudo apt install sshfs

# Fedora/RHEL
sudo dnf install fuse-sshfs

# Arch
sudo pacman -S sshfs
```

### Sources
Python standard library modules and the system SSHFS installation.

### Calls
Uses `ssh`, `sshfs`, and the platform unmount command.

### Called By
- Human operators mounting remote filesystems

### Environment Variables
| Variable | Purpose |
|----------|---------|
| `SSHFS_OPTS` | Additional sshfs options (e.g., `-p 2222` for custom port) |
| `SSH_IDENTITY_FILE` | Path to SSH private key (e.g., `~/.ssh/id_ed25519`) |
| `SSH_PASSWORD_AUTH` | Set to `true` to enable interactive password prompting |

### Output Files
| File | Purpose |
|------|---------|
| `.bra/paths-remote.md` | Generated paths configuration |
| `.mnt/remote-ingest/` | Default mount point (under the body root) |

## Functions

| Function | Purpose |
| --- | --- |
| `_utc_now()` | Return the current UTC timestamp. |
| `_find_body_root()` | Resolve the body root. |
| `_append_log()` | Append an operation log entry. |
| `_safe_write_json()` | Write JSON through a temporary file. |
| `_resolve_mount_point()` | Resolve the local mount path. |
| `_is_macos()` | Identify the macOS platform. |
| `_print_install_instructions()` | Print platform-specific sshfs install instructions. |
| `_check_sshfs_installed()` | Check if sshfs is installed. Print install instructions if not. |
| `_check_ssh_access()` | Verify SSH access to target. Returns True if accessible or user confirms. |
| `_check_already_mounted()` | Check if mount point is already in use. |
| `_validate_identity_file()` | Validate SSH identity file if specified. Returns path or None. |
| `_build_sshfs_command()` | Build the read-only mount command. |
| `_unmount_command()` | Select the platform unmount command. |
| `_run_command()` | Execute a system command. |
| `_execute_mount()` | Execute or report mount results. |
| `_execute_unmount()` | Execute the unmount command. |
| `_list_directories()` | List immediate subdirectories, excluding hidden and common non-project directories. |
| `_interactive_select()` | Select directories from the mounted path. |
| `_generate_paths_config()` | Write ingest paths and crawl limits. |
| `_update_paths_config_status()` | Record the unmounted state. |
| `main()` | Parse options and control the operation. |

## Behavior

### Mount Modes

**Direct Mode (`-d`):**
- Mounts a specific project path
- No directory selection
- Uses mount point root for ingestion

**Recursive/Interactive Mode (`-r`):**
- Mounts parent directory
- Displays numbered directory list
- Allows selection of multiple projects
- Selection commands: numbers, ranges, `all`, `done`, `quit`

### SSHFS Options

The generated SSHFS command includes these default options:
| Option | Purpose |
|--------|---------|
| `-o ro` | Read-only mount |
| `-o reconnect` | Auto-reconnect on disconnect |
| `-o ServerAliveInterval=15` | Keep connection alive |
| `-o ServerAliveCountMax=3` | Retry 3 times before failing |
| `-o follow_symlinks` | Follow symlinks on remote |
| `-o cache=yes` | Enable caching for performance |
| `-o auto_cache` | Invalidate cache on file change |

### Interactive Selection UI

```
========================================
  Select Directories to Ingest
========================================

Found 5 directories.
Enter numbers separated by commas (e.g., 1,3,5) or ranges (e.g., 1-5)
Commands: [a]ll, [n]one, [d]one, [q]uit

----------------------------------------
     1) project-alpha
     2) project-beta
  *  3) project-gamma
  *  4) project-delta
     5) firmware-repo
----------------------------------------
  Selected: 2 of 5

Enter choice:
```

Selection input:
- Single number: `3` (toggle)
- Multiple: `1,3,5`
- Range: `1-3` (select all in range)
- `a` or `all`: Select all
- `n` or `none`: Deselect all
- `d` or `done`: Finish selection
- `q` or `quit`: Cancel

### Paths Configuration

Generated `.bra/paths-remote.md`:

```markdown
# Remote Ingest Paths (Auto-Generated)

> **Remote Host:** ralph@server
> **Remote Path:** /home/ralph/projects
> **Mount Point:** /Users/local/.mnt/remote-ingest
> **Mode:** recursive
> **Generated:** 2026-01-24T12:00:00Z
> **Status:** ACTIVE (mount in progress)

## Ingest Inputs (READONLY)

Root: /Users/local/.mnt/remote-ingest/

### Selected Paths
- /Users/local/.mnt/remote-ingest/project-gamma/
- /Users/local/.mnt/remote-ingest/project-delta/

## Ingest Outputs (WRITE ALLOWED)

Root: layer3-engagement/ingest/

## Crawl Constraints
- do_not_traverse_outside_mount: true
- do_not_follow_symlinks_outside_mount: true
- never_write_to_mount: true

## Default Excluded Subtrees
- node_modules
- venv
- .git
- dist
- build
- rootfs
- squashfs-root
- filesystem
- firmware
- extracted
- __pycache__
- .venv
- target

## Usage

To ingest from this remote mount, use the standard ingestion workflow
with paths from this config file.

To unmount when done:
umount /Users/local/.mnt/remote-ingest

Or run the cleanup command:
python3 layer1/scripts/remote-ingest.py --unmount --mount ralph@server /home/ralph/projects /Users/local/.mnt/remote-ingest
```

### Unmount Handling

```bash
python3 layer1/scripts/remote-ingest.py --unmount --mount
```

1. Check the selected mount path.
2. Execute the platform unmount command when `--mount` is present.
3. Update the ingest state and paths configuration after successful completion.

### Platform Differences

| Operation | macOS | Linux |
|-----------|-------|-------|
| Unmount | `umount` / `diskutil unmount` | `fusermount -u` |
| Force unmount | `umount -f` | `fusermount -uz` / `umount -l` |
| File size | `stat -f%z` | `stat -c%s` |

## Token Interactions

| Token | Effect on remote-ingest.py |
|-------|---------------------------|
| None | remote-ingest.py does not use tokens |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success — Mount created or unmount completed |
| 1 | Error — Prerequisites missing, mount failed, selection cancelled |

## Examples

```bash
# Direct mode: mount a specific project
python3 layer1/scripts/remote-ingest.py -d ralph@server /home/ralph/myproject

# Recursive mode: browse and select from multiple projects
python3 layer1/scripts/remote-ingest.py -r ralph@server /home/ralph/projects

# With custom mount point
python3 layer1/scripts/remote-ingest.py -d user@host /opt/project /mnt/myproject

# With explicit identity file
SSH_IDENTITY_FILE=~/.ssh/lab_key python3 layer1/scripts/remote-ingest.py -r user@host /data

# With password authentication
SSH_PASSWORD_AUTH=true python3 layer1/scripts/remote-ingest.py -d user@host /data/project

# Custom SSH port
SSHFS_OPTS="-p 2222" python3 layer1/scripts/remote-ingest.py -d user@host /data

# Unmount
python3 layer1/scripts/remote-ingest.py --unmount --mount

# List mounted contents after mounting
ls -la .mnt/remote-ingest
```

## Flow Position

```
┌─────────────────────────────────────────────────────────────────┐
│                   Remote Ingestion Workflow                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Remote System                     Local System                  │
│  ─────────────                     ────────────                  │
│                                                                  │
│  ┌────────────────┐                                             │
│  │ Remote Host    │                                             │
│  │                │                                             │
│  │ /home/projects/│                                             │
│  │ ├── alpha/     │                                             │
│  │ ├── beta/      │                                             │
│  │ └── gamma/     │                                             │
│  └───────┬────────┘                                             │
│          │                                                       │
│          │ SSH + SSHFS                                          │
│          │                                                       │
│          ▼                                                       │
│  ┌─────────────────────┐    ┌─────────────────────┐            │
│  │  remote-ingest.py   │───▶│ .mnt/remote-ingest/ │            │
│  │  -r user@host       │    │ (read-only mount)   │            │
│  │  /home/projects     │    └──────────┬──────────┘            │
│  └─────────────────────┘               │                        │
│          │                             │                        │
│          │                             ▼                        │
│          │              ┌─────────────────────────┐            │
│          │              │ Interactive Selection   │            │
│          │              │                         │            │
│          │              │ Select: alpha, gamma    │            │
│          │              └─────────────┬───────────┘            │
│          │                            │                         │
│          ▼                            ▼                         │
│  ┌─────────────────────┐    ┌─────────────────────┐            │
│  │ .bra/paths-       │    │ Ingestion Workflow  │            │
│  │ remote.md           │───▶│ (uses paths config) │            │
│  │                     │    │                     │            │
│  │ Inputs: alpha,gamma │    │ Reads from mount    │            │
│  │ Outputs: layer3-engagement/ingest│    │ Writes to local     │            │
│  │ Constraints: ...    │    │                     │            │
│  └─────────────────────┘    └──────────┬──────────┘            │
│                                        │                        │
│                                        ▼                        │
│                              ┌─────────────────────┐            │
│                              │ layer3-engagement/ingest/        │            │
│                              │ (analysis output)   │            │
│                              └─────────────────────┘            │
│                                                                  │
│  Cleanup:                                                       │
│  ────────                                                       │
│                                                                  │
│  ┌─────────────────────┐    ┌─────────────────────┐            │
│  │ remote-ingest.py    │───▶│ Mount removed       │            │
│  │ --unmount           │    │ Status: UNMOUNTED   │            │
│  └─────────────────────┘    └─────────────────────┘            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Related

- Readiness script: `layer1/scripts/precheck.py`
- Ingestion script: `layer1/scripts/ingest.py`
- Runtime paths: `.bra/paths-remote.md`
