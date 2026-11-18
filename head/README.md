# BRA Python runtime

Head supplies agent orchestration, tool hooks, privacy processing, evidence handling, and Python command utilities.
Boots uses this package to operate the engagement runtime.

## Install

Run this command from the repository root in an active virtual environment.

```bash
python -m pip install -e head
```

## Commands

```bash
bra --help
bra status
bra scope
bra tokens list
```

Use the [web interface](../boots/README.md) for the engagement workflow.

## Components

| Directory | Function |
| --- | --- |
| `bra/core/` | Agent runner, evidence, markers, and findings |
| `bra/hooks/` | SDK adapters for policy checks |
| `bra/anon/` | Detection, aliases, and report conversion |
| `bra/proxy/` | Local model proxy |
| `bra/config/` | Paths and runtime settings |

Read the [architecture](../docs/architecture.md) and [development guide](../docs/development.md) before changing shared components.
