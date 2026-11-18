# Token Policy (Pentest / Red-Team)

> **Version:** 1.0.0
> **Last Updated:** 2026-11-17
> **Layer:** Root Guide (Layer 1)

> Record token states during scope intake. Keep the ROE and project overview consistent.
> Tokens are unset by default.

## Tokens (one-line effects)
- `NEGATIVE-RESULTS`: Log negative coverage (execution matrix, commands, hashed outputs); unset = skip.
- `ARTIFACTS` override: Temporarily lift artifact deny globs; use sparingly and log.
- `DESTRUCTIVE-APPROVAL`: Permit destructive/state-altering actions on project files; unset = dry-run/skip destructive.
- `ACTIVE-TESTING-APPROVAL`: Permit active network assessment and local model fallback for authorized offensive code generation.
  Scope intake modes are `YES`, `NO`, and `ASK`.
- `SYSTEM-INSTALL-APPROVAL`: Permit system-wide package installations (sudo apt/yum/pip install); user-space installs allowed with warning.
- `IGNORE-BACKUP`: Disable all backups/backup processes.
- `WATCH`: Log all operations to `.bra/logs/watch.log` in human-readable format; unset = no watch logging.
- `TRACK`: Detailed audit record to `.bra/logs/track.log` with raw output and reasoning for each action; unset = no tracking.
- `LAYER2-WRITE-APPROVAL`: Permit changes to the template paths listed in the token file.
  `layer1/lib/promotion.py` creates this token for promotion work. Its context manager removes the token when the work finishes.
- `FRAMEWORK-DEV-APPROVAL`: Permit editing framework files (`layer1/scripts/`, `layer1/lib/`, `.claude/`, etc.); for development/maintenance, not engagement operations; paths listed in token file.
- `OVERRIDE-APPROVAL`: Permit creating, removing, and clearing override rules in `.bra/overrides.json`; required for all override mutations through the operator interface and commands.
- `SCAN-<TYPE>-APPROVAL`: Permit the specified aggressive scan class.
  Types are `FULL-PORT`, `MASSCAN`, `AGGRESSIVE`, `NC-SCAN`, and `ALL`.
  Obtain the approval through the operator workflow. Scan approvals can expire.
- `FINDINGS-FASTPATH`: Deterministic findings preflight/materialization path that can dequeue complete findings without subagent retries.
- `SLOWPATH-FINDINGS`: Script-first findings path that keeps system-managed sections/hashes deterministic while requiring subagent-authored narrative sections.

## Token sources

The token resolver checks these sources in order:

1. The environment variable with token hyphens replaced by underscores.
2. The marker file under `.bra/approvals/`.
3. The matching status in `layer3-engagement/ROE.md`.

Read `layer1/lib/tokens.py` for accepted values and token resolution.

## Kill Switch (command)
- `STOP-TEST`: Stop work immediately, regardless of active tokens.
- Runtime checks read `BRA_STOP=1`, `.bra/STOP`, and the fenced STOP marker in `CLAUDE.md`.
