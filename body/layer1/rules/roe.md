# Rules of Engagement (ROE) — Pentest / Red-Team

> **Version:** 1.0.0
> **Last Updated:** 2026-11-17
> **Layer:** Root Guide (Layer 1)

> These rules define engagement permissions. Read them with `CLAUDE.md`.
> Read `layer3-engagement/SCOPE.md` for targets and limits.
> Read `layer3-engagement/TOOLSUITES.md` and `layer3-engagement/SKILLSUITES.md` for tool and skill limits.
> Use `reportingrequirements.md` for report and evidence requirements.

## Authorization
- Obtain authorization confirmation during scope intake.
- Record an affirmative answer as authorization to operate within the agreed scope.
- Record all active tokens. Include `NEGATIVE-RESULTS`, `ARTIFACTS`, `DESTRUCTIVE-APPROVAL`, `ACTIVE-TESTING-APPROVAL`, `SYSTEM-INSTALL-APPROVAL`, and `IGNORE-BACKUP` when applicable.
- Obey in-scope targets and out-of-scope exclusions from `layer3-engagement/SCOPE.md`.

## Push/Publish
- Apply allow/deny policy (governance doc) for local staging.
- `layer3-engagement/NOTES/` and reporting outputs are append-only; any override requires explicit approval/token.

## Safety & Destructive Actions
- Destructive actions on project files (git, file deletion) require DESTRUCTIVE-APPROVAL token.
- Obtain `ACTIVE-TESTING-APPROVAL` before active network assessment.
- This includes port scans, fuzzing of live targets, and exploitation.
- Record the scope intake mode as `YES`, `NO`, or `ASK`.
- Obey the kill switch: `STOP-TEST` is the immediate stop instruction.
- Runtime stop checks read `BRA_STOP=1`, `.bra/STOP`, and the STOP marker in `CLAUDE.md`.

## Follow-on References
- Scope, auth, network, data rules: `layer3-engagement/SCOPE.md`.
- Tool and skill constraints: `layer3-engagement/TOOLSUITES.md`, `layer3-engagement/SKILLSUITES.md`.
- Reporting/evidence rules: `reportingrequirements.md` and disclosure templates.
