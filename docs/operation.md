# Operation

## Prepare an engagement

1. Start the [web interface](installation.md).
2. Open the scope form.
3. Record the target type.
4. Enter the permitted targets and excluded targets.
5. Record the assessment period.
6. Specify network access and data handling rules.
7. Select permitted tools and methods.
8. Select the active assessment mode.
9. Confirm the scope.
10. Examine the readiness report.

`body/layer2-templates/scope-intake.md` defines the intake fields.
The intake process writes the engagement scope and related records under `body/layer3-engagement/`.

## Active assessment modes

| Mode | Operation |
| --- | --- |
| `YES` | Permit approved network activity within scope. |
| `NO` | Restrict work to static analysis and local environments. |
| `ASK` | Request approval before network activity. |

Tool approval and target approval are separate controls. A tool approval does not add a target to scope.

## Work phases

BRA uses intelligence, static analysis, dynamic analysis, and report preparation phases.
The selected method supplies phase instructions. Available tools and current evidence supply additional context.

1. Start the engagement from the interface.
2. Examine each approval request.
3. Check the command, target, and requested permission.
4. Approve or deny the request.
5. Examine new findings and their evidence.
6. Resolve requests for missing scope information.
7. Review the phase results before continuing.

Use a masked target exactly as recorded in scope. BRA resolves its alias when it executes an approved command.

## Review records

| Record | Function |
| --- | --- |
| `SCOPE.md` | Targets, assessment type, and access limits |
| `ROE.md` | Rules of engagement and token decisions |
| `PLAN.md` | Phase plan |
| `NOTES/INTEL.md` | Intelligence records |
| `NOTES/LEADS.md` | Items that require investigation |
| `NOTES/FINDINGS.md` | Validated finding records |
| `REPORT.md` | Assessment report |
| `REVIEW.md` | Review results |
| `RETRO.md` | Assessment retrospective |

These records are stored under `body/layer3-engagement/`.
Raw tool output is stored under `body/.bra/artifacts/raw/`.

## Prepare a report

1. Examine each finding for complete evidence.
2. Check its affected target and reproduction steps.
3. Check its impact and remediation.
4. Review `REPORT.md` against the finding records.
5. Convert aliases with the [privacy procedure](privacy.md) when the final report requires real values.
6. Review the final output.

The templates also support vendor submissions, disclosure packages, and CVE Numbering Authority submissions.

## Command utilities

Run these commands in an environment with the `head` package installed.

| Command | Function |
| --- | --- |
| `bra status` | Show engagement status. |
| `bra precheck` | Check engagement readiness. |
| `bra scope` | Start the scope intake command. |
| `bra tokens list` | Show active approval tokens. |
| `bra stats` | Show engagement statistics. |
| `bra audit` | Examine the audit record. |
| `bra --help` | Show available commands. |

For backup and reset procedures, examine `bra backup --help` and `bra reset --help` before operation.
