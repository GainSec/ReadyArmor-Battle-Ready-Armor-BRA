# Governance

Governance defines the permitted operations for an engagement. Scope records, approval tokens, and policy scripts supply separate controls.

## Stop controls

The kill switch checks `BRA_STOP=1`, `body/.bra/STOP`, and the STOP marker in `body/CLAUDE.md`.

To stop an engagement, use the operator stop control. Confirm that the interface shows the stopped state before changing scope or permissions.

## Target controls

Scope records permitted work and exclusions for the operator and agent.
The native Bash guard extracts one recognized CIDR, IPv4 address, or domain from the original command.
It reads original targets, discovered target records, and boundary-matched literals from all scope text.
The literal matcher does not classify inclusion and exclusion sections.

Original targets and scope literals resolve `FULL` before discovered levels.
A discovered `LIMITED` result uses configured passive and active command patterns.
A literal synchronized into scope can take the earlier `FULL` branch.
`NONE` refuses interaction when it is the effective level.
`CUSTOM` passes the current operation predicate without parsing custom allowed-operation text.
Empty extraction skips the target check.
Alias substitution occurs later without a second target check.

Use the operator approval interface to change target permissions.
Keep commands within the recorded target and activity limits.

## Approval tokens

| Token | Permission |
| --- | --- |
| `ACTIVE-TESTING-APPROVAL` | Approved active network work |
| `DESTRUCTIVE-APPROVAL` | Approved destructive operations |
| `PUSH-APPROVAL` | Approved Git push operations |
| `LAYER2-WRITE-APPROVAL` | Approved template changes |
| `FRAMEWORK-DEV-APPROVAL` | Framework development permission where the policy permits it |
| `OVERRIDE-APPROVAL` | Approved override changes |
| `NO-TOKEN-TRACKING` | Disable SDK usage records |

Persistent tokens are stored under `.bra/approvals/` within the engagement root.
Invocation and scope-grant files use `.bra/one-time-approvals/`.
The allow-once retry also uses in-memory state with a 30-second expiry.
Capability token readers do not all inspect the same sources.
The Bash helper generally accepts environment variables and approval files.
The central token library additionally accepts matching ROE markers.
Script approvals persist by path until revoked or removed.
Read [Control in Depth](control-in-depth.md#tool-approval-has-explicit-defaults-and-lifetimes) for matching, exemptions, and lifetimes.

## File controls

| Location | SDK file-tool access |
| --- | --- |
| `layer1/` | Writes and edits are blocked during engagement. |
| `layer2-templates/` | Changes require the applicable approval. |
| `layer3-engagement/NOTES/` | Evidence records use append controls. |
| Engagement report outputs | Writes use append controls. |
| `.bra/artifacts/` | Permitted working artifacts |
| `.bra/artifacts/raw/` | Captured tool output |
| `.bra/.claude/` | SDK scratch writes; direct agent reading and editing are blocked. |
| `.bra/anon_map.json` | Direct agent access is blocked. |

The file guard applies these rules to SDK file requests.
Bash has separate command-text path checks; it does not apply every file-tool rule to shell activity.
The SDK wrapper retains the launching user's host permissions.

The file guard checks `Write` sizes for protected append records.
An `Edit` request does not provide a complete resulting file for that size check.
Review evidence integrity during report preparation.

The file guard restricts privacy-sensitive reads. The write schema does not impose equivalent read restrictions on every state file.
The Bash adapter allows the remaining SDK request when its Body guard or Python executable is absent.
Keep the governance scripts present in the installed product.

## Policy decisions

A denied operation includes a policy identifier and reason.
Use the reason to correct the target, output path, or approval request.
Do not move raw command output into `NOTES/` to bypass artifact controls.

The allowed engagement directories include `NOTES/`, `disclosure/`, `pitches/`, and `ingest/`.
`layer3-engagement/artifacts/` is not a permitted artifact destination.
