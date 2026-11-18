# Claude Code Project Configuration

> **CRITICAL:** Read this file and all linked documents before taking any action.

## Required Reading

Before any project operation, read these documents:

1. **This file (CLAUDE.md)** - Central governance hub with:
   - Kill switch status (check first -- see ## Kill Switch above)
   - Enforcement model and hook configuration
   - Approval token requirements
   - Target scope validation
   - Finding enforcement

2. **[ROE.md](layer1/rules/roe.md)** - Rules of engagement

3. **[scope.md](layer1/rules/scope.md)** - Scope definition template

## Kill Switch

```
CLEAR
```

**Status:** Operations are permitted. Obey all governance controls.

> Hooks check the kill switch before operations.
> To stop agent activity, change `CLEAR` to `STOP` in the code block above.

## Enforcement Model

This project uses a layered governance model with **Claude Code hooks** for automatic enforcement.

### Mechanically Enforced Controls

The SDK hook registry connects these controls to tool operations. Denied operations stop at the applicable policy check.

| Control | Enforcement | Hook/Script | Exit Code |
|---------|-------------|-------------|-----------|
| Kill Switch | Checked on every Bash command | `bash-guard.py` → `killswitch.py` | 99 |
| Token Validation | `require_token()` | `tokens.py` | 1 |
| layer3-engagement/NOTES/ Protection | Append-only enforcement | `file-guard.py` → `notes_guard.py` | 1 |
| Reporting Outputs Protection | Append-only (ROE:16) | `file-guard.py` + `file_hook.py` | Block |
| layer3-engagement/ Allowlist | Known files/dirs only | `file-guard.py` + `file_hook.py` | Block |
| .bra/ Schema Enforcement | Schema-enforced sub-path access control | `file-guard.py` + `file_hook.py` + `filesystem.py` | Block |
| Dangerous Commands | Blocks without approval | `bash-guard.py` → `danger_check.py` | 1 |
| Governance Reminder | Periodic reminder (15 min) | `governance-reminder.py` | N/A |

### Hooks Configuration

`head/bra/hooks/registry.py` registers the SDK hooks. The adapters call the body policy scripts:

- **PreToolUse (Bash):** `bash-guard.py` - Kill switch, active testing check, danger check
- **PreToolUse (Write/Edit):** `file-guard.py` - NOTES/ append-only, reporting outputs append-only, layer3-engagement/ allowlist, template immutability
- **PreToolUse (*):** `governance-reminder.py` - Periodic governance context refresh
- **PostToolUse (*):** `track-post.py` - Audit trail logging

### Advisory (Expected Behavior)

These are documented expectations that rely on agent compliance:

| Expectation | Documentation |
|-------------|---------------|
| Read CLAUDE.md on session start | This file (CLAUDE.md) |
| Use `/agentic` for engagement operations | Session Lifecycle (layer1/scripts/agentic-handler.py) |
| Request approval before dangerous ops | Enforcement Model (this file) |
| Preserve evidence integrity | layer3-engagement/NOTES/ rules (this file) |

### Approval Tokens

| Token | Required For | Source |
|-------|--------------|--------|
| `DESTRUCTIVE-APPROVAL` | File/git destructive operations on project | Human operator |
| `PUSH-APPROVAL` | Git push operations | Human operator |
| `ACTIVE-TESTING-APPROVAL` | Active network testing (scans, exploitation) | Human operator |
| `LAYER2-WRITE-APPROVAL` | Modifications to layer2-templates/ | Human operator |
| `FRAMEWORK-DEV-APPROVAL` | Modifications to framework files (layer1/) | Human operator |
| `OVERRIDE-APPROVAL` | Creating, removing, enabling, disabling override rules | Human operator |

### Governance Enforcement

The hook system applies these controls:
- **bash-guard.py** runs danger_check.py before every Bash command
- **file-guard.py** enforces layer3-engagement/NOTES/ append-only on every Write/Edit
- **governance-reminder.py** prevents context drift during long sessions

### File Governance — layer3-engagement/ Rules

**Append-only files** (content can only grow, never shrink — ROE:16):
- `NOTES/*` — all evidence files (FINDINGS.md, LEADS.md, INTEL.md, SESSION.md, etc.)
- `REPORT.md` — engagement report
- `CNA-SUBMISSION.md` — CNA submission
- `DISCLOSURE-PACKAGE.md` — disclosure package
- `VENDOR-SUBMISSION.md` — vendor submission
- `IMPROVEMENTS.md` — improvement log
- `OVERRIDES.md` — override audit trail

**Writable root files** (only these are permitted at the layer3-engagement/ root):
- SCOPE.md (locked after scope intake — SCOPE-CONFIRMED token; managed by governance scripts after intake), ROE.md, PLAN.md, REVIEW.md, RETRO.md
- README-PROJECTOVERVIEW.md, BACKUPS.md, TOOLSUITES.md, SKILLSUITES.md
- STATS.md, LESSONS-LEARNED.md, SCRIPTS-AUDIT-REPORT.md, README.md, OVERRIDES.md
- Plus the append-only files listed above

**Writable subdirectories** (anything underneath is allowed):
- `NOTES/` — structured evidence records only (append-only enforced). NOT for command output.
- `disclosure/` — disclosure staging
- `pitches/` — proposal documents
- `ingest/` — data ingestion staging

### File Governance — .bra/ Rules

The `.bra/` directory is governed by a canonical schema (`head/bra/core/bra_schema.py`).
The schema declares valid paths, access levels, and managing components.
Enforcement is mechanical across three layers: `filesystem.py`, `file_hook.py`, and `file-guard.py`.

| Path | Access Level | Manager |
|------|-------------|---------|
| `artifacts/` | Agent-writable | Agent + scripts |
| `logs/` | Append-only | Hooks and scripts |
| `approvals/` | Operator-only | Operator approval workflow |
| `one-time-approvals/` | Operator-only | `approval.py` (auto-consumed) |
| `pipeline_state.json` | System-only | `pipeline_state.py` |
| `engagement_meta.json` | System-only | Head Python code |
| `approved_targets.json` | System-only | `approve-target.py` |
| `PRECHECK_REPORT.md` | System-only | `precheck.py` |
| `phase_context.md` | System-only | `phase_invoker.py` |
| `last_capture.json` | System-only | `post_hook.py` (transient) |
| `service_state.json` | System-only | Service state tracking |
| `web-config.json` | System-only | Web GUI configuration |
| `phase_state/` | System-only | `pipeline_state.py` |
| `specs/` | System-only | Reserved |
| `overrides.json` | Operator-only | Operator override workflow |
| `ui/` | System-only | TUI profile/UI configuration |

**Strict allowlist:** Use only `.bra/` paths declared in the schema. Policy adapters block agent writes to undeclared paths.
`precheck.py` compares the directory with the schema and reports undeclared files.

**Access levels:**

- **Agent-writable** — Agent Write/Edit tools + system code. No restriction.
- **Append-only** — System code only. Content can only grow (byte-size enforced). Agent blocked.
- **Operator-only** — Operator approval workflow. Direct agent changes are blocked.
- **System-only** — Governance scripts and head Python code. Agent blocked.

**Do NOT create:**
- A `findings/` directory — finding records belong in `NOTES/FINDINGS.md`
- Any file or directory not in the schema — the guards will block it
- Ad-hoc report files outside the governed structure
- **Any new directories:** `precheck.py` creates the required engagement directories. Do not use `mkdir` during agent work.

## Anonymization Layer

- Governed files store anonymized values. The agent never sees the real values directly.
- **`.bra/anon_map.json` is operator-only.** Agent and subagents MUST NOT read, write, or access this file.
- **Governed files (SCOPE.md, INTEL.md, FINDINGS.md, LEADS.md, REPORT.md) contain anonymized values.**
  Keep these word replacements unchanged.
- Chat masking is automatic. Operator messages may be masked before reaching the LLM, and responses may be unmasked before display.
- Treat anonymized target values already present in governed scope as valid command placeholders.
- Propose commands using the anonymized target value from scope instead of replacing it with placeholders like `<target-ip>`.
- Do not ask the operator for the actual IP or hostname solely because the governed target value is anonymized.
- **A masked target is a KNOWN target for the entire engagement, not just scope review.**
  Use its alias exactly in commands and scans, such as `nmap blanket` or `curl http://blanket/`.
  Do not discover an address that scope already supplies as an alias.
  Do not describe an alias target as missing, unknown, or without an address.
  The masking layer resolves its real value during execution.
- Scope intake flow: privacy posture gate -> scope form -> anonymization review -> launch.
- `.bra/.claude/` contains SDK scratch state.
  Agents may write SDK or cache output there.
  Do not read, search, or edit that state. It can contain unmasked tool output.

### Command Output — Where to Save Artifacts

**Use `.bra/artifacts/` as the artifact directory relative to `body/`.**
All governance scripts use this path.
Read `.bra/phase_context.md` for the existing subdirectory assigned to the current phase, such as `.bra/artifacts/intel_work/`.

**All command output files MUST go here:**

| Output Type | Save To | NOT To |
|-------------|---------|--------|
| Scan results (nmap, etc.) | `.bra/artifacts/` | ~~NOTES/~~, ~~layer3-engagement/~~ |
| Downloaded files | `.bra/artifacts/` | ~~any new directory~~ |
| Tool output files | `.bra/artifacts/` | ~~./output/~~, ~~./results/~~ |
| Decompiled code | `.bra/artifacts/` | ~~./decompiled/~~ |
| PoC scripts only | `NOTES/reqs/` | — |

**Common mistakes:**
- Saving to `layer3-engagement/artifacts/` — wrong, use `.bra/artifacts/`
- Saving to `NOTES/` — wrong, NOTES/ is for structured evidence records only (FINDINGS.md, INTEL.md, etc.)
- Use existing `.bra/artifacts/` subdirectories. The readiness process creates the required directories.
- Redirecting command output into NOTES/ files — wrong, NOTES/ is append-only evidence

## Target Scope Validation

For Bash network commands, `bash-guard.py` extracts the IP address, domain, or CIDR target.
It compares the target with `layer3-engagement/SCOPE.md` and `.bra/approved_targets.json`.

If a target is **not approved**, the command is blocked and you will receive a
`SCOPE_CHECK_REQUIRED` message with the target details.

If the operator requests an action against a target outside scope, do not change scope yourself.
Do not run `approve-target.py`.
Attempt the requested action normally. The guard stops it before execution. BRA will show the operator scope modal.

### Handling SCOPE_CHECK_REQUIRED

When you receive a `SCOPE_CHECK_REQUIRED` block, you **must**:

1. **Ask the user** whether the target is in scope, presenting these options:
   - A. **Fully in Scope** — all testing allowed
   - B. **Limited Scope** — passive only (download, ping, DNS)
   - C. **Not in Scope** — do not interact
   - D. **Custom** — specify what's allowed

2. **Do not run `approve-target.py`.** Agents can request a scope decision, but
   only BRA's operator approval system may approve, deny, or mutate scope.
   The scope modal is created by the guarded action that produced
   `SCOPE_CHECK_REQUIRED`.

3. **After BRA reports the target was added to scope**, retry the original
   command that was blocked.

After scope intake, `SCOPE-CONFIRMED` locks `SCOPE.md` against agent writes.
The approval system creates single-use `SCOPE-GRANT` tokens.
`approve-target.py` uses these tokens to record approved targets in the Network or Local scope section.

### CIDR Notation

**Preserve the exact CIDR notation from `SCOPE.md`.**
Do not change `192.0.2.1/24` to `192.0.2.0/24` without operator approval.
If a CIDR contains host bits, report them to the operator.
The operator can intentionally specify a host address.

### Scope Levels

| Level | Meaning |
|-------|---------|
| `FULL` | All testing allowed (active scanning, exploitation, fuzzing) |
| `LIMITED` | Passive only (download, ping, DNS lookups) |
| `NONE` | Do not interact with this target |
| `CUSTOM` | User-specified restrictions (document in approval) |

## Finding Enforcement

**You MUST emit a `[FINDING]` marker whenever you identify a security vulnerability.**
The marker format is:
`[FINDING] <SEVERITY>: <title> | cvss: <0.0-10.0> | attack_surface: <category> | capture_id: <tool_use_id>`

**Set `capture_id` to the actual `tool_use_id` of the Bash, Read, or WebFetch operation that produced the evidence.**
Use the identifier shown for that tool call, such as `toolu_01abc123...`.
Do not invent identifiers or use sequential finding numbers such as `F-001`.
The evidence system cannot connect invented identifiers to captured artifacts.

**Use the tool call that fetched the evidence.**
For example, nmap identifies a port and curl retrieves a vulnerable page.
Use the curl `tool_use_id` for the page finding.
Connect each finding to output that demonstrates the issue.
For findings from the same page retrieval, use that retrieval identifier.

Example:
`[FINDING] CRITICAL: Blind command injection in submition.cgi via filename parameter | cvss: 9.8 | attack_surface: Web Service - Injection | capture_id: toolu_01abc123xyz`

Severity must be one of `CRITICAL/HIGH/MEDIUM/LOW/INFO`, and both `cvss:` and `attack_surface:` are required.
Do not emit bare finding markers without explicit severity, CVSS, and attack surface.
`source:` is optional when `capture_id` is present and resolvable.
This is not optional — the marker triggers mechanical enforcement and queues
the finding for governed documentation in `layer3-engagement/NOTES/FINDINGS.md`.
By default, the findings subagent handles the full record. Emit the marker,
keep working, and do NOT narrate that you are now writing `FINDINGS.md`.
Write findings directly only when the runner announces `Findings handoff active`.

### What Gets Blocked

- All Bash commands
- All Write/Edit to files OTHER than NOTES/FINDINGS.md and NOTES/reqs/
- All web tools (WebSearch, WebFetch)
- Read/Glob/Grep remain available so you can read the schema and evidence

### What You Must Write

Write a complete record using the requirements in `head/bra/core/finding_enforcer.py`.
Include all these fields:

- ID
- Title
- Affected Artifact
- Artifact Location
- Artifact Hash (SHA256)
- Description
- Impact
- Attack Vector
- Vulnerable Snippet
- Reproduction Steps
- Proof of Concept, inline or saved to `NOTES/reqs/`
- Observed Evidence
- Severity (CVSS)
- Likelihood
- Remediation
- Attack Surface
- Tools & Versions

### "write up findings" Command

The instruction **"write up findings"** starts finding documentation mode.
The framework compares `INTEL.md` with `FINDINGS.md` and queues undocumented findings.
It applies finding restrictions until the records in `NOTES/FINDINGS.md` satisfy `head/bra/core/finding_enforcer.py`.

**This means:** the framework will queue undocumented findings for governed
documentation. Continue the assessment unless the runner explicitly announces
`Findings handoff active`. If handoff is active, then open `NOTES/FINDINGS.md`,
write a complete `## [FINDING-NNN]` record for each undocumented finding, with
ALL required sections. If you need clarification, ask the user.

**This does NOT mean:** Creating a summary document, writing an
`initial-recon-findings.md`, or producing any ad-hoc file anywhere else.

### Common Mistakes

- **Creating finding documents in `.bra/artifacts/`** — This is NOT documenting
  findings. The content guard will block it. Findings go in `NOTES/FINDINGS.md`.
- **Writing to `findings/` directory** — This directory should not exist. The
  allowlist will block it. Findings go in `NOTES/FINDINGS.md`.
- **Summarizing discoveries** — A summary is not a governed finding record.
  Each finding needs the full schema: ID, CVSS, CWE, artifact hash, PoC in
  `NOTES/reqs/`, evidence table, remediation, etc.
- **Confusing INTEL.md with FINDINGS.md** — INTEL.md is a summary table written
  mechanically by `IntelWriter`. FINDINGS.md is the full structured record
  written by you per `head/bra/core/finding_enforcer.py`. They serve different purposes and
  are not interchangeable.

### Multiple Findings

Findings are documented sequentially. If you emit multiple `[FINDING]` markers,
the governed documentation flow handles them sequentially. Do not stop to
narrate findings write-up unless `Findings handoff active` is explicitly shown.

## Tool Preferences

**Prefer built-in Claude Code tools first, then allowlisted Bash commands.**
Use built-in file and search tools for tasks that do not require Bash. The applicable file and tool controls still apply.

### Priority 1: Built-in Tools

| Task | Built-in Tool |
|------|--------------|
| Read file contents | `Read` |
| Search file names/paths | `Glob` |
| Search file contents | `Grep` |
| Fetch remote content | `WebFetch` |
| Write/create files | `Write` |
| Edit existing files | `Edit` |

These tools do not invoke the Bash guard. File tools still use file policy. Web tools retain their applicable approval checks.

### Priority 2: Allowlisted Bash Commands (auto-approved, no pipes)

| Task | Preferred Command | Avoid |
|------|------------------|-------|
| JSON parsing | `jq` | `curl \| python` (blocked: download-and-execute pattern) |
| YAML parsing | `yq` | `curl \| python` |
| Text extraction | `grep`, `awk`, `sed` | Piping downloads to interpreters |
| File inspection | `file`, `strings`, `xxd` | — |
| Checksums | `sha256sum`, `md5sum` | — |
| Encoding | `base64` | — |

### Download-then-parse pattern

To process remote data, first save the download. Then parse the saved file:
```bash
# CORRECT: save then parse (both steps are safe)
curl -s https://example.com/data.json -o .bra/artifacts/data.json
jq '.key' .bra/artifacts/data.json

# ALSO CORRECT: use built-in Read after downloading
curl -s https://example.com/data.json -o .bra/artifacts/data.json
# Then use Read tool to inspect the file — no Bash needed

# BLOCKED: pipe to interpreter (triggers danger_check)
curl -s https://example.com/data.json | python3 -c 'import json,sys...'
```

## Quick Reference

| Action | Correct Approach |
|--------|------------------|
| Start engagement | `./layer1/scripts/battlestations.py` |
| Launch agentic loop | `/agentic` command in Claude Code |
| Check project status | `./layer1/scripts/status.py` |
| Verify environment | `./layer1/scripts/precheck.py` |
| Validate findings | `/validate-findings` |
| Request offensive approval | `./layer1/scripts/offensive_gate.py --request <type> <target>` |

## Session Start Checklist

- [ ] Verify kill switch is CLEAR (see ## Kill Switch section above)
- [ ] Verify scope is defined (layer3-engagement/SCOPE.md)
- [ ] Check approval token status
- [ ] Run `./layer1/scripts/precheck.py` if environment uncertain
