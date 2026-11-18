# VENDOR-SUBMISSION Template (Unredacted)


Use this form for the vendor report. Include sensitive details only when the vendor requires them for remediation.

## Engagement Context
- Scope: [app/device/version, authorized IPs/hosts]
- Auth context: [roles/creds used]
- Window: [dates/times]
- ROE: [key constraints, kill switch]

## Vulnerability Summary
| ID | Title | CVSS | CWE | Status (Proven/Exploit Ready) |
|----|-------|------|-----|--------------------------------|
|    |       |      |     |                                |

## Findings (one section per ID)
- Title
- Affected artifact
- Artifact location (original + local copy)
- Artifact hash
- Short description (1–3 lines)
- Impact (worst-case → actual, 2–4 lines)
- Attack vector (1–3 lines)
- Vulnerable snippet (≤40 lines, path/lines/hash)
- Reproduction steps (exact commands, env, host/sandbox)
- Proof of Concept (path in `layer3-engagement/NOTES/reqs/`)
- Observed evidence (with timestamps, tool versions, hashes)
- Severity (CVSS vector + score)
- Likelihood (H/M/L + rationale)
- Remediation (specific code/config change)
- Coverage evidence (what was exercised)
- Tools & versions
- Notes (sandbox snapshot IDs, cleanup/rollback, HIGH-SENSITIVITY items)

## Evidence Index
- Files with SHA256, timestamps, tool versions
- PoCs in `layer3-engagement/NOTES/reqs/`
- Referenced files in `layer3-engagement/NOTES/reqs/reqfiles/` with `_refmap.csv`

## Negative Results (include only if required)
- Execution matrix, commands/harnesses, hashed outputs

## Disclosure Package Pointers
- CNA submission (redacted)
- Disclosure package summary

## Timeline
- Discovery, analysis, documentation, vendor notify, CNA submission, public disclosure target

## Contacts
- Researcher name, email, PGP
