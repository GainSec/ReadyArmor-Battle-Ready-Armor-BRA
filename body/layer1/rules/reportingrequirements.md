# Reporting Requirements (Pentest / Red-Team)

## Finding Record (required fields)
- ID: unique finding identifier (FINDING-XXX)
- Title
- Affected artifact: path | filename | module | URL | endpoint
- Artifact location: original location (URL or device path) and local copy path if available
- Artifact hash: SHA256 of the affected artifact or binary
- Description: concise (1–3 lines)
- Impact: 2–4 lines; lead with maximum potential impact. Then state the actual impact observed here
- Attack vector: 1–3 lines on how this would be exploited in the wild
- Vulnerable snippet: Up to 40 lines of output, response, or code that demonstrate the issue.
  Include the source path or URL and its hash.
- Reproduction steps: exact commands, environment variables, input files; include sandbox/host details
- Proof of Concept: inline commands for trivial cases, or file in `layer3-engagement/NOTES/reqs/` for complex PoCs; not weaponized
- Observed evidence: logs/stack traces/screenshots/pcaps; include timestamps, tool names/versions, and hashes of evidence files
- Severity: CVSSv3 vector + score (or chosen rubric)
- Likelihood: High/Med/Low with rationale
- Remediation: specific code/config changes
- Attack surface: category of affected component (e.g. "Web Service — Injection", "API — Authentication Bypass")
- Tools & versions: every tool used to collect evidence

## Finding Record (optional fields)
- CWE: weakness enumeration (when mapped)
- CVE: if assigned (post-disclosure)
- Status: Open / Confirmed / Fixed / Will Not Fix
- Notes: sandbox snapshot IDs, rollback/cleanup steps, HIGH-SENSITIVITY flags for secrets

## Disclosure payload mapping
  - `VENDOR-SUBMISSION.md`: full unredacted finding set (include sensitive details/secrets needed for remediation).
  - `CNA-SUBMISSION.md`: same as vendor, minus very sensitive data (secrets, credentials, identifying environment details); keep CVSS, CWE, hashes, and evidence descriptions.
  - `DISCLOSURE-PACKAGE.md`: Summary package from `layer2-templates/disclosure-package.md`.
    Include the overview, file index, vulnerability table, and product information.
    Add excluded vectors, confirmed findings, original evidence locations, local copies, and binary hashes.
    Include the disclosure timeline, next actions, and contact information.

## Placement & Storage (append-only)
- Findings list: `layer3-engagement/NOTES/FINDINGS.md`.
- PoCs and reproducer inputs: `layer3-engagement/NOTES/reqs/` (one file per finding).
- Harvested referenced files: `layer3-engagement/NOTES/reqs/reqfiles/` via ref harvester; keep `_refmap.csv` manifest.
- Leads (non-confirmed): `layer3-engagement/NOTES/LEADS.md`.
- Disclosure outputs:
  - `layer3-engagement/VENDOR-SUBMISSION.md`: full, unredacted (including secrets where required); template at `layer2-templates/vendor-submission.md`.
  - `layer3-engagement/CNA-SUBMISSION.md`: same content with very sensitive data redacted; template at `layer2-templates/cna-submission.md`.
  - `layer3-engagement/DISCLOSURE-PACKAGE.md`: summary/package; template at `layer2-templates/disclosure-package.md`.

## Evidence Handling & Chain of Custody
- Hash every evidence file (SHA256) and record alongside the finding.
- Timestamps and tool versions are mandatory for every evidence item.
- Put secrets required for remediation only in `VENDOR-SUBMISSION.md`.
- Remove secrets and credentials from other reports.
- Mark evidence that contains secrets as `HIGH-SENSITIVITY`.
- Calculate the hash of its container file.
 

## Negative Results & Coverage (optional; format when enabled)
- If the applicable policy or token requires negative results, include an execution matrix.
- Record the checks, inputs, duration, coverage reports, commands, and harnesses.
- Calculate output hashes.
- Connect each output to its record.

## Metadata per Engagement (for reports)
- Repeat the application, device, and version selectors in the final report.
- Include authorized addresses, hosts, user roles, and the assessment period.
- Describe the kill switch and ROE limits.
- Use the ROE and PLAN as the source requirements.
