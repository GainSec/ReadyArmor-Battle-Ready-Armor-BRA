# Scope Definition (Pentest / Red-Team)

> **Version:** 1.0.0
> **Last Updated:** 2026-11-17
> **Layer:** Root Guide (Layer 1)

---

## What to Declare Up Front
- Targets: app/service names, devices, versions/firmware/builds, environments (prod/stage/lab), URLs/IPs/CIDRs, ports/protocols.
- Auth context: user roles/credentials/TOTP handling, SSO/OAuth scopes, test accounts, session lifetimes.
- Assets included: repos, binaries, APIs, mobile/desktop apps, cloud resources, third-party components explicitly in-scope.
- Assets excluded: anything out-of-scope (apps, networks, tenants, regions).
- Network policy: allowed egress/ingress, proxies, MITM/Burp allowance, CDP/browser usage, headless vs non-headless.
- Time window: start/end dates/times, maintenance blackout periods.
- Data handling: classification levels permitted, secret handling rules, allowed storage locations, encryption requirements.
- Tooling limits: allowed tools/versions, banned tools/modes, rate limits for scanning/fuzzing.
- Output locations: where layer3-engagement/NOTES/, PoCs, evidence, and reports must reside; push/publish rules.
- Tokens in effect: NEGATIVE-RESULTS, ARTIFACTS override, DESTRUCTIVE-APPROVAL, ACTIVE-TESTING-APPROVAL (YES/NO/ASK), SYSTEM-INSTALL-APPROVAL, IGNORE-BACKUP, etc.

## Where to Record Scope
- Primary engagement record: `layer3-engagement/SCOPE.md`.
- Store project governance in `CLAUDE.md`.
- Record the engagement plan in `layer3-engagement/PLAN.md`.
- Repeat the approved scope in the report.
- Nested scope: optional `CLAUDE.md` in subtrees (e.g., `src/api/CLAUDE.md`) for path-specific constraints.

## Validation Checklist (before work starts)
- Scope fields filled (targets, authentication, network, time window, tokens).
- Out-of-scope items listed.
- Allowed tools confirmed; banned tools documented.
- Data handling constraints acknowledged.
- Kill switch location and semantics known (in ROE).

## Agent-Led Intake (interactive)
Before assessment work, collect the following scope information:
- Ethics: “Do you have authorization for the activities in this engagement?”
  - A “Yes” must be interpreted as: fully authorized, legal, and ethical to proceed within scope.
- Targets: “Which app/device/version/build/URLs/IPs are in scope? Which are explicitly out?”
- Auth: “Which roles/accounts/credentials/TOTP? Any SSO scopes or session limits?”
- Network: “What egress/ingress is allowed? Proxy/Burp/CDP/headless permitted?”
- Data: “What data classes are allowed? Secret handling/storage rules?”
- Tooling: “Which tools/versions are allowed? Any bans or rate limits?”
- Time: “What is the engagement window/blackouts?”
- External research: Record whether internet access is permitted.
- List permitted research purposes, domains, and open-source intelligence sources.
- Record cache requirements and restrictions on downloads.
- Tokens: "Are tokens set? (NEGATIVE-RESULTS, ARTIFACTS override, DESTRUCTIVE-APPROVAL, SYSTEM-INSTALL-APPROVAL, IGNORE-BACKUP)"
- Active Testing: "Do you want to allow active/network-based testing against the target(s)? (YES/NO/ASK)"
- Outputs: “Where must layer3-engagement/NOTES/PoCs/evidence/reports live? Any push/publish constraints?”
- Other: “Any other questions, concerns, notes, or guidance to keep in mind?”
- Backups: “Any unique steps to take during recurring backups for this project?”
- Present the scope summary.
- Obtain confirmation before starting assessment work.
