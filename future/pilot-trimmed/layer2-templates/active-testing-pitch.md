# Active Testing Approval Request


**Generated:** {{TIMESTAMP}}
**Engagement:** {{ENGAGEMENT_NAME}}
**Status:** PENDING APPROVAL

Use this form to request active network assessment approval. Record the activity, target, risks, and scope before approval.

---

## Activity Requested

**Type:** {{ACTIVITY_TYPE}}
**Description:** {{ACTIVITY_DESCRIPTION}}
**Target:** {{TARGET_IDENTIFIER}}

### Activity Categories

| Category | Examples | Token Required |
|----------|----------|----------------|
| Port Scanning | nmap, masscan, rustscan | ACTIVE-TESTING-APPROVAL |
| Network Fuzzing | wfuzz against live targets, ffuf, gobuster | ACTIVE-TESTING-APPROVAL |
| Exploitation | Metasploit, sqlmap against live targets | ACTIVE-TESTING-APPROVAL |
| Static Analysis | ghidra, radare2, semgrep, binwalk | None (always allowed) |
| Local Testing | localhost/127.0.0.1 targets | None (always allowed) |

---

## Risk Assessment

| Factor | Assessment | Details |
|--------|------------|---------|
| Target Impact | {{IMPACT_LEVEL}} | {{IMPACT_DETAILS}} |
| Reversibility | {{REVERSIBILITY}} | {{REVERSIBILITY_DETAILS}} |
| Detection Risk | {{DETECTION_RISK}} | {{DETECTION_DETAILS}} |
| Data Loss Risk | {{DATA_LOSS_RISK}} | {{DATA_LOSS_DETAILS}} |

### Impact Levels

| Level | Definition |
|-------|------------|
| LOW | Minimal or no observable effect on target |
| MEDIUM | Temporary disruption, fully recoverable |
| HIGH | Extended disruption, may require intervention |
| CRITICAL | Potential permanent damage or data loss |

---

## Justification

{{JUSTIFICATION}}

### Required Justification Elements

- [ ] Why is this activity necessary for the engagement objectives?
- [ ] What security findings does this activity aim to discover?
- [ ] Have static/local alternatives been considered and ruled out?
- [ ] What is the expected outcome if successful?

---

## Scope Verification

- [ ] Activity is within authorized scope (SCOPE.md)
- [ ] Target is in-scope (PLAN.md)
- [ ] Time window is valid (ROE.md)
- [ ] Required tools are approved (TOOLSUITES.md)
- [ ] No conflicting exclusions exist

### Scope Reference

| Document | Section | Status |
|----------|---------|--------|
| SCOPE.md | Targets | {{SCOPE_STATUS}} |
| PLAN.md | In-Scope | {{PLAN_STATUS}} |
| ROE.md | Time Window | {{ROE_STATUS}} |
| TOOLSUITES.md | Allowed Tools | {{TOOLS_STATUS}} |

---

## Preconditions

| Requirement | Status | Notes |
|-------------|--------|-------|
| Backup created | {{BACKUP_STATUS}} | {{BACKUP_NOTES}} |
| Rollback plan defined | {{ROLLBACK_STATUS}} | {{ROLLBACK_NOTES}} |
| Emergency contacts available | {{CONTACTS_STATUS}} | {{CONTACTS_NOTES}} |
| Logging enabled | {{LOGGING_STATUS}} | {{LOGGING_NOTES}} |

---

## Approval

| Decision | Approver | Date | Notes |
|----------|----------|------|-------|
| PENDING | | | |

### To Approve

```bash
# Option 1: Create approval marker
touch .bra/approvals/ACTIVE-TESTING-APPROVAL

# Option 2: Set environment variable
export ACTIVE_TESTING_APPROVAL=1

# Option 3: Update ROE.md token table to "Set"
```

### To Deny

Set the status to `DENIED`. Record the reason in this document.

---

## Post-Approval

After approval:

1. Confirm the applicable token state.
2. Keep network assessment work within scope.
3. Record activity through the enabled `WATCH` and `TRACK` controls.
4. Document findings in `layer3-engagement/NOTES/FINDINGS.md`.

---

## Notes

{{ADDITIONAL_NOTES}}

---

## Template Usage

Run the request command from `body/`:

```bash
# Request approval for port scanning
python3 layer1/scripts/offensive_gate.py --request "port-scanning" "192.0.2.0/24" \
    --description "Network enumeration for service discovery"

# Request approval for fuzzing
python3 layer1/scripts/offensive_gate.py --request "fuzzing" "api.example.com" \
    --description "HTTP parameter fuzzing for injection vulnerabilities"
```

The script writes a timestamped pitch under `layer3-engagement/pitches/`. The operator reviews the request before permission is granted.
