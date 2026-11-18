# Attack Chain Documentation Template

> **Template Version:** 1.0
> **Derived From:** Reusable assessment patterns
> **Purpose:** Document multi-stage attack sequences for security assessments

---

## Attack Chain Overview

An attack chain connects initial access to its final impact. Use this form to record each step and its evidence.

---

## Chain Metadata

| Field | Value |
|-------|-------|
| **Chain ID** | AC-YYYY-MM-DD-NNN |
| **Target** | [System/Application Name] |
| **Assessment Date** | YYYY-MM-DD |
| **Assessor** | [Name/Handle] |
| **Classification** | Internal / Client Confidential |
| **Severity** | Critical / High / Medium / Low |

---

## Executive Summary

[1-2 paragraph summary of the attack chain, including:
- Initial access method
- Key vulnerabilities exploited
- Ultimate impact achieved
- Recommended priority for remediation]

---

## Attack Chain Diagram

```
┌─────────────────┐
│ Initial Access  │  [Method used to gain first foothold]
│ [CVE/Vuln ID]   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Execution      │  [How code/commands were executed]
│ [Technique]     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Persistence    │  [How access was maintained]
│ [Method]        │  (optional)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Priv Escalation │  [How elevated privileges were obtained]
│ [CVE/Method]    │  (optional)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Defense Evasion │  [How detection was avoided]
│ [Technique]     │  (optional)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Objective     │  [Final impact achieved]
│ [Data/Access]   │
└─────────────────┘
```

---

## Detailed Steps

### Step 1: Initial Access

**MITRE ATT&CK:** [T-ID if applicable]

**Technique:** [e.g., Default Credentials, SQL Injection, Phishing]

**Target:** [Component targeted]

**Prerequisites:**
- [What's needed before this step]
- [Required access level]

**Execution:**
```bash
# Command or action taken
[actual commands/steps]
```

**Evidence:**
```
[Output, screenshot reference, or log excerpt]
```

**Result:** [What was achieved]

---

### Step 2: [Next Stage]

**MITRE ATT&CK:** [T-ID if applicable]

**Technique:** [Technique name]

**Prerequisites:**
- Successful completion of Step 1
- [Additional requirements]

**Execution:**
```bash
[commands/steps]
```

**Evidence:**
```
[output/evidence]
```

**Result:** [outcome]

---

### Step N: Objective Achieved

**Impact Type:** [Data Exfiltration / System Compromise / Denial of Service / etc.]

**Access Obtained:** [root / SYSTEM / database admin / etc.]

**Data/Assets Affected:**
- [List of affected data or assets]

**Evidence:**
```
[proof of objective achievement]
```

---

## Vulnerability Summary

| Step | Vulnerability | CVE (if known) | CVSS | CWE |
|------|--------------|----------------|------|-----|
| 1 | [Vuln name] | CVE-XXXX-XXXXX | X.X | CWE-XXX |
| 2 | [Vuln name] | N/A | X.X | CWE-XXX |
| N | [Vuln name] | CVE-XXXX-XXXXX | X.X | CWE-XXX |

---

## Risk Assessment

### Likelihood Factors
- [ ] Publicly known vulnerability/exploit
- [ ] Exploit requires authentication
- [ ] Exploit requires special conditions
- [ ] Exploit is easily automated

**Likelihood Score:** [High / Medium / Low]

### Impact Factors
- [ ] Data confidentiality breach
- [ ] Data integrity compromise
- [ ] Service availability impact
- [ ] Regulatory/compliance implications
- [ ] Reputational damage potential

**Impact Score:** [Critical / High / Medium / Low]

### Overall Risk
**Risk = Likelihood × Impact = [RATING]**

---

## Remediation Recommendations

### Immediate Actions (0-7 days)
1. [Critical fix 1]
2. [Critical fix 2]

### Short-Term (7-30 days)
1. [Medium priority fix 1]
2. [Medium priority fix 2]

### Long-Term (30+ days)
1. [Strategic improvement 1]
2. [Strategic improvement 2]

---

## Detection Opportunities

### Network-Based
| Indicator | Detection Method | Tool |
|-----------|------------------|------|
| [Network signature] | [How to detect] | [SIEM/IDS rule] |

### Host-Based
| Indicator | Detection Method | Tool |
|-----------|------------------|------|
| [File/process indicator] | [How to detect] | [EDR/Sysmon rule] |

### Log-Based
| Log Source | Indicator | Query |
|------------|-----------|-------|
| [Source] | [What to look for] | [Query example] |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Procedure |
|--------|-----------|-----------|
| Initial Access | [TID] | [How it was used] |
| Execution | [TID] | [How it was used] |
| Persistence | [TID] | [How it was used] |
| Privilege Escalation | [TID] | [How it was used] |
| Defense Evasion | [TID] | [How it was used] |
| Collection | [TID] | [How it was used] |
| Exfiltration | [TID] | [How it was used] |
| Impact | [TID] | [How it was used] |

---

## References

### External References
- [CVE/Advisory links]
- [Vendor documentation]
- [Research papers]

### Internal References
- [Related findings]
- [Previous assessments]
- [Internal documentation]

---

## Appendices

### Appendix A: Full Command History
```bash
# Complete sequence of commands used
[commands]
```

### Appendix B: Tool Outputs
[Redacted or summarized tool outputs]

### Appendix C: Screenshots
[Reference to screenshot archive, not embedded for size]

---

## Common Attack Chain Templates

### Template: Android App → System Compromise
```
[Debuggable App] → [JDWP Exploit] → [Code Execution] → [Data Access]
     │                  │                 │                │
  Manifest          adb forward      Runtime.exec      /data/data/
```

### Template: IoT Camera → Network Access
```
[RTSP Unauth] → [Credential Dump] → [Web Shell] → [Pivot]
     │                │                 │             │
  554/tcp         config.xml       CGI injection  Internal scan
```

### Template: Thick Client → Database Compromise
```
[Config Leak] → [Hardcoded Creds] → [SQL Injection] → [Data Exfil]
     │                │                  │                │
  .ini file      cleartext DB     UNION SELECT      bulk dump
```

### Template: Firmware → Root Shell
```
[Firmware Extract] → [Cred Harvest] → [Telnet Login] → [Root]
     │                    │                │              │
  binwalk            /etc/shadow      default pwd    busybox
```

### Template: SELinux Bypass → Persistent Root
```
[Policy Extract] → [Inject Rules] → [Permissive] → [Root Access]
     │                  │                │              │
  /sys/fs/selinux  sepolicy-inject    shell_exec    su binary
```

---

## Checklist

- [ ] Chain metadata complete
- [ ] All steps documented with evidence
- [ ] Vulnerabilities catalogued with severity
- [ ] Risk assessment completed
- [ ] Remediation recommendations provided
- [ ] Detection opportunities identified
- [ ] MITRE ATT&CK mapping complete
- [ ] References linked
- [ ] Appendices attached
