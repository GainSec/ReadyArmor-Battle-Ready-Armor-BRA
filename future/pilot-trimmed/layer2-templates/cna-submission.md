# CNA/CVE Submission Template

> **Template Version:** 2.0
> **Purpose:** Complete CVE request and CNA submission with proper redaction for public disclosure
> **Derived From:** Historical engagements

Use this form to prepare a CVE request for a CVE Numbering Authority (CNA). Remove secrets before submission.

---

## Submission Pipeline Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Document   │ → │   Request   │ → │   Submit    │ → │ Coordinate  │ → │   Publish   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                  │                  │                  │                  │
 Complete finding    Get CVE ID       CNA submission     Vendor timeline      Public advisory
```

---

## Pre-Submission Checklist

- [ ] Finding fully documented with reproducible steps
- [ ] CWE mapped and verified
- [ ] CVSS score calculated with vector string
- [ ] Evidence preserved with hashes
- [ ] Sensitive data redacted
- [ ] Vendor contact information obtained
- [ ] Disclosure timeline defined

---

## Section 1: Engagement Context (Sanitized)

> **Redaction Guidelines:** Omit sensitive environment identifiers, internal hostnames, and operational details

| Field | Value |
|-------|-------|
| **Target Application** | [App/Device name and version] |
| **Vendor** | [Vendor name] |
| **Platform** | [Android/iOS/Windows/Linux/Embedded] |
| **Authorization Reference** | [Contract/engagement ID - redact sensitive] |
| **Testing Window** | [Start date] - [End date] |
| **Roles Used** | [User roles tested - omit credentials] |
| **Scope Constraints** | [High-level ROE summary] |

---

## Section 2: Vulnerability Summary Table

| CVE ID | Title | CVSS | CWE | Status |
|--------|-------|------|-----|--------|
| CVE-YYYY-XXXXX | [Short descriptive title] | X.X | CWE-XXX | [Proven/Exploit Ready] |

---

## Section 3: Vulnerability Details

### 3.1 Basic Information

| Field | Value |
|-------|-------|
| **Title** | [Descriptive vulnerability title] |
| **CVE ID** | CVE-YYYY-XXXXX (or "Pending") |
| **CWE Classification** | CWE-XXX: [CWE Name] |
| **Affected Product** | [Product Name] |
| **Affected Versions** | [Version range, e.g., "1.0.0 - 2.3.5"] |
| **Fixed Version** | [Version with fix, or "N/A"] |

### 3.2 Affected Artifact

| Field | Value |
|-------|-------|
| **Artifact Name** | [Filename/module name] |
| **Artifact Location** | [Path - redact sensitive host info] |
| **Artifact Hash (SHA256)** | [64-character hash] |
| **Artifact Size** | [Size in bytes] |

### 3.3 Vulnerability Description

**Short Description (1-3 lines):**
> [Concise description of the vulnerability suitable for CVE entry]

**Technical Description:**
> [Detailed technical explanation of the vulnerability, including the vulnerable function/component, input validation failure, or logic flaw]

### 3.4 Impact Assessment

| Scope | Impact Description |
|-------|-------------------|
| **Worst-Case Impact** | [Maximum theoretical impact if fully exploited] |
| **Realistic Impact** | [Likely real-world exploitation impact] |
| **Affected Users** | [Scope of affected user base] |
| **Data at Risk** | [Types of data potentially exposed/modified] |

### 3.5 Attack Vector

**Attack Prerequisites:**
- [Prerequisite 1 - e.g., "Local network access"]
- [Prerequisite 2 - e.g., "Valid user account"]

**Attack Complexity:** [Low/Medium/High]

**User Interaction Required:** [None/Required]

**Attack Description (1-3 lines):**
> [How an attacker would exploit this vulnerability]

### 3.6 Vulnerable Code Snippet

```
File: [path/to/file.ext]
Lines: [start]-[end]
Hash: [SHA256 of file]
```

```[language]
// Vulnerable code snippet (≤40 lines)
// Redact any hardcoded secrets or credentials
// Include sufficient context for understanding
```

**Vulnerability Analysis:**
> [Explanation of why this code is vulnerable]

### 3.7 Reproduction Steps

> **Note:** Omit secrets, credentials, and sensitive host identifiers

**Environment Setup:**
```bash
# Environment preparation commands
# Redact sensitive configuration values
```

**Exploitation Steps:**
1. [Step 1 - specific action]
2. [Step 2 - specific action]
3. [Step N - expected result]

**Expected Outcome:**
> [What the attacker achieves upon successful exploitation]

### 3.8 Proof of Concept

**PoC Description:**
> [Description of the proof of concept, what it demonstrates]

**PoC Location:**
> [Reference to sanitized PoC file location in evidence package]

**PoC Execution:**
```bash
# Sanitized PoC execution commands
# Replace sensitive values with [REDACTED] or placeholders
```

### 3.9 Observed Evidence

| Timestamp (UTC) | Observation | Evidence Hash |
|-----------------|-------------|---------------|
| YYYY-MM-DD HH:MM:SS | [Observation] | [SHA256] |

**Tool Versions Used:**
| Tool | Version |
|------|---------|
| [Tool name] | [Version] |

### 3.10 Severity Assessment

**CVSS v3.1 Vector:**
```
CVSS:3.1/AV:[N/A/L/P]/AC:[L/H]/PR:[N/L/H]/UI:[N/R]/S:[U/C]/C:[N/L/H]/I:[N/L/H]/A:[N/L/H]
```

**CVSS v3.1 Score:** X.X ([Critical/High/Medium/Low])

**CVSS Breakdown:**
| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector (AV) | [Network/Adjacent/Local/Physical] | [Why] |
| Attack Complexity (AC) | [Low/High] | [Why] |
| Privileges Required (PR) | [None/Low/High] | [Why] |
| User Interaction (UI) | [None/Required] | [Why] |
| Scope (S) | [Unchanged/Changed] | [Why] |
| Confidentiality (C) | [None/Low/High] | [Why] |
| Integrity (I) | [None/Low/High] | [Why] |
| Availability (A) | [None/Low/High] | [Why] |

**Likelihood:** [High/Medium/Low]
> [Rationale for likelihood assessment]

### 3.11 Remediation

**Recommended Fix:**
> [Specific code change, configuration update, or architectural fix]

**Mitigation (if fix unavailable):**
> [Temporary workarounds to reduce risk]

**Example Fixed Code:**
```[language]
// Corrected code example
```

### 3.12 Coverage Evidence

**Code Paths Exercised:**
- [Function/method 1]
- [Function/method 2]

**Test Coverage:**
> [Description of how thoroughness was verified]

### 3.13 Additional Notes

> [Any additional context, related findings, or relevant observations]
> **IMPORTANT:** No HIGH-SENSITIVITY content. No secrets or credentials.

---

## Section 4: Evidence Index (Sanitized)

| Evidence ID | Description | SHA256 Hash | Sensitivity |
|-------------|-------------|-------------|-------------|
| E001 | [Description - redact sensitive paths] | [Hash] | [Low/Medium/High] |

**Evidence Package Location:**
> [Reference to evidence package - redact sensitive paths]

**Chain of Custody:**
> [Brief description of evidence handling and preservation]

---

## Section 5: Disclosure Timeline

| Date | Milestone | Status |
|------|-----------|--------|
| YYYY-MM-DD | Vulnerability discovered | Complete |
| YYYY-MM-DD | Initial analysis complete | Complete |
| YYYY-MM-DD | Vendor notification sent | [Pending/Complete] |
| YYYY-MM-DD | Vendor acknowledgment received | [Pending/Complete] |
| YYYY-MM-DD | CVE ID requested | [Pending/Complete] |
| YYYY-MM-DD | CVE ID assigned | [Pending/Complete] |
| YYYY-MM-DD | Fix released by vendor | [Pending/Complete] |
| YYYY-MM-DD | Public disclosure target | [Pending/Complete] |

**Disclosure Policy:**
> [Reference to coordinated disclosure policy - typically 90 days]

---

## Section 6: Contact Information

| Role | Contact |
|------|---------|
| **Researcher Name** | [Name] |
| **Researcher Email** | [Email] |
| **Researcher PGP Key** | [Key ID or omit per policy] |
| **Organization** | [Organization - if applicable] |
| **Vendor Security Contact** | [Email - if known] |

---

## Section 7: CVE Request Form (For MITRE/CNA)

> Use this section when requesting a CVE ID

**CVE Request Information:**

| Field | Value |
|-------|-------|
| **Vulnerability Type** | [Type, e.g., "Buffer Overflow", "Injection"] |
| **Attack Type** | [Remote/Local/Physical] |
| **Impact** | [Code Execution/Information Disclosure/DoS/etc.] |
| **Affected Component** | [Specific component name] |
| **Product Name** | [Full product name] |
| **Vendor Name** | [Vendor name] |
| **Version(s) Affected** | [Version range] |
| **Version(s) Fixed** | [Fixed version or "Not yet fixed"] |

**CVE Description (for public disclosure):**
> [One paragraph description suitable for CVE database entry]

---

## Submission Checklist

### Pre-Submission
- [ ] All sections complete
- [ ] CVSS calculated correctly
- [ ] CWE appropriate for vulnerability type
- [ ] Evidence indexed with hashes
- [ ] Sensitive data redacted
- [ ] Reproduction steps verified
- [ ] PoC tested and sanitized

### Vendor Notification
- [ ] Vendor security contact identified
- [ ] Notification email drafted
- [ ] Timeline clearly communicated
- [ ] PGP encryption used (if available)

### CVE Request
- [ ] CVE request form completed
- [ ] Submitted to appropriate CNA
- [ ] Request ID tracked

### Post-Assignment
- [ ] CVE ID received and recorded
- [ ] Advisory updated with CVE ID
- [ ] Vendor coordination ongoing
- [ ] Public disclosure date confirmed

---

## Quick Reference

### CNA Submission Points
| CNA | Scope |
|-----|-------|
| MITRE | General (if no product-specific CNA) |
| Vendor CNA | Product-specific (if vendor is CNA) |
| Partner CNA | Through authorized partner |

### Standard Disclosure Timeline
| Phase | Duration |
|-------|----------|
| Vendor Notification | Day 0 |
| Vendor Acknowledgment | Day 7 (target) |
| Vendor Fix Development | Days 8-60 |
| Fix Release | Day 60-90 |
| Public Disclosure | Day 90 (or after fix) |

### Common CWE Categories
| Category | CWE Examples |
|----------|--------------|
| Injection | CWE-78 (OS Command), CWE-89 (SQL), CWE-79 (XSS) |
| Memory | CWE-119 (Buffer Overflow), CWE-416 (Use After Free) |
| Auth | CWE-287 (Improper Auth), CWE-306 (Missing Auth) |
| Crypto | CWE-327 (Broken Crypto), CWE-295 (Improper Cert Val) |
| Config | CWE-732 (Incorrect Permissions), CWE-276 (Incorrect Default) |
