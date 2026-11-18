# Credential & Secret Analysis Methodology Template

> **Template Version:** 1.1
> **Derived From:** BRA assessment procedures
> **Target:** Credential & Secret Analysis

## Overview

Use this method to examine credentials in source files, configuration, logs, and stored artifacts.
Record secret locations and access controls without copying secret values into the assessment report.
Distinguish an example value from a credential that an application actually uses.

## Phase 1: Reconnaissance

### Objectives
- [ ] Identify credential sources and storage locations.
- [ ] Map credential consumers.
- [ ] Record the applicable access boundaries.

### Techniques

1. Inventory configuration files, secret stores, build settings, and deployment manifests.
2. Identify the processes that read each credential.
3. Record the credential type and owner.
4. Record the path or secret identifier instead of the secret value.
5. Examine file permissions and secret delivery paths.
6. Identify log and backup locations that can contain credentials.

### Deliverables
- [ ] Credential location inventory
- [ ] Consumer and permission map
- [ ] Log and backup inventory

## Phase 2: Testing

### Objectives
- [ ] Verify access restrictions.
- [ ] Examine credential disclosure paths.
- [ ] Verify replacement and revocation procedures.

### Techniques

1. Compare the permitted reader list with the observed permissions.
2. Examine sample logs for credential disclosure.
3. Examine build outputs and packaged configuration for included secrets.
4. Determine whether the application records complete credentials in error messages.
5. Verify credential replacement with a designated test credential.
6. Record whether the old test credential remains accepted after revocation.
7. Capture evidence with secret values masked.

### Deliverables
- [ ] Permission comparison
- [ ] Masked disclosure evidence
- [ ] Replacement and revocation results

## Phase 3: Analysis & Reporting

### Objectives
- [ ] Describe demonstrated credential exposure.
- [ ] Identify the responsible storage or delivery component.
- [ ] Prepare correction and verification steps.

### Techniques

1. Connect each exposure to a file, event, or application response.
2. Record the access needed to obtain the credential.
3. Describe the demonstrated access granted by the designated test credential.
4. Specify the required storage, permission, or logging correction.
5. Assign credential replacement to the credential owner.
6. Repeat the failed access and revocation checks after the correction.

### Deliverables
- [ ] Credential findings with masked evidence
- [ ] Correction and replacement plan
- [ ] Verification results

## References

- [OWASP secrets management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
