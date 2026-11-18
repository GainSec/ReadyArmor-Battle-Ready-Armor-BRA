# Web Application Assessment Methodology Template

> **Template Version:** 1.1
> **Derived From:** BRA assessment procedures
> **Target:** Web Application Assessment

## Overview

Use this method to define and complete a web application assessment.
It connects the application inventory, selected tests, evidence, and final findings.
Use the web testing method for the individual request and response checks.

## Phase 1: Reconnaissance

### Objectives
- [ ] Define application components and user roles.
- [ ] Map entry points and trust boundaries.
- [ ] Select relevant assessment procedures.

### Techniques

1. Record the application version and assessment scope.
2. Inventory application routes, APIs, authentication methods, and external services.
3. Identify the user roles and their permitted operations.
4. Map sensitive data between entry points and storage components.
5. Identify the deployed configuration and applicable source revision.
6. Select the relevant cases from the web testing method.

### Deliverables
- [ ] Application and route inventory
- [ ] Role and trust map
- [ ] Selected test list

## Phase 2: Testing

### Objectives
- [ ] Examine the selected security controls.
- [ ] Reproduce suspected defects.
- [ ] Maintain a coverage record.

### Techniques

1. Prepare a normal request for each selected operation.
2. Record the expected result for the selected role.
3. Do the selected authentication, access, input, and session tests.
4. Record the request, response, role, and application state for each case.
5. Compare the response with the expected result.
6. Reproduce suspected defects from a defined application state.
7. Record completed, blocked, and inapplicable cases separately.

### Deliverables
- [ ] Coverage record
- [ ] Request and response evidence
- [ ] Reproduction results

## Phase 3: Analysis & Reporting

### Objectives
- [ ] Connect defects to affected application controls.
- [ ] Determine demonstrated business and technical effects.
- [ ] Prepare correction and verification procedures.

### Techniques

1. Connect each finding to its request and response evidence.
2. Record the affected routes, roles, data, and source anchors.
3. Describe the demonstrated effect.
4. Specify the responsible component and correction.
5. Repeat the relevant cases after the correction.
6. Record remaining coverage gaps in the assessment results.

### Deliverables
- [ ] Findings and affected component list
- [ ] Correction procedures
- [ ] Verification and coverage results

## References

- [Web testing method](web-application-testing.md)
- [OWASP Web Security Testing Guide](https://wstg.owasp.org/v4.2/)
