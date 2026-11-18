# Web Application Testing Methodology Template

> **Template Version:** 1.1
> **Derived From:** BRA assessment procedures
> **Target:** Web Application Testing

## Overview

Use this method to examine web requests, responses, and application controls.
Each case has an expected result, an observed result, and captured evidence.
Select cases from the application map and the applicable assessment scope.

## Phase 1: Reconnaissance

### Objectives
- [ ] Identify the operations under examination.
- [ ] Record expected access and input rules.
- [ ] Prepare repeatable application state.

### Techniques

1. Select an application operation from the assessment inventory.
2. Record its route, HTTP method, parameters, and content type.
3. Identify the required identity and permission level.
4. Record the expected input constraints and output behavior.
5. Prepare designated test accounts and test records.
6. Capture a normal request and response.

### Deliverables
- [ ] Operation and parameter record
- [ ] Expected access rules
- [ ] Normal request and response

## Phase 2: Testing

### Objectives
- [ ] Compare controls across roles and sessions.
- [ ] Verify input handling.
- [ ] Record repeatable results.

### Techniques

1. Examine authentication and session behavior for the selected operation.
2. Compare the permitted roles with the observed access decisions.
3. Examine input boundaries and rejected input behavior.
4. Examine response data and error messages for unintended disclosure.
5. Verify state-changing operations against the expected request protections.
6. Record the complete request sequence for each suspected defect.
7. Repeat the sequence from the defined initial state.

### Deliverables
- [ ] Role and session comparison
- [ ] Input and error handling results
- [ ] Repeatable request sequences

## Phase 3: Analysis & Reporting

### Objectives
- [ ] Determine which control differs from the expected behavior.
- [ ] Connect results to source or configuration evidence.
- [ ] Verify the correction.

### Techniques

1. Describe the expected and observed result for each failed case.
2. Link the result to captured requests and responses.
3. Record the required role, session state, and test data.
4. Identify the relevant source or configuration when available.
5. Specify the correction and expected verification result.
6. Repeat the case after the correction.
7. Record the result in the assessment coverage record.

### Deliverables
- [ ] Test case results
- [ ] Finding evidence references
- [ ] Regression results

## References

- [Web assessment method](web-application-assessment.md)
- [OWASP Web Security Testing Guide](https://wstg.owasp.org/v4.2/)
