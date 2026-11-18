# IoT/Embedded Security Assessment Methodology Template

> **Template Version:** 1.1
> **Derived From:** BRA assessment procedures
> **Target:** IoT/Embedded Security Assessment

## Overview

Use this method to coordinate an assessment of a device, its firmware, and its connected services.
Record the relationship between hardware revisions, firmware versions, and application interfaces.
Use the detailed device method for the applicable hardware and firmware procedures.

## Phase 1: Reconnaissance

### Objectives
- [ ] Identify device components and firmware versions.
- [ ] Inventory physical and network interfaces.
- [ ] Map device trust boundaries.

### Techniques

1. Record the device model, hardware revision, and firmware version.
2. Record the acquisition source and hashes of firmware artifacts.
3. Inventory physical ports and documented service interfaces.
4. Identify the boot sequence and update mechanism from available evidence.
5. Map communications between the device, companion application, and backend.
6. Select the relevant procedures from the detailed device method.

### Deliverables
- [ ] Device and firmware inventory
- [ ] Interface and trust map
- [ ] Assessment procedure list

## Phase 2: Testing

### Objectives
- [ ] Examine selected device controls.
- [ ] Connect firmware observations to runtime behavior.
- [ ] Capture reproducible evidence.

### Techniques

1. Examine firmware configuration and included services.
2. Compare documented interfaces with observed interfaces.
3. Examine authentication and access controls for each selected service.
4. Examine the firmware update verification path.
5. Compare device behavior before and after each selected test.
6. Record the device state, input, output, and artifact hashes.
7. Restore the defined baseline before the next independent test.

### Deliverables
- [ ] Firmware and service review results
- [ ] Device state and response records
- [ ] Evidence manifest

## Phase 3: Analysis & Reporting

### Objectives
- [ ] Connect observations across device components.
- [ ] Determine the demonstrated effect of each defect.
- [ ] Prepare correction and verification procedures.

### Techniques

1. Connect each finding to the affected hardware and firmware revision.
2. Record the required physical or network access.
3. Link firmware anchors to the relevant runtime evidence.
4. Describe the demonstrated trust boundary failure.
5. Specify the affected component and correction.
6. Repeat the procedure on the corrected device or firmware.

### Deliverables
- [ ] Version-specific findings
- [ ] Correction procedures
- [ ] Verification results

## References

- [Detailed device method](iot-embedded-security.md)
- [OWASP Internet of Things](https://owasp.org/projects/internet-of-things)
