# Reverse Engineering Methodology Template

> **Template Version:** 1.1
> **Derived From:** BRA assessment procedures
> **Target:** Reverse Engineering

## Overview

Use this method to reconstruct the relevant behavior of a compiled artifact.
Connect each conclusion to artifact hashes, code locations, and observed behavior.
Separate static observations from results obtained during execution.

## Phase 1: Reconnaissance

### Objectives
- [ ] Identify the artifact format and architecture.
- [ ] Inventory entry points and dependencies.
- [ ] Select the behavior to examine.

### Techniques

1. Record the artifact source, version, and cryptographic hash.
2. Identify the executable format and processor architecture.
3. Inventory imported libraries, exported symbols, and available debug information.
4. Locate configuration, resources, and embedded files.
5. Identify entry points related to the assessment question.
6. Record the selected analysis tools and their versions.

### Deliverables
- [ ] Artifact manifest
- [ ] Entry point and dependency inventory
- [ ] Analysis question and tool record

## Phase 2: Testing

### Objectives
- [ ] Trace the selected behavior.
- [ ] Compare static analysis with execution evidence.
- [ ] Reproduce the relevant result.

### Techniques

1. Examine the selected functions in a disassembler or decompiler.
2. Trace their callers, data inputs, and output operations.
3. Record addresses and offsets for relevant instructions and data.
4. Prepare the execution environment for the selected behavior.
5. Capture the relevant calls, arguments, and results with the chosen runtime tools.
6. Compare the execution evidence with the static interpretation.
7. Record unresolved branches as open questions.

### Deliverables
- [ ] Function and data flow map
- [ ] Address and offset references
- [ ] Runtime evidence and unresolved questions

## Phase 3: Analysis & Reporting

### Objectives
- [ ] Explain the reconstructed behavior.
- [ ] Identify supported security findings.
- [ ] Preserve a reproducible analysis path.

### Techniques

1. State the input conditions for the reconstructed behavior.
2. Describe the observed control and data flow.
3. Link each claim to a code location or captured event.
4. Record the artifact hash beside the code references.
5. Describe any demonstrated security effect.
6. Record the commands and environment needed to repeat the observation.

### Deliverables
- [ ] Behavior description
- [ ] Evidence-backed findings
- [ ] Reproduction procedure

## References

- [Evidence pipeline](../../../docs/evidence-pipeline.md)
