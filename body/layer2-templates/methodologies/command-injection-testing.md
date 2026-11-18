# Command Injection Testing Methodology Template

> **Template Version:** 1.1
> **Derived From:** BRA assessment procedures
> **Target:** Command Injection Testing

## Overview

Use this method to examine how application inputs reach operating system commands.
Command injection occurs when external input changes the command that an application executes.
Record the input, execution path, process identity, and observed result for each finding.

## Phase 1: Reconnaissance

### Objectives
- [ ] Identify interfaces that accept external input.
- [ ] Locate command execution functions.
- [ ] Map input validation and argument construction.

### Techniques

1. Record the source revision and assessment scope.
2. Locate calls to process and shell interfaces.
3. Trace each input from its entry point to the execution function.
4. Record shell use, executable selection, arguments, and environment variables.
5. Identify validation that occurs before execution.

For Python, examine `subprocess` calls and the value of `shell`.
For JavaScript, examine the selected `child_process` function and its arguments.
For native code, examine process creation and shell invocation separately.

### Deliverables
- [ ] Input and execution map
- [ ] Source anchors for command construction
- [ ] Process identity and environment record

## Phase 2: Testing

### Objectives
- [ ] Compare intended arguments with observed arguments.
- [ ] Verify input validation at the execution boundary.
- [ ] Reproduce suspected command changes in the assessment environment.

### Techniques

1. Select an identified execution path.
2. Record the expected executable and argument list.
3. Use the application test harness to supply a normal input.
4. Capture the resulting process arguments and output.
5. Repeat the test with the input that produced the suspected defect.
6. Compare the observed command with the expected command.
7. Record rejected inputs and successful validation separately.

A shell invocation and a direct process invocation have different parsing rules.
Base each conclusion on the actual execution interface.

### Deliverables
- [ ] Normal and suspected input records
- [ ] Captured process arguments
- [ ] Reproduction result and evidence identifiers

## Phase 3: Analysis & Reporting

### Objectives
- [ ] Determine the affected execution boundary.
- [ ] Describe the demonstrated effect.
- [ ] Prepare a correction and verification procedure.

### Techniques

1. Connect the finding to its source anchors and captured output.
2. Describe which input changes the executed command.
3. Record the privileges and resources available to that process.
4. Describe the observed effect without extending it beyond the evidence.
5. Prefer a direct process interface when the operation does not need a shell.
6. Specify explicit executable and argument validation for the affected operation.
7. Repeat the reproduction after the correction.

### Deliverables
- [ ] Finding with evidence references
- [ ] Correction procedure
- [ ] Regression test result

## References

- [OWASP command injection](https://community.owasp.org/attacks/Command_Injection)
- [Python subprocess security](https://docs.python.org/3/library/subprocess.html#security-considerations)
