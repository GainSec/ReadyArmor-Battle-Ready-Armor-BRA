# Methodology Roadmap

This catalog lists the methodology files supplied with BRA.
The directory contains fourteen assessment methods.
The methodology loader reads phase headings, objectives, techniques, and deliverable checklists from these files.

## Available methods

| File | Application |
| --- | --- |
| [Android mobile security](android-mobile-security.md) | Android applications and their supporting services |
| [Bluetooth and radio security](bluetooth-radio-security.md) | Bluetooth interfaces and radio observations |
| [Command injection](command-injection-testing.md) | Application inputs that reach process execution |
| [Credential analysis](credential-secret-analysis.md) | Credential storage, delivery, access, and revocation |
| [.NET assessment](dotnet-assessment.md) | Managed applications and .NET components |
| [Field intelligence](field-intel.md) | Field observations and evidence collection |
| [HomeKit fuzzing](hap-homekit-fuzzing.md) | HomeKit protocol implementation review |
| [Device assessment](iot-embedded-security-assessment.md) | Device inventory, trust boundaries, and assessment coordination |
| [Detailed embedded security](iot-embedded-security.md) | Device hardware, firmware, and interfaces |
| [Reverse engineering](reverse-engineering.md) | Compiled artifact behavior and execution evidence |
| [SELinux and Android](selinux-android-exploitation.md) | Android security policy and privilege boundaries |
| [Thick client security](thick-client-security.md) | Installed desktop applications and supporting services |
| [Web assessment](web-application-assessment.md) | Application mapping, coverage, and findings |
| [Web testing](web-application-testing.md) | Request, response, session, and access checks |

## Method format

Use one level-one heading for the method title.
Include the `Template Version` metadata field.
Use `## Phase N: Name` for each numbered phase.
Use consecutive phase numbers that start at one.

Each phase uses these subsection names:

- `### Objectives`: bullet items that describe the phase goals.
- `### Techniques`: the procedure and applicable command examples.
- `### Deliverables`: checkbox items for required results.

Use `- [ ]` for an incomplete deliverable.
Use `- [x]` for a complete deliverable in the engagement copy.
The loader reads these headings and checkbox markers exactly.
It also reads the language identifier and commands from fenced code blocks.

## Select a method

1. Identify the target type in the engagement scope.
2. Select the applicable method from this catalog.
3. Read its phases and required deliverables.
4. Match the selected procedures to the engagement permissions.
5. Record the selected method in the engagement plan.
6. Preserve evidence identifiers for the completed procedures.

## Examine the parsed method

Use the loader from the repository directory.

```sh
python3 body/layer1/lib/methodology_loader.py --summary body/layer2-templates/methodologies/web-application-assessment.md
```

Use `--phase` to examine a specific phase.

```sh
python3 body/layer1/lib/methodology_loader.py --phase body/layer2-templates/methodologies/web-application-assessment.md 'Phase 1'
```

## Add or revise a method

1. Place the file in `body/layer2-templates/methodologies/`.
2. Preserve the loader headings and metadata fields.
3. Specify the required inputs and observable results for each phase.
4. Use existing command options from the selected tools.
5. Add the file to this catalog.
6. Examine the parsed summary and phase details.
7. Update the related tests when a parser contract changes.

The loader implementation is `body/layer1/lib/methodology_loader.py`.
