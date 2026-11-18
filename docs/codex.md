# BRA Codex

The BRA Codex is the product reference for the complete governed assessment model.
It explains the objects, decisions, mechanisms, and retained knowledge that connect an engagement from intake to close-out.

Use the [operation guide](operation.md) for task instructions.
Use [end-to-end flows](end-to-end.md) for concrete runtime traces.
Use this Codex to understand why the components exist and how their responsibilities fit together.

## 1. The engagement is the operating unit

An engagement is one assessment with defined targets, authorization, activity limits, records, and outputs.
It has a lifecycle rather than a single prompt.

The scope writer creates the structured target and authorization record.
The selected method supplies assessment phases.
The runner performs model turns within the surrounding controls.
The evidence and finding components retain the results.
Close-out creates the selected deliverables and records lessons.

A new engagement receives its own scope and state.
Reusable knowledge can carry forward, while earlier target permissions and evidence remain part of their original context.

### The principal engagement objects

| Object | Meaning | Typical location |
| --- | --- | --- |
| Scope | Targets, included work, exclusions, activity mode, and limits | `layer3-engagement/SCOPE.md` |
| Rules of engagement | Operational requirements and selected token state | `layer3-engagement/ROE.md` |
| Plan | Ordered work and checkpoints | `layer3-engagement/PLAN.md` |
| Approval | Recorded permission for an activity or matching request | `.bra/approvals/` and managed approval state |
| Alias map | Relationship between sensitive values and word aliases | `.bra/anon_map.json` |
| Capture | Tool output with source identity and artifact metadata | `.bra/artifacts/raw/` and evidence index |
| Intelligence | Observed information used by the assessment | `NOTES/INTEL.md` |
| Lead | An observation that needs investigation | `NOTES/LEADS.md` |
| Finding | A structured issue record with analysis and evidence references | `NOTES/FINDINGS.md` |
| Pitch | A proposal that requires review | `layer3-engagement/pitches/` |
| Doctrine | Reusable methods, workflows, skills, tools, and reviewed recommendations | `layer2-templates/` |

All locations are relative to `body/`.
The `NOTES/` directory is inside `layer3-engagement/`.

## 2. Head, Body, and Boots carry different responsibilities

Boots is the interaction layer.
It receives browser and service requests, presents decisions, broadcasts progress, and manages engagement tasks.

Head is the model-facing runtime.
It opens SDK turns, registers policy adapters, processes results, resolves evidence, and coordinates finding documentation.

Body is the governed workspace and its surrounding assets.
It holds policy implementations, reusable doctrine, engagement records, and runtime state with distinct ownership rules.

The folder split is useful because it exposes the interfaces that a replacement must preserve.
A new interface still needs to submit decisions and actions through the managed engagement path.
A different model backend still needs the relevant tool, policy, capture, and record behavior.

## 3. Authority has more than one dimension

A request can satisfy one condition while still needing another.
Permission to use a tool does not add its target to scope.
Permission to contact a target does not grant a destructive operation.
Permission to create an artifact does not make it a governed finding.

BRA therefore evaluates separate authority dimensions:

- The activity class and active assessment mode.
- The target and permitted scope level.
- The tool or script request.
- The operation's installation, destructive, or scan characteristics.
- The output path and state owner.
- The privacy mode and mapping state.
- The current finding or lifecycle workflow.

This separation makes approval more precise.
The operator can answer the decision that the request actually needs.
The recorded authority can then be inspected by the corresponding runtime component.

### Permission lifetimes

Some decisions apply once.
Some apply to the current session or engagement.
Some create a persistent target or mode record.
Takeover uses a short lease with its own expiry.

The matching and lifetime matter as much as the word “approved.”
A retry with a changed command is a different request from the original input.
The tool approval component uses identifiers and input matching to connect valid retries with their grants.

## 4. Control in Depth connects guidance and execution

The model receives governance text, method instructions, scope context, and structured reasons for blocked work.
These inputs help it choose useful actions and recover from denials.

Runtime components then evaluate the proposed transition.
The SDK hook registry connects the stop check, tool approval, finding guard, command policy, file policy, and capture path.
Body scripts supply policy decisions outside the model's reasoning process.

The file adapter returns a transport block when it cannot obtain a valid policy result.
The command adapter interprets the body guard return code and reason.
The runner converts recognized blocks into operator decisions and continuation behavior.

This is application governance over managed requests and records.
The wrapper places SDK state under the engagement directory but retains the launching user's host permissions.
It does not configure an operating-system sandbox.
`Read`, `Grep`, `Glob`, `Write`, and `Edit` use the file adapter.
`Bash` uses a separate command adapter.
Other enabled tools do not inherit the Bash target extractor.

The callback registry is not a guaranteed short-circuit chain.
Bash previews tool approval before its own policy call.
Its Body routine repeats stop state.
Mapped command execution does not independently repeat every shared hook predicate.

The [Control in Depth guide](control-in-depth.md) describes the lowest boundaries and each failure decision.

### Context continuity

The first normal SDK turn includes the governance text from `CLAUDE.md`.
The compaction hook restores that text when the SDK compacts context.

The runtime also keeps scope and authority in files and state.
A prompt summary is therefore not the only place where the engagement's permissions exist.

## 5. Privacy preserves useful target relationships

Simple removal of a target value can make the work impossible to follow.
BRA's alias mapping preserves the relationship between a sensitive value and a stable word.

The agent can reason about the same target across scope, commands, captures, findings, and reports.
The operator can inspect the original value through the local display path.
The execution path can substitute the real value when required.

### Detection, selection, and mapping

Detection produces candidate values.
The operator privacy paths select and store mappings.
The active scope or chat mode determines where replacement occurs.

Manual mappings support values that need operator judgment.
The map stores each original value with its alias, type, source, and creation metadata.
Known values reuse their existing aliases.

### The command boundary

A mapped command first enters the checks applicable to its original text.
The target extractor recognizes one CIDR, IPv4 address, or qualifying domain.
It can return no target for a word-only alias.
The privacy intercept then executes its real-value form locally, without repeating target validation.
The result is masked and stored for model-facing reuse.
The original SDK invocation is blocked after this local execution.

This arrangement keeps one approved work item connected across different data views.
It also avoids a second execution of the same mapped command through the SDK.

### Operator conversion

The interface can rehydrate displayed records and identify replaced values.
The standalone report utility converts a masked report into a separate operator output file.
The map remains a local record that requires the engagement's data handling rules.

## 6. Captures provide the origin of observations

A capture is more specific than a note saying that a tool was used.
It connects a result with its tool, command context, identifiers, artifact path, time, and hash.

The post-tool hook creates raw artifacts from nonempty output.
The mapped command intercept creates the corresponding masked artifact and capture context on its own path.
The evidence index supports later lookup.

A subsequent inspection can produce a derivative capture.
The runner's provenance logic attempts to retain the originating capture when it supports the observation.
This keeps a finding connected to the request that collected the relevant evidence.

## 7. Markers become living records

The agent emits structured marker lines for findings, services, endpoints, target properties, and leads.
The parser converts recognized lines into structured data.
The runner corrects provenance fields and writes marker events.

Event replay updates intelligence and lead records.
Finding events also create scaffolds and system-managed sections.
The browser receives callbacks for the corresponding visible updates.

The records serve different purposes:

| Stream | Primary question |
| --- | --- |
| Intelligence | What information was observed? |
| Leads | What should be investigated next? |
| Findings | What issue is documented, with what evidence and impact? |
| Reports | What reviewed result should be delivered to this audience? |
| Pitches | What reusable improvement should be considered? |

The shared capture context connects these streams without making them interchangeable.

## 8. Finding completeness is an explicit workflow

A finding marker starts work rather than finishing it.
The queue retains the finding until its record meets the enforcer's requirements.

### System-managed content

The materializer derives evidence-related sections from capture context.
These include affected artifact details, local paths, hashes, line spans, reproduction information, and observed evidence references.
It can also create proof and evidence support files.

### Analysis content

The documentation task supplies fields such as description, impact, attack vector, remediation, CWE, and tool versions.
It uses a dedicated system prompt and restricted tools.
Its hooks retain policy checks while omitting the finding guard that would block its own documentation work.

### Validation and handoff

The enforcer checks required sections and metadata.
It rejects unresolved placeholders and checks applicable local artifact hashes and proof references.
Inline proof content and explicitly unavailable hashes have defined handling paths.

The runner reconciles records left complete by an earlier interrupted task.
It can merge leftover documentation output before starting another turn.
If the worker stalls or cannot finish, the main agent receives a restricted findings handoff.

The operator remains responsible for reviewing the technical interpretation and severity.
Mechanical completeness and evidence linkage provide the material for that review.

## 9. Close-out is a managed transition

Close-out starts with the required report metadata.
When findings selection is enabled, the operator records the chosen report set.

The managed sequence runs statistics, report preparation, disclosure generation, narrative enhancement, and lessons generation.
The manager checks report placeholders and exposes retry or skip choices for failed steps.
It records the ended time and clears the managed session state when close-out completes.

### Deliverable roles

- The executive summary communicates the result and priorities.
- The technical report describes findings and remediation.
- The vendor submission carries the remediation details required by the vendor.
- The CNA submission organizes the selected CVE request information.
- The disclosure package connects summaries, evidence locations, timeline, and contacts.
- The evidence manifest records hashes and custody information.
- Attack-chain records explain relationships between individual issues.

The report templates and data handling rules define the expected content for each audience.

## 10. Growth converts experience into reviewable values

An assessment can reveal a useful method, a missing tool, or repeated control friction.
BRA's improvement routines record those observations as candidates.

The incremental path uses findings, leads, artifact changes, and override activity.
The retrospective path combines lessons, findings, review gaps, statistics, and available method information.
The output is a pitch with items that the operator can review.

### Promotion is a separate action

The promotion routine reads approved items and chooses a supported destination.
It creates a temporary template-write token when none exists.
It removes the token it created when the operation finishes.
It adds a skill, tool reference, method draft, attack pattern, or override recommendation.
It then records implementation status and removes the temporary token.

Draft content can require further authoring.
A reusable override recommendation does not activate an exception in the current or next engagement.
This preserves the distinction between knowledge and authority.

### Ingestion is related, but separate

The ingestion script can process approved pitch items.
The reference integration script can combine imported project knowledge after supported redaction.
Deduplication and review help keep reusable content organized.

These are additional entry points into reusable knowledge.
They are not a single mandatory sequence for every promotion.

## 11. Model and interface choices have explicit boundaries

The current model runtime uses the Claude Agent SDK.
Optional proxy routing sends requests through a local completion clamp and LiteLLM to an OpenAI-compatible backend.
The same SDK tool and hook path remains active.

The browser and HTTP interfaces use the managed engagement components.
Python utilities expose readiness, status, statistics, packaging, and other operational tasks.
The optional 2x4 surface adds provider chat, bounded reads, call controls, and leased action routing.

An external Hermes voice path uses an installed plugin.
The bundled OpenClaw voice runtime contains provider-specific call and media support.
Provider services and speech configuration supply the selected call implementation.

## 12. What the architecture retains

The engagement retains scope, decisions, alias relationships, captures, records, and report context.
The reusable catalog retains reviewed knowledge from accepted proposals.
The runtime retains explicit interfaces between model work, permission checks, and durable output.

These are the practical sources of continuity.
A new turn can refer to evidence rather than reconstructing it from a summary.
A later operator can inspect decisions rather than infer them from conversation tone.
A future engagement can use a reviewed lesson without inheriting earlier target permission.

Continue with the [source map](source-map.md) to inspect the implementation behind these mechanisms.
