# BRA features and capabilities

BRA coordinates assessment work through a governed workspace.
This guide describes what each capability does, why it is useful, and which component provides it.

## Engagement definition and readiness

### Scope intake

The web intake records authorization, target type, targets, exclusions, activity mode, and engagement details.
The scope writer creates the sections used by the runtime validators.
Token selections become explicit state for later checks.

Scope confirmation blocks ordinary SDK file-tool writes to the engagement scope.
Later target changes use the operator decision path.
This gives an engagement a defined starting boundary and a record of subsequent decisions.

### Readiness checks

The readiness script checks directory structure, scripts, tools, scope, and runtime paths.
It can create missing engagement structure and report unresolved items.
The operator can inspect the readiness report before starting work.

Tool checks help distinguish an unavailable capability from an analysis result.
A missing scanner is an installation condition, not evidence that a target has no exposed service.

### Target-specific methods

The target classifier reads explicit scope types and supported content signals.
Its method map covers Android, IoT and embedded systems, Bluetooth, desktop clients, .NET, SELinux, HomeKit, and field assessment.

Method files define phases, objectives, techniques, and deliverables.
The phase context combines those instructions with the engagement state and available tools.
Additional methods and workflows remain available in the reusable catalog.

**Components:** `boots/engage.py`, `scope-intake.py`, `precheck.py`, `target_type_detector.py`, `methodology_loader.py`, and `phase_invoker.py`.

## Tool, command, and target control

### Structured tool approval

The tool approval hook evaluates non-exempt requests before the operation continues.
It can match approval by invocation identifier, tool input, or an operator-selected session permission.
The retry path can match the original input when a new SDK invocation identifier appears.

The interface shows the relevant tool or command details.
The operator can approve, deny, or select an available permission scope.
BRA records the result and chooses the corresponding continuation path.

### Scope-aware command checks

The body command guard recognizes configured network operations and target patterns.
It checks applicable activity, target, operation, installation, path, and scan predicates in the original command.
Target extraction selects one recognized CIDR, IPv4 address, or domain.
Empty extraction skips the target predicate.
Scope literals and original targets resolve `FULL` before discovered levels.
The scope-text matcher does not distinguish inclusion from exclusion sections.

Unknown targets produce `SCOPE_CHECK_REQUIRED`.
The operator scope decision can add or upgrade the target through governed registration.
The agent then continues using the resulting scope state.

### File policy and state ownership

The SDK file guard refuses direct `Write` and `Edit` requests to the governance layer during engagement.
It restricts template changes, checks engagement output paths, protects the confirmed scope, and applies runtime schema rules.

Artifacts belong in `.bra/artifacts/`.
Structured evidence and findings belong in the engagement notes.
Approval files, queues, privacy mappings, and phase state have designated owners.
This helps keep a temporary work file separate from permission state or a report-ready record.

### Stop, pause, and recovery

Stop checks read the runtime stop state and the governance stop marker.
The engagement manager can cancel managed tasks and terminate tracked SDK descendants.
Pause and resume controls retain the surrounding engagement context.

The manager also reconciles stale in-memory state before preparing another runner.
This supports recovery from interrupted turns and prevents old tasks from continuing unnoticed through the normal managed path.

**Components:** SDK hook registry, `tool_approval_hook.py`, `bash_hook.py`, `file_hook.py`, body guards, `approval.py`, and `EngageManager`.

## Privacy and model context

### Reusable aliases

The local map stores real values, word aliases, types, sources, and creation details.
Repeated values reuse their mappings.
Replacement processes longer values first to reduce partial matches.

The model can use an alias as a known target throughout the engagement.
This preserves the relationship between the scope entry, a command, and its later evidence.

### Detection and review

The detection API combines regex proposals with optional local named entity recognition.
Manual mappings let the operator add values that require masking.
Privacy modes select the applicable scope and chat behavior.

`ANON-SCAN` reviews newly detected chat values before continuing the message.
`MAP-SCAN` reuses known values from the map.
Raw modes supply unmasked input when selected by the operator.

### Execution substitution and output masking

A mapped Bash command enters the original-command checks before the privacy intercept executes its substituted form.
No second target check evaluates that substituted command.
The intercept records masked output and returns a masked preview.
It blocks the original SDK invocation after performing that local execution.

The post-tool path also applies mapped-value masking when it saves captured artifacts.
Operator displays can rehydrate values with highlight metadata.
The final report conversion utility writes a separate real-value report outside the agent session.

**Components:** `AnonAPI`, `AnonMap`, `NERClient`, chat preparation, scope review, command interception, and `rehydrate.py`.

## Evidence, intelligence, leads, and findings

### Captured tool output

The post-tool hook captures nonempty output to raw artifact storage.
Capture records include the tool, available invocation and session identifiers, command context, artifact path, time, and hash.
The evidence index makes these details available for later source resolution.

### Structured observations

The marker parser recognizes findings, services, endpoints, target properties, and leads.
The runner normalizes those observations and writes marker events.
Materializers then update the corresponding records.

Intelligence contains observed information.
Leads identify work that needs investigation.
Findings contain structured issue records.
These streams have different roles, even when they refer to the same capture.

### Origin-aware provenance

A later `Read` of an artifact can create another tool capture.
The runner ranks originating captures above derivative inspection captures when resolving evidence.
It also checks explicit identifiers, current tool results, and source hints.

This helps a finding point to the request that collected the evidence rather than an unrelated recent command.
The normalized event preserves that relationship for replay and review.

### Restricted finding documentation

A finding marker enters a pending queue.
System routines create the scaffold, evidence context, artifact references, reproduction information, and proof support files.
A documentation task completes the narrative fields through a restricted tool set.

The enforcer checks required sections, metadata, unresolved placeholders, applicable local artifact hashes, and proof references.
A complete record leaves the pending queue.
A stalled documentation task can hand work back to the main agent with restricted tools.

**Components:** `post_hook.py`, `capture_provenance.py`, `markers.py`, `marker_events.py`, `runner.py`, materializers, and `FindingEnforcer`.

## Reports and coordinated disclosure

### Close-out metadata and finding selection

Close-out collects the required engagement and report metadata.
When findings selection is enabled, the operator chooses which records enter the report set.
The selection is stored for the downstream report routines.

### Report generation and enhancement

The close-out sequence generates statistics, prepares the report, creates disclosure outputs, and invokes report enhancement.
The runtime checks for remaining report placeholders.
Failed steps expose retry or skip choices to the operator.

The report templates include executive summaries, severity tables, technical content, and prioritized remediation.
Vendor and CNA forms separate their required content and handling rules.
Disclosure records include timelines, evidence indexes, and contacts.

### Evidence manifest and attack chains

The evidence manifest records artifact hashes, collection details, and custody information.
Attack-chain templates connect individual findings to multi-stage paths, impact, detection opportunities, and MITRE ATT&CK identifiers.

These forms help turn assessment output into reviewable deliverables.
The operator reviews the technical interpretation and final distribution.

**Components:** end-intake handling, `report-ready.py`, `disclose.py`, `report_enhance.py`, and report templates.

## Reviewed growth and reusable doctrine

### Incremental improvement

The improvement routine monitors phase artifacts, new findings, leads, and override decisions.
It records candidate lessons and can generate pitches during the engagement.
Change detection and stored improvement state reduce repeated processing.

### Retrospective growth

The lessons routine combines engagement context, findings, leads, review gaps, and observed methods.
It starts retrospective proposal generation after the engagement records are available.

### Controlled promotion

Promotion reads approved checklist items from pitches.
It routes supported categories into skills, tool references, method drafts, attack patterns, and override recommendations.
A temporary path-scoped template-write token surrounds the operation.

Processed items receive implementation status.
Existing entries can be skipped, and categories requiring manual placement remain visible for review.
A promoted method can require further authoring before operational use.

### Reference ingestion

The ingestion tools process approved pitch content or imported project references.
Redaction removes supported project identifiers before references are combined.
Deduplication and operator review support reuse across engagements.

**Components:** `self-improvement.py`, `growth.py`, `lessons-learned.py`, `promotion.py`, `ingest.py`, and `integrate-ingest.py`.

## Interfaces, model routing, and telemetry

### Web and command surfaces

The browser interface displays managed agent events, approval cards, scope, findings, artifacts, logs, and reusable loadout content.
HTTP routes expose those resources to supported integrations.
Python commands provide operational utilities such as readiness, status, statistics, backup, and packaging.

### Model backend choice

The runtime uses the Claude Agent SDK.
The optional local proxy clamps configured completion limits and passes requests through LiteLLM to an OpenAI-compatible backend.
This preserves the SDK tool and hook path while changing the inference service.

A local backend can keep inference on the selected infrastructure.
Model selection and assessment network permissions remain separate configuration decisions.

### Usage and engagement telemetry

SDK result messages supply token, cache, duration, model usage, and cost fields when available.
BRA stores query records and exposes summary views.
`NO-TOKEN-TRACKING` disables that usage record path.

Engagement telemetry summarizes findings, leads, artifacts, tokens, methods, and cumulative activity.
Battle-card levels and achievement displays provide a progress view alongside operational metrics.

### Optional 2x4 assistance

2x4 can read bounded summaries, named files, and allowed log tails through a separate service token.
Chat can use the configured provider relay.
Call controls delegate to the selected OpenClaw or installed Hermes voice integration.

Takeover requires confirmation and an active lease for controlled actions.
Scope mutation approvals are denied during takeover.
Stand-down invalidates the active lease and returns the controller to standby.

**Components:** `boots/main.py`, `boots/telemetry.py`, `token_usage.py`, proxy modules, `takeover.py`, and the 2x4 plugins.

## Continue reading

Use the [Codex](codex.md) to follow the complete operating model.
Use [end-to-end flows](end-to-end.md) to inspect concrete transitions.
Use the [source map](source-map.md) to find the corresponding functions.
