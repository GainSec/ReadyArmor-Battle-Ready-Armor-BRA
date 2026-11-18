# BRA interfaces

BRA separates the assessment workspace from the surface used to inspect or operate it.
Use the browser for live engagement work and approvals.
Use explicit terminal commands for named management routines.
Use the authenticated APIs for supported integrations, and 2x4 for bounded external assistance.

## Choose a surface

| Surface | Primary use | Can drive work? | State and authority |
| --- | --- | --- | --- |
| Boots browser | Scope intake, live work, evidence, reporting, and growth review | Yes, through the engagement router | Current Boots state and configured workspace |
| Terminal commands | Status, readiness, permissions, and Body management routines | Yes, through the named routine | Host operator permissions and configured Body root |
| Browser terminal | Observe or operate a host terminal from Debug | Yes, through trusted shell input | Debug access for management routes; separate terminal connection |
| Manager dashboard | Portfolio review | Observation | GUI-authenticated portfolio API and configured snapshot |
| HTTP API | Records, configuration, proposal decisions, and selected management functions | On its supported mutation routes | GUI authentication and route-specific conditions |
| Engagement WebSocket | Live agent messages and decisions | Yes | GUI authentication and the shared engagement manager |
| Log WebSocket | Live log output | Observation | GUI authentication |
| 2x4 chat | Discussion with a configured companion assistant | Chat; takeover is a separate path | Browser authentication and configured upstream credentials |
| 2x4 control API | Named documents, status, and supported actions | With an active lease where required | Dedicated service authentication and takeover state |
| Voice plugin | Calls, spoken results, and supported control requests | For defined actions | Provider configuration, service credentials, and applicable leases |

## Boots browser

Run the launcher from the repository root:

```bash
python3 boots/gui.py --host 127.0.0.1 --port 9999
```

Open `http://127.0.0.1:9999` and enter the access token displayed by the server.
The [installation guide](installation.md) covers dependency installation and manual startup.

The browser can:

- Define scope and configuration.
- Start or resume the agent through the engagement manager.
- Send instructions, select offered options, and resolve approval cards.
- Pause, stop, or activate the kill switch.
- Inspect intelligence, leads, findings, captures, reports, and logs.
- Review improvement proposals and their selected dispositions.

The browser uses HTTP for records and configuration.
It uses `/ws/engage` for live engagement messages and events.
The same server can send state and events to connected browser clients.
A reconnect receives a current snapshot and replayable history.

The [screenshots](screenshots.md) show desktop and mobile browser layouts.
These layouts use the same Boots application and configured engagement.

Sources: [launcher](../boots/gui.py), [server](../boots/main.py), [engagement manager](../boots/engage.py).

## Terminal command interface

Install the Head package in the Python environment used for these commands:

```bash
python -m pip install -e head
```

The package provides the `bra` command.
`python -m bra` invokes the same command application.
Use an explicit command:

```bash
bra --help
bra status
bra tokens list
```

The following names connect to specific Body routines:

| Command | Operation |
| --- | --- |
| `bra status` | Detect session state and show the status routine output. |
| `bra precheck` | Run the readiness routine. |
| `bra audit` | Run the project audit routine. |
| `bra backup` | Invoke the selected backup operation. |
| `bra lessons` | Run the lessons procedure. |
| `bra growth` | Generate engagement growth proposals. |
| `bra disclose` | Invoke the disclosure procedure with its applicable conditions. |
| `bra packup` | Invoke engagement packaging. |

The CLI resolves its Body root through Head settings.
The script bridge runs the selected Python routine with that Body directory as its working directory.
Confirm that configuration before using a management command against an existing engagement.

These commands run as the local host operator.
They can read or change the state owned by their selected routine.
They do not route every management action through the browser or the SDK tool hook.
The invoked routine supplies its own prerequisites and decisions.

Sources: [package entrypoint](../head/pyproject.toml), [CLI](../head/bra/cli.py), [script bridge](../head/bra/core/bridge.py), [root settings](../head/bra/config/settings.py).

## Browser terminal

The Debug panel contains a terminal view backed by `tmux` and `ttyd`.
Install both tools on the Boots host before using this surface.
Open Debug, complete its configured authentication, then select an existing tmux session or create one.
Start the view to attach `ttyd` to that session.

The view starts read-only by default.
Clear **Read-only** before startup to enable direct terminal input.
The terminal iframe connects separately to the returned `ttyd` port, initially 7681 when available.
Boots authenticates the management routes; the terminal connection has its own network endpoint.

The management routes can list, create, attach, stop, scroll, or kill the selected terminal resources.
The send route passes text and an optional Enter key to the active tmux session.
Its shell commands run as the host operator, outside the managed SDK tool path.
The view's read-only setting controls `ttyd` input; it does not disable the separate send route.
Use this surface for trusted host administration and direct tool work.

All `/api/live/*` management routes require GUI authentication and the Debug session when Debug authentication is enabled.
The available routes are `status`, `start`, `stop`, `spawn`, `kill`, `scroll`, and `send`.
Read [the API reference](api.md) for their request fields.

Sources: [terminal routes](../boots/main.py#L3789), [Debug terminal controls](../boots/static/index.html#L5672).

## Manager dashboard

Open `/manager` on the Boots server for portfolio review.
The dashboard reads `/api/manager/portfolio` with GUI authentication.
Its engagement list comes from `body/layer4-telemetry/manager_portfolio.json` when that file supplies valid data.
The handler also supplies a stable fallback structure for the current BRA engagement.
This surface presents portfolio information; use the main browser for engagement actions and approvals.

Sources: [dashboard](../boots/static/manager.html), [portfolio handler](../boots/main.py#L6530).

## HTTP API

Boots exposes records and management routes under `/api/`.
Normal server startup enables GUI token authentication.
Clients can supply the token in an `Authorization: Bearer` header.
The browser can also use its authenticated cookie.

For a client shell, set `BRA_GUI_TOKEN` to the current server access token.
The variable below is a client-side example; it is not a server configuration field.

```bash
curl -H "Authorization: Bearer ${BRA_GUI_TOKEN}" \
  http://127.0.0.1:9999/api/engage/state
```

Use read routes for current configuration, engagement documents, records, and status.
Supported mutation routes handle their declared configuration, proposal, approval, or management operation.
Use the [API reference](api.md) to select the required route and handler.

The explicit `--no-auth` server option disables general GUI token checks.
The dedicated 2x4 service-token dependency remains separate.

Source: [request authentication and route handlers](../boots/main.py).

## Live WebSocket API

`/ws/engage` connects a client to the shared engagement manager.
It sends the current state after connection, then replayable history and live events.
Incoming messages go to the same router used by the browser.

| Message family | Examples | Role |
| --- | --- | --- |
| Agent lifecycle | `start`, `resume`, `pause`, `stop`, `kill` | Control the managed agent session. |
| Investigation input | `continue`, `select`, `select_with_message` | Continue work or select an offered path. |
| Pending decisions | `approve_tool`, `approve_script`, `approve_token` | Resolve the relevant pending request. |
| Scope decisions | `approve_scope_add`, `approve_scope_upgrade` | Request the matching operator scope decision. |
| Connection keepalive | `ping` | Receive `pong`. |

The router interprets each message and calls its specific manager method.
A message name does not authorize an unrelated operation.
The active SDK tool path retains its registered policy hooks.

`/ws/logs` supplies live log output rather than agent control.
WebSocket authentication checks a Bearer header, the GUI cookie, then the optional token query parameter.
Use credentials from the running server rather than a bundled default.

Sources: [WebSocket handlers](../boots/main.py), [message router](../boots/engage.py).

## Companion assistant chat

The browser's 2x4 chat connection reaches `/ws/chat/numbuh_2x4` on Boots.
Boots then uses the selected upstream provider:

| Provider | Upstream connection | Configuration role |
| --- | --- | --- |
| OpenClaw | Gateway WebSocket and protocol handshake | Upstream address and gateway token |
| Hermes | OpenAI-compatible HTTP chat request | Service address, session key, and optional API key |

This companion provider is separate from the main assessment runtime.
The main assessment still uses the Claude Agent SDK and its configured model route.
Changing the companion provider does not replace that SDK.

The companion can discuss status and context.
Its ability to operate the engagement comes from the separate control endpoints and takeover rules.
Read [2x4 integration](2x4.md) for provider fields and fallback behavior.

Source: [Boots chat relay and Hermes request builder](../boots/main.py).

## Bounded control and phone access

The 2x4 control API requires a dedicated service token.
Boots generates or loads that token at runtime.
Configure the control client with the matching value.
It has a different role from the GUI token and the upstream assistant credential.

The named document identifiers are `scope`, `stats`, `report`, `findings`, and `precheck`.
The named log identifier is `engage`.
These routes select bounded resources rather than accepting an arbitrary filesystem path.

Supported engagement actions require the active takeover lease where specified.
Confirmation must arrive within 15 seconds. The active lease lasts 30 seconds.
Expiry or stand-down invalidates it.
The action mapper supports continuation, option selection, and specified approval decisions.
It maps scope-add and scope-upgrade approvals to denial during active takeover.

The voice integration can initiate, continue, speak into, inspect, or stop a configured call.
The bundled voice plugin supports Twilio, Telnyx, Plivo, and a local mock provider.
Provider setup supplies credentials, callback reachability, and speech or media behavior.
OpenClaw calls use its installed gateway and plugin.
The Hermes call path loads the corresponding plugin from the configured Hermes installation.

Phone and assistant controls use these declared actions and resources.
They do not expose a general shell through the 2x4 control API.
Use the [2x4 guide](2x4.md) for the route list and takeover procedure.

Sources: [control plugin](../2x4/openclaw-2x4-control-dev/index.ts), [voice plugin](../2x4/openclaw-2x4-voice-call-bra-dev/index.ts), [lease controller](../boots/takeover.py), [service routes](../boots/main.py).

## Handoff and shared state

Point each surface at the intended Boots server or configured Body workspace.
Browser clients connected to the same server share its current engagement state.
A terminal command reads the workspace selected by Head settings.
The engagement manager aligns Head settings with the browser-selected root before routed work.

The workspace retains scope, findings, evidence, reports, and reviewed knowledge.
The running Boots process retains its current clients, pending decisions, and takeover lease state.
A browser reconnect can recover that server state; an SDK resume uses the selected session identifier.
These records and mechanisms give the next operator an explicit account of the work to continue.

Use the browser for the active engagement and its approval cards.
Use terminal commands for their named management functions.
Use service clients for the resources and actions their credentials permit.
Interface choice changes the connection and available actions; it does not erase the applicable record or permission checks.
