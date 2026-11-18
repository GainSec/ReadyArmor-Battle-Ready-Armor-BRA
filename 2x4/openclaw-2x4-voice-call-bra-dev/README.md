# BRA voice call plugin

The BRA voice plugin supplies telephony tools and gateway methods for OpenClaw.
It supports Twilio, Telnyx, Plivo, and a local `mock` provider.

## Install the local plugin

Run this command from the BRA repository root.

```bash
openclaw plugins install ./2x4/openclaw-2x4-voice-call-bra-dev
```

Restart the OpenClaw gateway after plugin installation.

## Configure the provider

Set the plugin provider and telephone numbers in the gateway plugin configuration.
Use `provider: "mock"` for local development without telephone calls.

| Setting | Function |
| --- | --- |
| `provider` | Select `twilio`, `telnyx`, `plivo`, or `mock`. |
| `fromNumber` | Set the outgoing telephone number. |
| `toNumber` | Set the default destination. |
| `twilio.accountSid` | Supply the Twilio account identifier. |
| `twilio.authToken` | Supply the Twilio access token. |
| `telnyx.apiKey` | Supply the Telnyx access key. |
| `telnyx.connectionId` | Select the Telnyx connection. |
| `telnyx.publicKey` | Supply the Telnyx webhook verification key. |
| `plivo.authId` | Supply the Plivo account identifier. |
| `plivo.authToken` | Supply the Plivo access token. |
| `serve.port` | Set the webhook server port. |
| `serve.path` | Set the webhook path. |
| `publicUrl` | Set the public callback URL. |

The default webhook path is `/voice/webhook`.
Twilio, Telnyx, and Plivo require a reachable public callback URL.
The plugin verifies webhook signatures and applies replay controls.

## Call commands

```bash
openclaw voicecall-bra call --to "+15555550123" --message "Assessment status is available."
openclaw voicecall-bra status --call-id CALL_ID
openclaw voicecall-bra end --call-id CALL_ID
```

Chat commands include `/call-bra`, `/callme-bra`, `/call-bra summary`, and `/call-bra stand down`.
The primary tool is `voice_call_bra`. Its alias is `voice_call_bra_alias`.
Gateway methods include `voicecall_bra.initiate`, `.continue`, `.speak`, `.end`, and `.status`.

## Streaming

`streaming.enabled` enables the media stream path.
`streaming.preStartTimeoutMs` limits the wait for a valid start frame.
Connection limits apply globally and per source IP.

The plugin uses core speech configuration for streaming output.
Plugin `tts` settings override corresponding core settings.
Twilio streaming requires WebSocket support and the configured speech provider credentials.

`staleCallReaperSeconds` ends calls that have no terminal callback.
The default is `0`, which disables the reaper.
Set its value above `maxDurationSeconds` when the reaper is required.

## Development checks

1. Install the plugin dependencies.

   ```bash
   npm install
   ```

2. Do the unit checks.

   ```bash
   npm test
   ```

Read the [BRA integration guide](../../docs/2x4.md) for control permissions and takeover leases.
