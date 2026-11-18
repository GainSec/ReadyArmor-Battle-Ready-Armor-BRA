# OpenClaw 2x4 control plugin

This plugin connects OpenClaw tools to the bounded BRA control API.

## Configuration

Set `bootsBaseUrl` to the Boots server URL.
Set `bootsServiceToken` to the dedicated 2x4 service token.

The plugin sends the service token as a bearer token.
Takeover actions also require `takeoverLeaseId`, sent in `x-2x4-lease-id`.

## Commands

```text
/bra summary
/bra explain 200
/bra file scope
/bra log engage 200
/bra engage status
/bra call status call-123
/bra stand down
```

The primary tool is `bra_2x4_control`. The `bra` alias accepts command text.

## Gateway methods

| Method | Function |
| --- | --- |
| `bra2x4.summary` | Read the engagement summary. |
| `bra2x4.file` | Read an allowed file identifier. |
| `bra2x4.log` | Read an allowed log tail. |
| `bra2x4.engage_status` | Read engagement status. |
| `bra2x4.engage_action` | Request an engagement action. |
| `bra2x4.call_continue` | Continue a call. |
| `bra2x4.call_speak` | Send call speech. |
| `bra2x4.call_status` | Read call status. |
| `bra2x4.call_stop` | End a call. |
| `bra2x4.takeover_confirm` | Confirm takeover. |
| `bra2x4.stand_down` | End takeover. |

File and log requests accept listed identifiers instead of unrestricted paths.
Read the [integration guide](../../docs/2x4.md) for routes and lease behavior.
