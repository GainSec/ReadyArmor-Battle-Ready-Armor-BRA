# Governance layer

Layer 1 contains the policy rules and operational scripts for Battle Ready Armor.
The file guard blocks agent changes to this directory during an engagement.

| Directory | Contents |
| --- | --- |
| `rules/` | Scope, approval, engagement, and reporting rules |
| `hooks/` | File, command, reminder, and capture policy entry points |
| `scripts/` | Readiness, scope, approval, backup, report, and lifecycle commands |
| `lib/` | Shared token, target, phase, method, and state functions |

## Readiness check

Run this command from the repository root.

```bash
python body/layer1/scripts/precheck.py --check-only
```

Use `--structure` to create missing engagement directories and document skeletons.
Use `--tools` to examine tool availability.

## Policy interface

SDK adapters call the body policy scripts with normalized requests.
The file guard returns `decision`, `reason`, `policy`, and optional `meta` fields.

Read the [governance guide](../../docs/governance.md) for permissions and storage rules.
Read the [architecture guide](../../docs/architecture.md) for adapter and policy responsibilities.
