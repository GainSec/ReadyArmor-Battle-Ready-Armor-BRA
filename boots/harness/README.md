# Finding harnesses

The finding harnesses inspect prompts and exercise documentation tasks outside the full engagement queue.
They use the same agent request components as Boots.

## Inspect a prompt

Run this command from the repository root.

```bash
PYTHONPATH=head:boots:. python -m boots.harness.findings_flow   --bra-root body --finding-id 001 --prompt-only
```

The selected finding must exist in the engagement records.
The inspection option prints the effective prompt without a model request.

## Execute a documentation task

```bash
PYTHONPATH=head:boots:. python -m boots.harness.findings_flow   --bra-root body --finding-id 001 --show-events
```

The task uses the configured model connection.
Agent text goes to standard output. Event information goes to standard error.
The harness validates the resulting finding record.

## Options

| Option | Function |
| --- | --- |
| `--bra-root PATH` | Select the engagement root; default `body`. |
| `--finding-id ID` | Select the finding identifier. |
| `--user-prompt TEXT` | Replace the deferred request. |
| `--prompt-only` | Print the prompt without model execution. |
| `--show-events` | Print streaming event types. |
| `--save-output PATH` | Select the output file. |

The default output is `boots/harness/output/finding-ID-output.md`.
This harness covers prompt construction and tool restrictions.
The full runner manages queue reconciliation, progress callbacks, and browser events.
