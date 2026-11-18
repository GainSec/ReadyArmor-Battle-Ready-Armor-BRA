# Evidence pipeline

BRA connects findings to captured tool results through identifiers, artifact paths, and event records.
A capture identifier identifies one recorded tool output.

## Capture

`head/bra/hooks/post_hook.py` receives tool results.
It records the tool name, command context, session identifier, and available tool identifier.
It saves nonempty output under `body/.bra/artifacts/raw/`.

The evidence index is `body/.bra/logs/evidence_index.jsonl`.
Records include the capture identifier, artifact path, SHA-256 hash, source type, and creation time.
Additional fields can include a command, URL, method, host, or endpoint.

## Markers

The agent emits structured marker lines. `head/bra/core/markers.py` converts these lines into marker records.

```text
[FINDING] HIGH: Example finding | cvss: 7.5 | capture_id: cap_example
```

Other marker types include `SERVICE`, `ENDPOINT`, `TARGET`, and `LEAD`.
The runner resolves evidence references before it writes marker events.
An explicit capture identifier must resolve to recorded evidence.
The selection logic prefers an originating capture over a later inspection of that capture.

The event ledger is `body/.bra/logs/marker_events.jsonl`.
Its records provide input for note and finding generation.

## Finding processing

1. The runner parses a finding marker.
2. It resolves the capture and source artifact.
3. It records the marker event.
4. The finding enforcer adds the finding to the pending queue.
5. It creates a finding skeleton in `NOTES/FINDINGS.md`.
6. Materializers add evidence and reproduction information.
7. A documentation task supplies the remaining analysis fields.
8. The merger inserts the task output into the finding record.
9. Validation removes a complete finding from the pending queue.

The documentation task supplies CWE, description, impact, attack vector, remediation, and tool versions.
System-generated sections include the affected artifact, reproduction steps, proof of concept, and evidence.

## Evidence outputs

| Path within the engagement root | Contents |
| --- | --- |
| `.bra/artifacts/raw/` | Raw captures with privacy masking |
| `.bra/logs/evidence_index.jsonl` | Capture metadata and hashes |
| `.bra/logs/marker_events.jsonl` | Parsed marker events |
| `.bra/pending_findings.json` | Pending documentation queue |
| `layer3-engagement/NOTES/FINDINGS.md` | Finding records |
| `layer3-engagement/NOTES/reqs/` | Finding context and evidence support files |

## Review a finding

1. Open the finding in the interface.
2. Check its capture identifier.
3. Locate that identifier in the evidence index.
4. Open the referenced artifact.
5. Compare the artifact with the reproduction steps.
6. Check the finding description and impact.
7. Resolve missing fields before report preparation.

The API reads findings from the engagement records. Browser events report updates from the runner.
