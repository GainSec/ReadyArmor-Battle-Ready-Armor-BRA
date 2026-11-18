# Privacy

Masking replaces a sensitive value with a word alias. Rehydration replaces that alias with its original value.
The local mapping file connects each alias to its original value.

## Data path

1. Detection identifies sensitive values in scope or chat input.
2. BRA applies the selected privacy mode.
3. Approved mappings replace sensitive values before model requests.
4. The model receives aliases in governed content.
5. The command guard resolves aliases for approved local execution.
6. Captured output is masked before it returns to the model.
7. Operator views can display the original values.

The mapping file is `body/.bra/anon_map.json`.
Regex detection covers IP addresses, CIDR ranges, MAC addresses, and selected credential patterns.
Optional named entity recognition supplies additional detection proposals.

## Privacy modes

| Token | Function |
| --- | --- |
| `MAP-SCAN` | Mask values already present in the map. |
| `ANON-SCAN` | Detect new values and request approval in the engagement runtime. |
| `NO-SCAN` | Send chat content without scan masking. |
| `ANON-DISABLE` | Disable privacy transformations. |
| `DUMB-SCOPE` | Review regex detections and apply approved mappings to scope. |
| `FRONTIER-SCOPE` | Use raw scope for model-assisted scope work. |
| `MICRO-SCOPE` | Use the NER scope path enabled with `--ner`. |
| `NO-SCOPE` | Use raw scope. |

The runtime rejects `LOCAL-SCOPE` and `LOCAL-SCAN` as unavailable.
For chat, `ANON-SCAN` uses regex detection for new mapping proposals.
Scope detection can also use the local NER path when enabled.

## Masked targets

A masked target remains a known target throughout the engagement.
Use the recorded alias directly in commands, such as `curl http://alias/`.
Do not perform address discovery only because scope contains a word alias.
The local guard substitutes the original address after evaluating the original command.
The native target extractor can return no target for a word-only alias.
The intercept does not repeat target validation after substitution.
Read [Control in Depth](control-in-depth.md#target-validation-uses-concrete-extraction-rules) for exact scope matching and precedence.

For alias commands, the guard executes the substituted command and saves masked output.
It blocks the original SDK invocation and returns a masked preview instead.

## Final report conversion

Run this procedure as the operator, outside the agent session.

1. Open a terminal at the repository root.
2. Activate the installed Python environment.
3. Convert the report to a separate output file.

   ```bash
   python -m bra.anon.rehydrate      --map body/.bra/anon_map.json      --input body/layer3-engagement/REPORT.md      --output body/layer3-engagement/REPORT-FINAL.md
   ```

4. Review the converted report.
5. Apply the engagement data handling rules to the output.

The conversion utility reads the local map directly.
Keep it outside the agent tool path. The original masked report remains available for comparison.
