# integrate-ingest.py

## Purpose

The script combines ingested project references and applies redaction rules.
It reads `layer3-engagement/ingest/*/` and writes reusable tool, method, skill, and workflow references.
Run the commands below from `body/`.

## Location

`layer1/scripts/integrate-ingest.py`

## Usage

```bash
python3 layer1/scripts/integrate-ingest.py                    # Run full integration
python3 layer1/scripts/integrate-ingest.py --dry-run          # Preview without writing files
python3 layer1/scripts/integrate-ingest.py --output-dir DIR   # Custom output directory
python3 layer1/scripts/integrate-ingest.py --verbose          # Detailed output
python3 layer1/scripts/integrate-ingest.py --help             # Show help
```

## Dependencies

### Sources
Python standard library modules only.

### Calls
The script writes reference files; it does not execute analysis tools.

### Called By
- Manual invocation after ingestion complete
- `remote-ingest.py` workflow (user-initiated followup)

### Data Sources (Read Only)

| File Pattern | Purpose |
|--------------|---------|
| `layer3-engagement/ingest/*/tools.md` | Tools from each ingested project |
| `layer3-engagement/ingest/*/skills.md` | Skills from each ingested project |
| `layer3-engagement/ingest/*/methodologies.md` | Methodologies from each project |
| `layer3-engagement/ingest/*/workflows.md` | Workflows from each project |

### Output Files

| File | Purpose |
|------|---------|
| `layer2-templates/reference/integrated/tools-integrated.md` | Aggregated tools reference |
| `layer2-templates/reference/integrated/skills-integrated.md` | Aggregated skills reference |
| `layer2-templates/reference/integrated/methodologies-integrated.md` | Aggregated methodologies |
| `layer2-templates/reference/integrated/workflows-integrated.md` | Aggregated workflows |
| `layer2-templates/reference/integrated/INTEGRATION-SUMMARY.md` | Integration run summary |

## Functions

| Function | Purpose |
| --- | --- |
| `_body_root()` | Resolve the engagement root. |
| `_resolve_under_root()` | Keep output paths inside the body root. |
| `_redact()` | Replace identifiers with generic values. |
| `_collect_projects()` | List ingested project directories. |
| `_integrate_file()` | Combine and redact selected source files. |
| `_write_summary()` | Process the corresponding integration data. |
| `_parse_args()` | Process the corresponding integration data. |
| `main()` | Parse options and execute integration. |

## Redaction Rules

### Auto-Redacted Patterns

| Category | Pattern | Replacement |
|----------|---------|-------------|
| Project names | Folder names from `layer3-engagement/ingest/` | `[PROJECT]` |
| User paths | `/Users/name/`, `/home/name/` | `/Users/[USER]/`, `/home/[USER]/` |
| IP addresses | Private IPv4 addresses in the supported ranges | `[INTERNAL_IP]` |
| Serial numbers | Supported device serial pattern | `[DEVICE_SERIAL]` |
| API keys | `sk-*`, `api_key=*` | `[API_KEY]` |
| Credentials | `password: "*"` | `password: "[REDACTED]"` |

### Named Replacements

Review the output for identifiers outside these patterns. Project folder names supply the project-name replacements.
The implementation preserves generic tool names and assessment techniques.

Additional generic labels can include:
- Company names → `[TARGET]`, `[VENDOR]`
- Product names → `[DEVICE]`, `[APP_COMPONENT]`
- Service names → `[SERVICE]`, `[API]`
- Framework names → `[FRAMEWORK]`, `[TOOL_FRAMEWORK]`

## Workflow Position

```
[Ingest] → [integrate-ingest.py] → [dedupe-integrated.py] → [Approval]
              ↑ YOU ARE HERE
```

This script is the second step after ingestion, preparing content for deduplication.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (missing directories, invalid options) |

## Example Output

```
[INFO] Starting integration with redaction...
[INFO]   Ingest dir: /path/to/layer3-engagement/ingest
[INFO]   Output dir: /path/to/layer2-templates/reference/integrated
[INFO] Found 12 project directories for redaction
[INFO] Processing tools...
[INFO]   Aggregated 523 tool entries from 8 projects
[INFO] Processing methodologies...
[INFO]   Aggregated 156 methodology entries from 6 projects
[INFO] Processing skills...
[INFO]   Aggregated 289 skill entries from 7 projects
[INFO] Processing workflows...
[INFO]   Aggregated 98 workflow entries from 5 projects
[INFO] Integration complete.
```

## Related Scripts

| Script | Purpose |
|--------|---------|
| `remote-ingest.py` | Mount remote filesystems for ingestion |
| `dedupe-integrated.py` | Deduplicate integrated content against master TOCs |
| `approval-gate.py` | Manage pitch approval workflow |

## See Also

- Implementation: `layer1/scripts/integrate-ingest.py`
- Deduplication implementation: `layer1/scripts/dedupe-integrated.py`
