# Development

## Source layout

| Path | Function |
| --- | --- |
| `boots/main.py` | FastAPI routes and server startup |
| `boots/engage.py` | Engagement requests and browser events |
| `boots/takeover.py` | Takeover state and leases |
| `head/bra/core/` | Agent runner, markers, evidence, and finding validation |
| `head/bra/hooks/` | SDK tool adapters |
| `head/bra/anon/` | Detection, mapping, and report conversion |
| `head/bra/proxy/` | LiteLLM configuration and process control |
| `body/layer1/hooks/` | Policy scripts |
| `body/layer1/scripts/` | Operational scripts |
| `tests/` | Integration and regression checks |

## Install development dependencies

1. Complete the [manual installation](installation.md#manual-installation).
2. Install the check dependencies.

   ```bash
   python -m pip install pytest cryptography
   ```

## Do the checks

Run commands from the repository root.

1. Do the launcher checks.

   ```bash
   PYTHONPATH=head:. python -m pytest -q tests/test_boots_python_launchers.py
   ```

2. Do the governance and privacy checks.

   ```bash
   PYTHONPATH=head:. python -m pytest -q      tests/test_file_guard_python_native.py      tests/test_bash_guard_python_native.py      tests/test_engage_anon_runtime.py      tests/test_main_anon_runtime.py      tests/test_post_hook_anon_masking.py      head/bra/anon/tests/test_rehydrate.py
   ```

3. Do the proxy checks.

   ```bash
   PYTHONPATH=head:. python -m pytest -q      tests/test_proxy_settings.py tests/test_proxy_config.py tests/test_proxy_token_budget.py
   ```

4. Do all repository checks when changing shared runtime behavior.

   ```bash
   PYTHONPATH=head:. python -m pytest -q tests head/bra/anon/tests
   ```

Some harnesses make model requests when used without their inspection options.
Use `--help` to select the required harness mode.
The [harness guide](../boots/harness/README.md) describes finding prompt inspection.

## Change governance

1. Identify the policy script and its SDK adapter.
2. Add a regression case for the required decision.
3. Keep the JSON decision fields stable.
4. Do the checks for both the script and adapter.
5. Check that transport errors produce the intended decision.

Store captured tool output under `.bra/artifacts/`.
Use temporary engagement directories for checks that create state.

## Documentation terms

Use the product terms in the [term list](terms.md).
Write one action in each procedure step.
Keep procedure sentences at 20 words or fewer.
Keep descriptive sentences at 25 words or fewer.
Use complete sentences and the active voice.
Keep identifiers, API routes, and command syntax unchanged.
