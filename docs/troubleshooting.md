# Troubleshooting

## Server does not start

1. Run `python3 boots/gui.py --help`.
2. Check that Python 3.10 or later is available.
3. Check the installation output for dependency errors.
4. Check that the selected address exists on this computer.
5. Select an available port.

The launcher uses a fixed LAN address by default.
Use `--host 127.0.0.1` for a local installation.

## Authentication fails

1. Use the access token from the current server startup.
2. Check that the browser points to the correct server.
3. Enter the token again.

Browser access and 2x4 service access use different tokens.
The API accepts a bearer token. The browser also uses its configured session cookies.

## Engagement is not ready

1. Run the readiness check.

   ```bash
   python body/layer1/scripts/precheck.py --check-only
   ```

2. Read `body/.bra/PRECHECK_REPORT.md` if present.
3. Complete the scope fields in the interface.
4. Install the tools required by the selected method.
5. Run the full readiness check again.

## Command is denied

1. Read the returned policy identifier and reason.
2. Check the active assessment mode.
3. Check the target against scope.
4. Check the requested output path.
5. Use the operator interface to review the required approval.

A tool approval does not grant target access. A target approval does not grant destructive-operation permission.

## Agent requests an address already present in scope

1. Check the masked scope target.
2. Check the alias in the operator privacy view.
3. Confirm that the engagement instructions identify aliases as known targets.
4. Use the alias directly in the permitted command.

The command guard resolves aliases locally. Address discovery is unnecessary when scope already supplies the target alias.

## Finding remains pending

1. Open the finding record.
2. Check its required fields.
3. Check the referenced capture identifier.
4. Check the evidence artifact.
5. Examine the finding context under `layer3-engagement/NOTES/reqs/`.
6. Complete the missing documentation through the engagement workflow.

## Proxy request exceeds model limits

1. Open the Proxy Router settings.
2. Check the backend model mapping.
3. Set the correct context limit.
4. Reduce the completion limit if required.
5. Examine the proxy status.

The completion limit is fixed. It does not automatically subtract the prompt length from the context limit.

## 2x4 relay fails

1. Check the provider selection.
2. Check the upstream URL.
3. Check the server-side provider token.
4. Check the gateway connection.
5. Examine the legacy chat queue if the interface selects it.

For denied takeover actions, check the lease identifier and its expiry.
