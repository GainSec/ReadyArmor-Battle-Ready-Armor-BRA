# Installation

## Requirements

BRA requires Python 3.10 or later, pip, and the Python venv module.
The web launcher installs FastAPI, Uvicorn, and the `bra` package. The package includes the Claude Agent SDK and LiteLLM.
A model connection is required for agent requests. Analysis tools depend on the selected assessment method.

## Automatic installation

Run these commands from the repository root.

1. Start the launcher.

   ```bash
   python3 boots/gui.py --host 127.0.0.1 --port 9999
   ```

2. Wait for dependency installation to finish.
3. Open `http://127.0.0.1:9999`.
4. Enter the terminal access token.
5. Open Settings.
6. Enter the model connection details.

The launcher uses `body/` as the engagement root. It passes the repository and `head/` paths to the server.

## Manual installation

1. Create a virtual environment.

   ```bash
   python3 -m venv .venv
   ```

2. Activate the environment.

   ```bash
   . .venv/bin/activate
   ```

3. Install the web dependencies.

   ```bash
   python -m pip install -r boots/requirements.txt
   ```

4. Install the Python package.

   ```bash
   python -m pip install -e head
   ```

5. Prepare the engagement directories.

   ```bash
   python body/layer1/scripts/precheck.py --structure
   ```

6. Start the server.

   ```bash
   PYTHONPATH=head:. python -m boots.main --bra-dir body --host 127.0.0.1 --port 9999
   ```

## Launch options

| Option | Function |
| --- | --- |
| `--host ADDRESS` | Select the listening address. |
| `--port NUMBER` | Select the listening port. |
| `--bra-dir PATH` | Select the engagement root. |
| `--ner` | Enable named entity recognition for privacy detection. |
| `--no-auth` | Disable token authentication. |
| `--help` | Show launcher help. |

The built-in host default is `127.0.0.1`.
Use `BRA_GUI_HOST` or `--host` to select another listening address.
The default port is `9999`.
The NER option can download a model of approximately 1.6 GB on first use.

## Readiness checks

1. Show the readiness options.

   ```bash
   python body/layer1/scripts/precheck.py --help
   ```

2. Examine the environment without changes.

   ```bash
   python body/layer1/scripts/precheck.py --check-only
   ```

3. Read `body/.bra/PRECHECK_REPORT.md` after a full readiness check.
4. Install the tools required by the selected method.

A readiness result of `0` indicates success. Result `1` indicates unresolved checks.
Result `2` indicates issues in check-only mode.
