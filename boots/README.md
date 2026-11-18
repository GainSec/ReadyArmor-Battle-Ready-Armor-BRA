# Boots web interface

Boots supplies the browser interface and HTTP API for Battle Ready Armor.
It displays scope, findings, artifacts, logs, and engagement progress.

## Start

Run this command from the repository root.

```bash
python3 boots/gui.py --host 127.0.0.1 --port 9999
```

The launcher creates its virtual environment and installs dependencies on first use.
Open `http://127.0.0.1:9999`. Enter the token shown in the terminal.

Use `python3 boots/gui.py --help` to show launch options.
Use `python3 boots/gui-debug.py --help` to show debug launch options.

## Documentation

- [Installation](../docs/installation.md)
- [Operation](../docs/operation.md)
- [API reference](../docs/api.md)
- [2x4 connection](../docs/2x4.md)
- [Troubleshooting](../docs/troubleshooting.md)

The server supplies interactive API documentation at `/docs`.
The default engagement root is the repository `body/` directory.
