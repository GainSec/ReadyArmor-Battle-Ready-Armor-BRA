#!/usr/bin/env python3
"""Set up NER harness: create venv, install deps, print run command.

Usage:
    python setup_ner_harness.py
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VENV = HERE / ".ner-venv"
HF_CACHE = VENV / ".hf-cache"
HARNESS = HERE / "ner_harness.py"


def run(cmd: list[str], **kwargs) -> None:
    print(f"  $ {' '.join(cmd)}")
    subprocess.check_call(cmd, **kwargs)


def main() -> None:
    print(f"Setting up NER harness venv at {VENV}\n")

    # Create venv
    if not VENV.exists():
        run([sys.executable, "-m", "venv", str(VENV)])
    else:
        print(f"  venv already exists at {VENV}")

    pip = str(VENV / "bin" / "pip")
    python = str(VENV / "bin" / "python")

    # Install deps
    print()
    run([pip, "install", "--upgrade", "pip", "-q"])
    run([pip, "install", "spacy", "transformers", "torch", "fastapi", "uvicorn", "requests", "-q"])

    # Download spaCy model
    print()
    run([python, "-m", "spacy", "download", "en_core_web_sm", "-q"])

    # Write activation wrapper that sets HF_HOME
    wrapper = VENV / "bin" / "ner"
    wrapper.write_text(
        f"#!/bin/sh\nexport HF_HOME=\"{HF_CACHE}\"\nexec \"{python}\" \"{HARNESS}\" \"$@\"\n"
    )
    wrapper.chmod(0o755)

    # Done
    print("\n" + "=" * 60)
    print("Setup complete. All models stored inside the venv:")
    print(f"  spaCy:           {VENV}/lib/...")
    print(f"  SecBERT + CyNER: {HF_CACHE}/ (download on first use, ~400MB each)")
    print(f"\nDelete {VENV} to remove everything.")
    print("=" * 60)
    ner = str(wrapper)
    print(f"\nRun commands:\n")
    print(f"  # Check installed models")
    print(f"  {ner} models\n")
    print(f"  # A/B/C compare (sample texts)")
    print(f"  {ner} compare\n")
    print(f"  # A/B/C compare (custom text)")
    print(f"  {ner} compare \"Scan 192.168.18.9 owned by Acme Corp\"\n")
    print(f"  # Start BRA-compatible NER server")
    print(f"  {ner} serve --port 8100\n")


if __name__ == "__main__":
    main()
