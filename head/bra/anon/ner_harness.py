#!/usr/bin/env python3
"""NER model harness — runs spaCy, SecBERT, and CyNER side-by-side.

Provides two modes:

  1. A/B/C comparison (CLI):
     python ner_harness.py compare "Scan 192.168.18.9 owned by Acme Corp, contact admin@acme.com"

  2. BRA-compatible NER endpoint (server):
     python ner_harness.py serve [--port 8100] [--model spacy|secbert|cyner|all]

     POST /ner          — standard BRA endpoint (uses selected model)
     POST /ner/compare  — returns all 3 models' results side-by-side
     GET  /ner/models   — list loaded models and status

Setup:
  pip install spacy transformers torch fastapi uvicorn
  python -m spacy download en_core_web_sm

  SecBERT and CyNER download automatically from HuggingFace on first use (~400MB each).
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass, asdict
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Entity:
    text: str
    label: str
    start: int
    end: int
    model: str


# ---------------------------------------------------------------------------
# Model loaders (lazy — only load when first called)
# ---------------------------------------------------------------------------

_spacy_nlp = None
_secbert_pipeline = None
_cyner_pipeline = None


def _load_spacy():
    global _spacy_nlp
    if _spacy_nlp is not None:
        return _spacy_nlp
    try:
        import spacy
        _spacy_nlp = spacy.load("en_core_web_sm")
        logger.info("spaCy en_core_web_sm loaded")
    except Exception as e:
        logger.warning(f"spaCy not available: {e}")
        _spacy_nlp = False
    return _spacy_nlp


def _load_secbert():
    global _secbert_pipeline
    if _secbert_pipeline is not None:
        return _secbert_pipeline
    try:
        from transformers import pipeline
        _secbert_pipeline = pipeline(
            "ner",
            model="jackaduma/SecBERT",
            aggregation_strategy="simple",
        )
        logger.info("SecBERT loaded")
    except Exception as e:
        logger.warning(f"SecBERT not available: {e}")
        _secbert_pipeline = False
    return _secbert_pipeline


def _load_cyner():
    global _cyner_pipeline
    if _cyner_pipeline is not None:
        return _cyner_pipeline
    try:
        from transformers import pipeline
        _cyner_pipeline = pipeline(
            "ner",
            model="aiforsec/CyNER",
            aggregation_strategy="simple",
        )
        logger.info("CyNER loaded")
    except Exception as e:
        logger.warning(f"CyNER not available: {e}")
        _cyner_pipeline = False
    return _cyner_pipeline


# ---------------------------------------------------------------------------
# Detection runners
# ---------------------------------------------------------------------------

def _run_spacy(text: str) -> list[Entity]:
    nlp = _load_spacy()
    if not nlp:
        return []
    doc = nlp(text)
    return [
        Entity(
            text=ent.text,
            label=ent.label_,
            start=ent.start_char,
            end=ent.end_char,
            model="spacy",
        )
        for ent in doc.ents
    ]


def _run_secbert(text: str) -> list[Entity]:
    pipe = _load_secbert()
    if not pipe:
        return []
    results = pipe(text)
    return [
        Entity(
            text=r.get("word", ""),
            label=r.get("entity_group", r.get("entity", "")),
            start=r.get("start", 0),
            end=r.get("end", 0),
            model="secbert",
        )
        for r in results
    ]


def _run_cyner(text: str) -> list[Entity]:
    pipe = _load_cyner()
    if not pipe:
        return []
    results = pipe(text)
    return [
        Entity(
            text=r.get("word", ""),
            label=r.get("entity_group", r.get("entity", "")),
            start=r.get("start", 0),
            end=r.get("end", 0),
            model="cyner",
        )
        for r in results
    ]


_RUNNERS = {
    "spacy": _run_spacy,
    "secbert": _run_secbert,
    "cyner": _run_cyner,
}


def run_all(text: str) -> dict[str, list[Entity]]:
    """Run all available models and return results keyed by model name."""
    results = {}
    for name, runner in _RUNNERS.items():
        t0 = time.monotonic()
        entities = runner(text)
        elapsed = time.monotonic() - t0
        results[name] = {
            "entities": entities,
            "elapsed_ms": round(elapsed * 1000),
            "available": not isinstance(
                {"spacy": _spacy_nlp, "secbert": _secbert_pipeline, "cyner": _cyner_pipeline}[name],
                bool,
            ),
        }
    return results


def run_single(text: str, model: str) -> list[Entity]:
    """Run a single model."""
    runner = _RUNNERS.get(model)
    if not runner:
        return []
    return runner(text)


# ---------------------------------------------------------------------------
# CLI: compare mode
# ---------------------------------------------------------------------------

def cli_compare(text: str) -> None:
    """Print side-by-side comparison table."""
    results = run_all(text)

    print(f"\nInput: {text!r}\n")
    print(f"{'Model':<10} {'Time':>8}  {'Status':<12} Entities")
    print("-" * 80)

    for model_name, data in results.items():
        status = "loaded" if data["available"] else "not installed"
        elapsed = f"{data['elapsed_ms']}ms"
        entities = data["entities"]
        if not entities:
            print(f"{model_name:<10} {elapsed:>8}  {status:<12} (none)")
        else:
            for i, ent in enumerate(entities):
                prefix = f"{model_name:<10} {elapsed:>8}  {status:<12}" if i == 0 else " " * 32
                print(f"{prefix} [{ent.label}] {ent.text!r} ({ent.start}:{ent.end})")

    # Unique values per model
    print("\n--- Unique detections ---")
    all_values: dict[str, set[str]] = {name: set() for name in _RUNNERS}
    for model_name, data in results.items():
        for ent in data["entities"]:
            all_values[model_name].add(ent.text)

    all_found = set()
    for v in all_values.values():
        all_found |= v

    for value in sorted(all_found):
        found_by = [m for m, vals in all_values.items() if value in vals]
        missed_by = [m for m in _RUNNERS if m not in found_by]
        if missed_by:
            print(f"  {value!r:30s} found by: {', '.join(found_by):20s}  missed by: {', '.join(missed_by)}")
        else:
            print(f"  {value!r:30s} found by: ALL")


# ---------------------------------------------------------------------------
# Server mode
# ---------------------------------------------------------------------------

def serve(port: int = 8100, model: str = "all") -> None:
    """Start FastAPI server with BRA-compatible /ner endpoint."""
    try:
        from fastapi import FastAPI
        import uvicorn
    except ImportError:
        print("Install fastapi and uvicorn: pip install fastapi uvicorn", file=sys.stderr)
        sys.exit(1)

    app = FastAPI(title="BRA NER Harness")

    @app.post("/ner")
    async def ner_endpoint(body: dict) -> dict:
        """BRA-compatible NER endpoint.

        If model=all, merges deduplicated results from all models.
        Otherwise uses the selected model.
        """
        text = body.get("text", "")
        if not text:
            return {"entities": []}

        if model == "all":
            all_entities: list[dict] = []
            seen: set[str] = set()
            for name in _RUNNERS:
                for ent in run_single(text, name):
                    if ent.text not in seen:
                        seen.add(ent.text)
                        all_entities.append({
                            "text": ent.text,
                            "label": ent.label,
                            "start": ent.start,
                            "end": ent.end,
                        })
            return {"entities": all_entities}
        else:
            entities = run_single(text, model)
            return {"entities": [
                {"text": e.text, "label": e.label, "start": e.start, "end": e.end}
                for e in entities
            ]}

    @app.post("/ner/compare")
    async def ner_compare(body: dict) -> dict:
        """Run all models and return side-by-side results."""
        text = body.get("text", "")
        if not text:
            return {"results": {}}
        results = run_all(text)
        return {
            "results": {
                name: {
                    "entities": [asdict(e) for e in data["entities"]],
                    "elapsed_ms": data["elapsed_ms"],
                    "available": data["available"],
                }
                for name, data in results.items()
            }
        }

    @app.get("/ner/models")
    async def ner_models() -> dict:
        """List loaded models and status."""
        # Trigger lazy loading
        run_all("")
        return {
            "models": {
                "spacy": {"available": not isinstance(_spacy_nlp, bool), "model_name": "en_core_web_sm"},
                "secbert": {"available": not isinstance(_secbert_pipeline, bool), "model_name": "jackaduma/SecBERT"},
                "cyner": {"available": not isinstance(_cyner_pipeline, bool), "model_name": "aiforsec/CyNER"},
            },
            "active_model": model,
        }

    print(f"NER harness starting on port {port} (model: {model})")
    print(f"  BRA endpoint:  POST http://localhost:{port}/ner")
    print(f"  Compare:       POST http://localhost:{port}/ner/compare")
    print(f"  Model status:  GET  http://localhost:{port}/ner/models")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


# ---------------------------------------------------------------------------
# Sample texts for quick testing
# ---------------------------------------------------------------------------

SYNTHETIC_HEX_VALUE = "a1" * 16

SAMPLE_TEXTS = [
    "Scan 192.168.18.9 for open ports, MAC AA:BB:CC:DD:EE:FF",
    f"Target device at 10.0.0.1 owned by Acme Corporation, admin password is {SYNTHETIC_HEX_VALUE}",
    "Found vulnerable service on camera.local (198.51.100.57) running GoAhead httpd",
    "CVE-2023-1234 affects firmware v2.3.1 on Hikvision DS-2CD2142FWD-I at 192.168.1.100/24",
    "SSH key fingerprint SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA found on host bastion.internal.corp",
    "Contact John Smith at john.smith@acmecorp.com regarding the pentest of 172.16.0.0/12",
]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="BRA NER model harness")
    sub = parser.add_subparsers(dest="command")

    # compare
    cmp = sub.add_parser("compare", help="Run A/B/C comparison")
    cmp.add_argument("text", nargs="?", help="Text to analyze (omit for sample texts)")

    # serve
    srv = sub.add_parser("serve", help="Start BRA-compatible NER server")
    srv.add_argument("--port", type=int, default=8100)
    srv.add_argument("--model", choices=["spacy", "secbert", "cyner", "all"], default="all")

    # models
    sub.add_parser("models", help="Check which models are installed")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if args.command == "compare":
        if args.text:
            cli_compare(args.text)
        else:
            print("Running samples (pass custom text as argument):\n")
            for sample in SAMPLE_TEXTS:
                cli_compare(sample)
                print()

    elif args.command == "serve":
        serve(port=args.port, model=args.model)

    elif args.command == "models":
        print("Checking model availability...\n")
        run_all("")
        for name, obj in [("spacy", _spacy_nlp), ("secbert", _secbert_pipeline), ("cyner", _cyner_pipeline)]:
            status = "installed" if not isinstance(obj, bool) else "not installed"
            print(f"  {name:<10} {status}")
        print("\nInstall missing models:")
        print("  spaCy:   pip install spacy && python -m spacy download en_core_web_sm")
        print("  SecBERT: pip install transformers torch  (downloads from HuggingFace on first use)")
        print("  CyNER:   pip install transformers torch  (downloads from HuggingFace on first use)")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
