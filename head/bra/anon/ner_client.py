"""NER detection client — supports external HTTP endpoint or local model.

Two modes:
  1. HTTP endpoint: POST {"text": "..."} → {"entities": [...]}
     (e.g. the ner_harness.py server)
  2. Local model: loads SecureModernBERT-NER directly via transformers.
     Model downloads on first use (~1.6GB) and is cached in HF_HOME.

Gracefully returns empty list if not configured or model unavailable.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from bra.anon.detect import Detection

logger = logging.getLogger(__name__)

# Default model for local mode
DEFAULT_MODEL = "attack-vector/SecureModernBERT-NER"

# Map NER labels to anon types
# Covers: spaCy labels, SecureModernBERT-NER (22 types), SecureBERT 2.0-NER
_LABEL_MAP: dict[str, str] = {
    # SecureModernBERT-NER labels
    "IPV4": "ip",
    "IPV6": "ip",
    "DOMAIN": "domain",
    "URL": "domain",
    "EMAIL": "credential",
    "HASH": "credential",
    "REGISTRY-KEY": "credential",
    "REGISTRY-KEYS": "credential",
    "FILEPATH": "operator-flagged",
    "MALWARE": "operator-flagged",
    "THREAT-ACTOR": "operator-flagged",
    "CAMPAIGN": "operator-flagged",
    "CVE": "pass-through",        # CVEs are analytically useful, don't mask
    "TOOL": "pass-through",       # tool names are useful
    "PRODUCT": "operator-flagged",
    "VENDOR": "operator-flagged",
    "PLATFORM": "pass-through",   # "Android", "Windows" — not identifiable
    "SECTOR": "pass-through",     # "security", "finance" — not identifiable
    "COUNTRY": "operator-flagged",
    "REGION": "operator-flagged",
    # SecureBERT 2.0-NER labels
    "Indicator": "operator-flagged",
    "System": "pass-through",
    "Organization": "operator-flagged",
    "Malware": "operator-flagged",
    "Vulnerability": "pass-through",
    # spaCy labels
    "IP": "ip",
    "MAC": "mac",
    "KEY": "credential",
    "PASSWORD": "credential",
    "ORG": "operator-flagged",
    "PERSON": "operator-flagged",
    "GPE": "operator-flagged",
    "LOC": "operator-flagged",
    "FAC": "operator-flagged",
}

# Labels that should NOT be flagged for anonymization
_PASS_THROUGH_LABELS = {k for k, v in _LABEL_MAP.items() if v == "pass-through"}

# Minimum score to accept a NER detection
_MIN_SCORE = 0.6


@dataclass
class NERConfig:
    endpoint: str | None = None
    local_model: str | None = None
    hf_cache: str | None = None

    @property
    def enabled(self) -> bool:
        return bool(
            (self.endpoint and self.endpoint.strip())
            or (self.local_model and self.local_model.strip())
        )


# Cached local pipeline (lazy load)
_local_pipeline = None
_local_model_id: str | None = None


def _load_local_pipeline(model_id: str, hf_cache: str | None = None):
    """Load a HuggingFace NER pipeline, caching for reuse."""
    global _local_pipeline, _local_model_id

    if _local_pipeline is not None and _local_model_id == model_id:
        return _local_pipeline

    try:
        if hf_cache:
            os.environ["HF_HOME"] = hf_cache
        os.environ["TOKENIZERS_PARALLELISM"] = "false"

        from transformers import pipeline
        _local_pipeline = pipeline(
            "ner",
            model=model_id,
            aggregation_strategy="simple",
        )
        _local_model_id = model_id
        logger.info(f"NER model loaded: {model_id}")
        return _local_pipeline
    except Exception:
        logger.warning(f"Failed to load NER model: {model_id}", exc_info=True)
        _local_pipeline = False
        _local_model_id = model_id
        return None


class NERClient:
    """Client for NER detection — HTTP endpoint or local model."""

    def __init__(self, config: NERConfig) -> None:
        self._config = config

    def detect(self, text: str) -> list[Detection]:
        """Run NER and return detections.

        Returns empty list if not configured or unavailable.
        """
        if not self._config.enabled:
            return []

        if self._config.endpoint and self._config.endpoint.strip():
            return self._detect_http(text)
        else:
            return self._detect_local(text)

    def _detect_http(self, text: str) -> list[Detection]:
        """Query external NER endpoint."""
        try:
            import requests

            resp = requests.post(
                self._config.endpoint,
                json={"text": text},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            logger.warning("NER endpoint unreachable or returned error", exc_info=True)
            return []

        return self._parse_entities(data.get("entities", []))

    def _detect_local(self, text: str) -> list[Detection]:
        """Run local HuggingFace NER model."""
        model_id = (self._config.local_model or "").strip() or DEFAULT_MODEL
        pipe = _load_local_pipeline(model_id, self._config.hf_cache)
        if not pipe:
            return []

        # Chunk for transformer max sequence length
        chunk_size = 512
        chunks = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]

        raw_entities: list[dict] = []
        offset = 0
        for chunk in chunks:
            try:
                results = pipe(chunk)
                for r in results:
                    raw_entities.append({
                        "text": r.get("word", "").strip(),
                        "label": r.get("entity_group", ""),
                        "start": r.get("start", 0) + offset,
                        "end": r.get("end", 0) + offset,
                        "score": r.get("score", 0),
                    })
            except Exception:
                logger.warning(f"NER chunk failed at offset {offset}", exc_info=True)
            offset += len(chunk)

        return self._parse_entities(raw_entities)

    def _parse_entities(self, entities: list[dict]) -> list[Detection]:
        """Convert raw NER entities to Detection objects."""
        results: list[Detection] = []
        seen: set[str] = set()

        for entity in entities:
            value = (entity.get("text", "") or "").strip()
            label = entity.get("label", "")
            score = entity.get("score", 1.0)

            # Skip empty, duplicates, low-confidence, and pass-through labels
            if not value or value in seen:
                continue
            if label in _PASS_THROUGH_LABELS:
                continue
            if score < _MIN_SCORE:
                continue

            seen.add(value)
            type_ = _LABEL_MAP.get(label, "operator-flagged")
            if type_ == "pass-through":
                continue

            results.append(Detection(
                value=value,
                type_=type_,
                span=(entity.get("start", 0), entity.get("end", 0)),
                confidence="low",
                source="ner",
            ))

        return results
