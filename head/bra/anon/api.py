"""Top-level anonymization API.

This is the public interface for the anon module. All callers
(scope intake, boots, report generation) use this.
"""
from __future__ import annotations

from pathlib import Path

from bra.anon.detect import Detection, detect_regex
from bra.anon.mapping import AnonMap
from bra.anon.ner_client import NERClient, NERConfig


class AnonAPI:
    """Public anonymization interface."""

    def __init__(
        self,
        map_path: Path,
        ner_config: NERConfig | None = None,
    ) -> None:
        self._map = AnonMap(map_path)
        self._ner = NERClient(ner_config or NERConfig())

    def detect(self, text: str) -> list[Detection]:
        """Detect identifiable data in text.

        Runs regex first (high confidence), then NER (low confidence).
        Items found by both get promoted to high confidence, source="both".
        Returns proposals not yet in the map.
        """
        # Stage 1: regex (high confidence)
        results = detect_regex(text)
        regex_values = {d.value for d in results}

        # Stage 2: NER (low confidence, additive)
        if self._ner._config.enabled:
            ner_results = self._ner.detect(text)
            for d in ner_results:
                if d.value in regex_values:
                    # Both agree — promote the regex detection
                    for r in results:
                        if r.value == d.value:
                            r.confidence = "high"
                            r.source = "both"
                            break
                else:
                    # NER-only — low confidence, user should verify
                    results.append(d)

        # Filter out anything already in the map
        existing = {m["real"] for m in self._map.all_mappings()}
        return [d for d in results if d.value not in existing]

    def add_mappings(self, detections: list[Detection], *, source: str) -> None:
        """Add detected items to the mapping."""
        for d in detections:
            self._map.add(d.value, type_=d.type_, source=source)

    def add_manual(self, real: str, *, type_: str = "operator-flagged") -> str:
        """Manually add a mapping. Returns the anon word."""
        _, anon_word = self._map.add(real, type_=type_, source="operator-flagged")
        return anon_word

    def mask(self, text: str) -> str:
        """Replace real values with anon words."""
        return self._map.mask(text)

    def unmask(self, text: str) -> str:
        """Replace anon words with real values."""
        return self._map.unmask(text)

    def save(self) -> None:
        """Persist mappings to disk."""
        self._map.save()

    def all_mappings(self) -> list[dict]:
        """Return all current mappings."""
        return self._map.all_mappings()

    def mapping_summary(self) -> dict:
        """Return lightweight mapping metadata for management views."""
        return self._map.summary()

    def set_engagement(self, name: str) -> None:
        """Set the engagement name metadata."""
        self._map.set_engagement(name)
