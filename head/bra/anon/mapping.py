"""Anonymization mapping file manager.

Manages .bra/anon_map.json — the mapping between real values and
their anonymized random word replacements. Append-only: mappings
are added but never modified or deleted.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from bra.anon.wordgen import generate_word_excluding


class AnonMap:
    """Manages the anonymization mapping file."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._version = 1
        self._engagement: str = ""
        self._created: str = ""
        self._mappings: list[dict] = []
        self._real_index: dict[str, dict] = {}
        self._anon_index: dict[str, dict] = {}
        self._used_words: set[str] = set()

        if path.exists():
            self.load()

    def load(self) -> None:
        """Load mappings from disk."""
        data = json.loads(self._path.read_text())
        self._version = data.get("version", 1)
        self._engagement = data.get("engagement", "")
        self._created = data.get("created", "")
        self._mappings = data.get("mappings", [])
        self._rebuild_indexes()

    def save(self) -> None:
        """Write mappings to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if not self._created:
            self._created = now
        data = {
            "version": self._version,
            "engagement": self._engagement,
            "created": self._created,
            "mappings": self._mappings,
        }
        self._path.write_text(json.dumps(data, indent=2) + "\n")

    def add(self, real: str, *, type_: str, source: str) -> tuple[str, str]:
        """Add a new mapping. Returns (real, anon_word).

        If *real* already exists, returns the existing mapping.
        """
        if real in self._real_index:
            m = self._real_index[real]
            return m["real"], m["anon"]

        anon_word = generate_word_excluding(self._used_words)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = {
            "real": real,
            "anon": anon_word,
            "type": type_,
            "source": source,
            "created": now,
        }
        self._mappings.append(entry)
        self._real_index[real] = entry
        self._anon_index[anon_word] = entry
        self._used_words.add(anon_word)
        return real, anon_word

    def get_by_real(self, real: str) -> dict | None:
        """Look up a mapping by its real value."""
        return self._real_index.get(real)

    def get_by_anon(self, anon: str) -> dict | None:
        """Look up a mapping by its anon word."""
        return self._anon_index.get(anon)

    def all_mappings(self) -> list[dict]:
        """Return a copy of all mappings."""
        return list(self._mappings)

    def summary(self) -> dict:
        """Return lightweight mapping metadata for management views."""
        counts_by_type: dict[str, int] = {}
        for mapping in self._mappings:
            type_ = str(mapping.get("type", "unknown") or "unknown")
            counts_by_type[type_] = counts_by_type.get(type_, 0) + 1
        return {
            "version": self._version,
            "engagement": self._engagement,
            "created": self._created,
            "total": len(self._mappings),
            "counts_by_type": counts_by_type,
        }

    def mask(self, text: str) -> str:
        """Replace all real values with their anon words."""
        for m in sorted(self._mappings, key=lambda x: len(x["real"]), reverse=True):
            text = text.replace(m["real"], m["anon"])
        return text

    def unmask(self, text: str) -> str:
        """Replace all anon words with their real values."""
        for m in sorted(self._mappings, key=lambda x: len(x["anon"]), reverse=True):
            text = text.replace(m["anon"], m["real"])
        return text

    def set_engagement(self, name: str) -> None:
        """Set the engagement name metadata."""
        self._engagement = name

    def _rebuild_indexes(self) -> None:
        """Rebuild lookup indexes from mappings list."""
        self._real_index.clear()
        self._anon_index.clear()
        self._used_words.clear()
        for m in self._mappings:
            self._real_index[m["real"]] = m
            self._anon_index[m["anon"]] = m
            self._used_words.add(m["anon"])
