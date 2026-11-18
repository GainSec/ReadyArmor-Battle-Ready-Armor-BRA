"""Random word generator for anonymization substitutions.

Provides collision-safe word selection from a curated noun list.
"""
from __future__ import annotations

import random

from bra.anon.wordlist import WORDLIST


def generate_word() -> str:
    """Return a random word from the wordlist."""
    return random.choice(WORDLIST)


def generate_word_excluding(used: set[str]) -> str:
    """Return a random word not in *used*.

    Raises ``ValueError`` if every word in the list has been consumed.
    """
    available = [w for w in WORDLIST if w not in used]
    if not available:
        raise ValueError("Word list exhausted — all words are already in use")
    return random.choice(available)
