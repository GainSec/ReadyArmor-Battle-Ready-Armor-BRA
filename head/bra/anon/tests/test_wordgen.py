"""Tests for random word generator."""
import pytest
from bra.anon.wordgen import generate_word, generate_word_excluding


def test_generate_word_returns_string():
    word = generate_word()
    assert isinstance(word, str)
    assert len(word) >= 3


def test_generate_word_no_numbers():
    """Words should not contain digits."""
    for _ in range(100):
        word = generate_word()
        assert not any(c.isdigit() for c in word), f"Word contains digit: {word}"


def test_generate_word_lowercase():
    for _ in range(100):
        word = generate_word()
        assert word == word.lower()


def test_generate_word_excluding_avoids_used():
    used = set()
    for _ in range(50):
        word = generate_word_excluding(used)
        assert word not in used
        used.add(word)


def test_generate_word_excluding_raises_if_exhausted():
    """If all words are used, raise ValueError."""
    from bra.anon.wordlist import WORDLIST
    used = set(WORDLIST)
    with pytest.raises(ValueError, match="exhausted"):
        generate_word_excluding(used)


def test_wordlist_excludes_ambiguous_status_like_terms():
    from bra.anon.wordlist import WORDLIST

    banned = {"locket", "anchor", "beacon", "mirror", "timber"}
    for word in banned:
        assert word not in WORDLIST, f"Ambiguous anonymization word should be excluded: {word}"
