"""Tests for anon mapping file manager."""
import json
import pytest
from pathlib import Path
from bra.anon.mapping import AnonMap


@pytest.fixture
def map_path(tmp_path):
    return tmp_path / ".bra" / "anon_map.json"


@pytest.fixture
def anon_map(map_path):
    map_path.parent.mkdir(parents=True, exist_ok=True)
    return AnonMap(map_path)


def test_create_new_map(anon_map, map_path):
    """First save creates the file with version and empty mappings."""
    anon_map.save()
    data = json.loads(map_path.read_text())
    assert data["version"] == 1
    assert data["mappings"] == []


def test_add_mapping(anon_map):
    real, anon_word = anon_map.add("192.168.18.9", type_="ip", source="scope-intake")
    assert real == "192.168.18.9"
    assert isinstance(anon_word, str)
    assert len(anon_word) >= 3


def test_add_duplicate_returns_existing(anon_map):
    _, word1 = anon_map.add("192.168.18.9", type_="ip", source="scope-intake")
    _, word2 = anon_map.add("192.168.18.9", type_="ip", source="scope-intake")
    assert word1 == word2


def test_mask_replaces_real_with_anon(anon_map):
    anon_map.add("192.168.18.9", type_="ip", source="test")
    mapping = anon_map.get_by_real("192.168.18.9")
    result = anon_map.mask("Connect to 192.168.18.9 on port 80")
    assert mapping["anon"] in result
    assert "192.168.18.9" not in result


def test_unmask_replaces_anon_with_real(anon_map):
    anon_map.add("192.168.18.9", type_="ip", source="test")
    mapping = anon_map.get_by_real("192.168.18.9")
    masked = f"Connect to {mapping['anon']} on port 80"
    result = anon_map.unmask(masked)
    assert "192.168.18.9" in result
    assert mapping["anon"] not in result


def test_save_and_load_roundtrip(anon_map, map_path):
    anon_map.add("192.168.18.9", type_="ip", source="test")
    anon_map.add("AA:BB:CC:DD:EE:FF", type_="mac", source="test")
    anon_map.save()

    loaded = AnonMap(map_path)
    loaded.load()
    assert loaded.get_by_real("192.168.18.9") is not None
    assert loaded.get_by_real("AA:BB:CC:DD:EE:FF") is not None


def test_mappings_list(anon_map):
    anon_map.add("192.168.18.9", type_="ip", source="test")
    anon_map.add("secret123", type_="credential", source="test")
    mappings = anon_map.all_mappings()
    assert len(mappings) == 2


def test_anon_words_are_unique(anon_map):
    anon_map.add("10.0.0.1", type_="ip", source="test")
    anon_map.add("10.0.0.2", type_="ip", source="test")
    anon_map.add("10.0.0.3", type_="ip", source="test")
    words = [m["anon"] for m in anon_map.all_mappings()]
    assert len(words) == len(set(words))
