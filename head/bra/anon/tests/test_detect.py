"""Tests for regex-based detection of identifiable data."""
import pytest
from bra.anon.detect import detect_regex, Detection

SYNTHETIC_HEX_VALUE = "a1" * 16


def test_detect_ipv4():
    text = "Target is at 192.168.18.9 on the network"
    results = detect_regex(text)
    reals = [d.value for d in results]
    assert "192.168.18.9" in reals


def test_detect_ipv4_at_sentence_end():
    text = "Target is at 192.168.18.9."
    results = detect_regex(text)
    reals = [d.value for d in results]
    assert "192.168.18.9" in reals


def test_detect_ipv4_in_url():
    text = "http://192.168.18.9:80/cgi-bin/test.cgi"
    results = detect_regex(text)
    reals = [d.value for d in results]
    assert "192.168.18.9" in reals


def test_detect_cidr():
    text = "Scan range 10.0.0.0/24"
    results = detect_regex(text)
    reals = [d.value for d in results]
    assert "10.0.0.0/24" in reals


def test_detect_mac_address():
    text = "Device MAC is AA:BB:CC:DD:EE:FF"
    results = detect_regex(text)
    reals = [d.value for d in results]
    assert "AA:BB:CC:DD:EE:FF" in reals


def test_detect_hex_string_api_key():
    text = f'SIGNKEY = "{SYNTHETIC_HEX_VALUE}"'
    results = detect_regex(text)
    reals = [d.value for d in results]
    assert SYNTHETIC_HEX_VALUE in reals


def test_detect_does_not_flag_short_hex():
    """Short hex strings (< 16 chars) should not be flagged."""
    text = "color is #ff0000"
    results = detect_regex(text)
    reals = [d.value for d in results]
    assert "#ff0000" not in reals
    assert "ff0000" not in reals


def test_detect_does_not_flag_versions():
    """Version strings should not be flagged."""
    text = "lighttpd/1.4.76"
    results = detect_regex(text)
    reals = [d.value for d in results]
    assert "1.4.76" not in reals


def test_detect_multiple():
    text = f"Target 192.168.18.9 backend 198.51.100.57 key {SYNTHETIC_HEX_VALUE}"
    results = detect_regex(text)
    reals = [d.value for d in results]
    assert "192.168.18.9" in reals
    assert "198.51.100.57" in reals
    assert SYNTHETIC_HEX_VALUE in reals


def test_detect_returns_type():
    text = "IP 10.0.0.1 MAC AA:BB:CC:DD:EE:FF"
    results = detect_regex(text)
    types = {d.value: d.type_ for d in results}
    assert types["10.0.0.1"] == "ip"
    assert types["AA:BB:CC:DD:EE:FF"] == "mac"


def test_detect_deduplicates():
    text = "192.168.18.9 and again 192.168.18.9"
    results = detect_regex(text)
    reals = [d.value for d in results]
    assert reals.count("192.168.18.9") == 1


def test_detect_password():
    text = "password is 12345678"
    results = detect_regex(text)
    reals = [d.value for d in results]
    assert "12345678" in reals
