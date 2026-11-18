"""Tests for NER model client."""
import pytest
from unittest.mock import patch, MagicMock
from bra.anon.ner_client import NERClient, NERConfig
from bra.anon.detect import Detection


def test_ner_config_defaults():
    config = NERConfig()
    assert config.endpoint is None
    assert config.enabled is False


def test_ner_disabled_returns_empty():
    client = NERClient(NERConfig(endpoint=None))
    results = client.detect("Some text with 192.168.1.1")
    assert results == []


def test_ner_enabled_calls_endpoint():
    config = NERConfig(endpoint="http://localhost:8080/ner")
    client = NERClient(config)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "entities": [
            {"text": "Acme Corp", "label": "ORG", "start": 0, "end": 9}
        ]
    }
    with patch("requests.post", return_value=mock_response) as mock_post:
        results = client.detect("Acme Corp server at location X")
        mock_post.assert_called_once()
        assert len(results) == 1
        assert results[0].value == "Acme Corp"


def test_ner_endpoint_unreachable_returns_empty():
    config = NERConfig(endpoint="http://localhost:99999/ner")
    client = NERClient(config)
    results = client.detect("Some text")
    assert results == []
