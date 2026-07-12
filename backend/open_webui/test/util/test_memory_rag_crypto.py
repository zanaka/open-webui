import time

import pytest

from open_webui.retrieval.vector.main import SearchResult
from open_webui.routers.memories import (
    _decrypt_memory_results,
    _encrypt_memory_items,
)
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek, set_current_user_id
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.rag_crypto import decrypt_result, encrypt_items

USER = "u-mem"
CONTENT = "I am allergic to peanuts"


@pytest.fixture
def dek():
    key = generate_dek()
    cache_dek(USER, key, jti="j", expires_at=time.time() + 3600)
    set_current_user_id(USER)
    yield key
    set_current_user_id(None)
    crypto_context._dek_cache.clear()


def _items():
    return [
        {
            "id": "m1",
            "text": CONTENT,
            "vector": [0.1, 0.2],
            "metadata": {"created_at": 1},
        }
    ]


def _result_from(items):
    return SearchResult(
        ids=[[i["id"] for i in items]],
        documents=[[i["text"] for i in items]],
        metadatas=[[i["metadata"] for i in items]],
        distances=[[0.0]],
    )


class TestEncrypt:
    def test_round_trip(self, dek):
        items = _items()
        _encrypt_memory_items(items, USER)
        assert items[0]["text"] != CONTENT

        result = decrypt_result(_result_from(items), dek)
        assert result.documents[0][0] == CONTENT

    def test_ciphertext_at_rest(self, dek):
        items = _items()
        _encrypt_memory_items(items, USER)
        assert "peanuts" not in items[0]["text"]

    def test_no_dek_raises(self):
        crypto_context._dek_cache.clear()
        set_current_user_id(None)
        with pytest.raises(Exception):
            _encrypt_memory_items(_items(), USER)

    def test_empty_items_needs_no_dek(self):
        # A reset with no memories yields an empty list; it must not require a DEK.
        crypto_context._dek_cache.clear()
        set_current_user_id(None)
        _encrypt_memory_items([], USER)  # does not raise


class TestDecrypt:
    def test_decrypts_with_dek(self, dek):
        items = _items()
        _encrypt_memory_items(items, USER)
        results = _decrypt_memory_results(_result_from(items), USER)
        assert results.documents[0][0] == CONTENT

    def test_no_dek_passes_through(self):
        # Encrypt with a known key, then query with no DEK cached -> ciphertext stays.
        items = _items()
        encrypt_items(items, generate_dek())
        ciphertext = items[0]["text"]
        results = _result_from(items)

        crypto_context._dek_cache.clear()
        set_current_user_id(None)
        _decrypt_memory_results(results, USER)
        assert results.documents[0][0] == ciphertext
