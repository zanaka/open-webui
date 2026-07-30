import pytest

from open_webui.retrieval.vector.main import GetResult
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.rag_crypto import (
    decrypt_result,
    encrypt_items,
    redact_metadatas_for_log,
)


def _items():
    return [
        {
            "id": "c1",
            "text": "patient diagnosis is confidential",
            "vector": [0.1, 0.2],
            "metadata": {
                "name": "report.pdf",
                "source": "report.pdf",
                "file_id": "f1",
                "hash": "deadbeef",
            },
        }
    ]


def _result_from(items):
    return GetResult(
        ids=[[item["id"] for item in items]],
        documents=[[item["text"] for item in items]],
        metadatas=[[item["metadata"] for item in items]],
    )


class TestChunkCryptoPrimitives:
    def test_round_trip_recovers_text_and_filename(self):
        kdek = generate_dek()
        items = _items()
        encrypt_items(items, kdek)
        result = decrypt_result(_result_from(items), kdek)
        assert result.documents[0][0] == "patient diagnosis is confidential"
        assert result.metadatas[0][0]["name"] == "report.pdf"
        assert result.metadatas[0][0]["source"] == "report.pdf"

    def test_ciphertext_at_rest_hides_plaintext(self):
        kdek = generate_dek()
        items = _items()
        encrypt_items(items, kdek)
        stored = items[0]
        assert stored["text"] != "patient diagnosis is confidential"
        assert "confidential" not in stored["text"]
        assert "report.pdf" not in stored["metadata"]["name"]
        assert "report.pdf" not in stored["metadata"]["source"]

    def test_multiple_chunks_each_round_trip(self):
        kdek = generate_dek()
        items = [
            {
                "id": "c1",
                "text": "first secret",
                "vector": [0.1],
                "metadata": {"name": "a.pdf", "source": "a.pdf"},
            },
            {
                "id": "c2",
                "text": "second secret",
                "vector": [0.2],
                "metadata": {"name": "b.pdf", "source": "b.pdf"},
            },
        ]
        encrypt_items(items, kdek)
        assert items[0]["text"] != "first secret"
        assert items[1]["text"] != "second secret"

        result = decrypt_result(_result_from(items), kdek)
        # Each chunk is recovered independently, in order (no cross-wiring).
        assert result.documents[0] == ["first secret", "second secret"]
        assert [m["name"] for m in result.metadatas[0]] == ["a.pdf", "b.pdf"]

    def test_identifiers_stay_queryable(self):
        kdek = generate_dek()
        items = _items()
        encrypt_items(items, kdek)
        # An id says nothing about the content, so it stays as it is.
        assert items[0]["metadata"]["file_id"] == "f1"

    def test_the_content_hash_is_keyed(self):
        """It has to stay comparable, but not recomputable from the document.
        See test_vector_metadata_crypto.py for why."""
        kdek = generate_dek()
        first, second = _items(), _items()
        encrypt_items(first, kdek)
        encrypt_items(second, kdek)

        assert first[0]["metadata"]["hash"] != "deadbeef"
        assert first[0]["metadata"]["hash"] == second[0]["metadata"]["hash"]

    def test_wrong_key_cannot_decrypt(self):
        items = _items()
        encrypt_items(items, generate_dek())
        with pytest.raises(Exception):
            decrypt_result(_result_from(items), generate_dek())


class TestRedactMetadatasForLog:
    def test_masks_filename_fields(self):
        metadatas = [[{"name": "report.pdf", "source": "report.pdf", "page": 3}]]
        out = redact_metadatas_for_log(metadatas)
        assert out[0][0]["name"] == "<redacted>"
        assert out[0][0]["source"] == "<redacted>"
        assert out[0][0]["page"] == 3

    def test_does_not_mutate_input(self):
        metadatas = [[{"name": "report.pdf", "page": 3}]]
        redact_metadatas_for_log(metadatas)
        assert metadatas[0][0]["name"] == "report.pdf"

    def test_handles_empty_and_non_dict(self):
        assert redact_metadatas_for_log([]) == []
        assert redact_metadatas_for_log(None) is None
        assert redact_metadatas_for_log([[None]]) == [[None]]

