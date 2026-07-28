import pytest

from open_webui.retrieval.vector.encrypting_client import EncryptingVectorClient
from open_webui.retrieval.vector.main import GetResult, SearchResult
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.rag_crypto import encrypt_items
from open_webui.utils.vector_keys import VectorKeyError
from open_webui.utils.vem_crypto import rotate_vectors

PLAINTEXT = "patient record is secret"
FILENAME = "report.pdf"


class FakeVectorDB:
    """Stands in for a connector, recording what actually reaches storage."""

    def __init__(self, result=None):
        self.inserted = None
        self.searched_vectors = None
        self.result = result

    def insert(self, collection_name, items):
        self.inserted = items

    def upsert(self, collection_name, items):
        self.inserted = items

    def search(self, collection_name, vectors, filter=None, limit=10):
        self.searched_vectors = vectors
        return self.result

    def query(self, collection_name, filter, limit=None):
        return self.result

    def get(self, collection_name):
        return self.result


def _items():
    return [
        {
            "id": "c1",
            "text": PLAINTEXT,
            "vector": [0.1, 0.2, 0.3, 0.4],
            "metadata": {"name": FILENAME, "page": 1},
        }
    ]


def _stored_result(key):
    items = _items()
    encrypt_items(items, key)
    return SearchResult(
        ids=[["c1"]],
        documents=[[items[0]["text"]]],
        metadatas=[[items[0]["metadata"]]],
        distances=[[0.0]],
    )


class TestKeyIsRequired:
    def test_insert_without_key_is_a_call_error(self):
        client = EncryptingVectorClient(FakeVectorDB())
        with pytest.raises(TypeError):
            client.insert("file-1", _items())

    def test_search_without_key_is_a_call_error(self):
        client = EncryptingVectorClient(FakeVectorDB())
        with pytest.raises(TypeError):
            client.search("file-1", [[0.1, 0.2, 0.3, 0.4]])

    def test_empty_key_is_refused(self):
        client = EncryptingVectorClient(FakeVectorDB())
        with pytest.raises(VectorKeyError):
            client.insert("file-1", _items(), key=b"")


class TestNothingReachesStorageInTheClear:
    def test_text_and_metadata_are_encrypted(self):
        inner = FakeVectorDB()
        key = generate_dek()

        EncryptingVectorClient(inner).insert("file-1", _items(), key=key)

        stored = inner.inserted[0]
        assert stored["text"] != PLAINTEXT
        assert PLAINTEXT not in stored["text"]
        assert stored["metadata"]["name"] != FILENAME

    def test_vectors_are_rotated(self):
        inner = FakeVectorDB()
        key = generate_dek()
        original = _items()[0]["vector"]

        EncryptingVectorClient(inner).insert("file-1", _items(), key=key)

        assert inner.inserted[0]["vector"] != original

    def test_queries_are_rotated_to_match(self):
        inner = FakeVectorDB(result=None)
        key = generate_dek()
        query = [0.1, 0.2, 0.3, 0.4]

        EncryptingVectorClient(inner).search("file-1", [query], key=key)

        assert inner.searched_vectors == rotate_vectors([query], key)


class TestResultsComeBackReadable:
    def test_search_decrypts(self):
        key = generate_dek()
        inner = FakeVectorDB(result=_stored_result(key))

        result = EncryptingVectorClient(inner).search(
            "file-1", [[0.1, 0.2, 0.3, 0.4]], key=key
        )

        assert result.documents[0][0] == PLAINTEXT
        assert result.metadatas[0][0]["name"] == FILENAME

    def test_get_decrypts(self):
        key = generate_dek()
        inner = FakeVectorDB(result=_stored_result(key))

        result = EncryptingVectorClient(inner).get("file-1", key=key)

        assert result.documents[0][0] == PLAINTEXT

    def test_another_users_key_cannot_read_it(self):
        owner_key = generate_dek()
        other_key = generate_dek()
        inner = FakeVectorDB(result=_stored_result(owner_key))

        with pytest.raises(Exception):
            EncryptingVectorClient(inner).get("file-1", key=other_key)

    def test_missing_result_is_passed_through(self):
        inner = FakeVectorDB(result=None)
        assert EncryptingVectorClient(inner).get("file-1", key=generate_dek()) is None
