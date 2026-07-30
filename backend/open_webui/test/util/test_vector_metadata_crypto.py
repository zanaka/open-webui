"""What a vector item gives away to someone who can read the store.

The chunk text was already encrypted, but the metadata stored beside it carried
the document's title, the headings the chunk sits under and, for web results,
the snippet itself. It also carried a plain SHA-256 of the document, which is a
different kind of leak: it cannot be read, but it can be *checked*. Anyone with
a copy of a candidate document could hash it and learn whether the store holds
it, without decrypting anything, and the same file uploaded by two people was
visibly the same file.
"""

import hashlib

import pytest

from open_webui.retrieval.vector.encrypting_client import _protect_filter
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.rag_crypto import (
    decrypt_result,
    encrypt_items,
    hash_token,
    redact_metadatas_for_log,
)
from open_webui.utils.vector_keys import VectorKeyError

SECRET = "Q3 restructuring plan"
KEY = b"k" * 32
OTHER_KEY = b"j" * 32


class _Result:
    def __init__(self, documents, metadatas):
        self.documents = documents
        self.metadatas = metadatas


def _item(**metadata):
    return {"id": "1", "text": SECRET, "vector": [0.1], "metadata": metadata}


def _stored(**metadata):
    items = [_item(**metadata)]
    encrypt_items(items, KEY)
    return items[0]


class TestContentBearingMetadata:
    @pytest.mark.parametrize("field", ["name", "source", "title", "snippet", "link"])
    def test_it_is_ciphertext_at_rest(self, field):
        stored = _stored(**{field: SECRET})

        assert SECRET not in str(stored["metadata"][field])

    @pytest.mark.parametrize("field", ["name", "source", "title", "snippet", "link"])
    def test_it_comes_back_readable(self, field):
        stored = _stored(**{field: SECRET})
        result = _Result([[stored["text"]]], [[stored["metadata"]]])

        decrypt_result(result, KEY)

        assert result.metadatas[0][0][field] == SECRET

    def test_headings_are_encrypted_one_by_one(self):
        """A list, so it needs handling of its own rather than str() of a list."""
        stored = _stored(headings=["Board papers", SECRET])

        assert SECRET not in str(stored["metadata"]["headings"])

    def test_headings_come_back_readable(self):
        stored = _stored(headings=["Board papers", SECRET])
        result = _Result([[stored["text"]]], [[stored["metadata"]]])

        decrypt_result(result, KEY)

        assert result.metadatas[0][0]["headings"] == ["Board papers", SECRET]

    def test_fields_that_say_nothing_about_the_content_are_left_alone(self):
        stored = _stored(file_id="f1", page=3)

        assert stored["metadata"]["file_id"] == "f1"
        assert stored["metadata"]["page"] == 3

    def test_the_log_redactor_covers_every_encrypted_field(self):
        metadatas = [[{"title": "x", "snippet": "y", "headings": ["z"], "page": 1}]]

        redacted = redact_metadatas_for_log(metadatas)[0][0]

        assert redacted["title"] == "<redacted>"
        assert redacted["snippet"] == "<redacted>"
        assert redacted["headings"] == "<redacted>"
        assert redacted["page"] == 1


class TestTheHashIsNoLongerAnOracle:
    def test_the_stored_hash_cannot_be_recomputed_from_the_document(self):
        """The whole point: holding the document must not confirm it is here."""
        plain = hashlib.sha256(SECRET.encode()).hexdigest()

        stored = _stored(hash=plain)

        assert stored["metadata"]["hash"] != plain

    def test_the_same_document_looks_different_under_a_different_key(self):
        """So two people holding the same file is no longer visible."""
        plain = hashlib.sha256(SECRET.encode()).hexdigest()

        assert hash_token(plain, KEY) != hash_token(plain, OTHER_KEY)

    def test_it_is_still_the_same_for_the_same_document(self):
        """Recognising a document already held is what the hash is for."""
        plain = hashlib.sha256(SECRET.encode()).hexdigest()

        assert hash_token(plain, KEY) == hash_token(plain, KEY)

    def test_two_documents_still_look_different(self):
        assert hash_token("a", KEY) != hash_token("b", KEY)


class TestFiltersAreTranslated:
    def test_a_hash_filter_is_keyed_to_match_what_is_stored(self):
        plain = hashlib.sha256(SECRET.encode()).hexdigest()
        stored = _stored(hash=plain)

        translated = _protect_filter({"hash": plain}, KEY, "c1")

        assert translated["hash"] == stored["metadata"]["hash"]

    def test_a_hash_filter_without_a_key_is_refused(self):
        """Passing it through would match nothing and read as an empty store."""
        with pytest.raises(VectorKeyError):
            _protect_filter({"hash": "abc"}, None, "c1")

    def test_other_filters_pass_through_without_a_key(self):
        """Deleting by file_id has nothing to do with the content."""
        assert _protect_filter({"file_id": "f1"}, None, "c1") == {"file_id": "f1"}

    def test_an_empty_filter_is_left_alone(self):
        assert _protect_filter(None, None, "c1") is None

    def test_the_other_keys_in_the_filter_survive(self):
        translated = _protect_filter({"hash": "abc", "file_id": "f1"}, KEY, "c1")

        assert translated["file_id"] == "f1"


class TestRoundTrip:
    def test_a_web_result_leaks_nothing_at_rest(self):
        """The URL appears twice, as `source` and as `link`; both must go.

        An earlier version of this test asserted the opposite for `link`,
        calling it an id the store needs. It is not: nothing filters on it,
        and it says where the person was reading — the same fact `source`
        is encrypted to hide.
        """
        stored = _stored(
            source="https://example.com/plan",
            title=SECRET,
            snippet=f"{SECRET} — details follow",
            link="https://example.com/plan",
        )

        at_rest = str(stored)

        assert SECRET not in at_rest
        assert "https://example.com/plan" not in at_rest
