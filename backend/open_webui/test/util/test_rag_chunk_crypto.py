import time
from dataclasses import dataclass

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.auths import Auth, Auths
from open_webui.models.users import User
from open_webui.models.knowledge import (
    Knowledge,
    KnowledgeForm,
    KnowledgeKey,
    Knowledges,
)
from open_webui.retrieval.vector.main import GetResult
from open_webui.utils import rag_crypto
from open_webui.utils.crypto_context import cache_dek, set_current_user_id
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.knowledge_crypto import create_owner_kdek, resolve_kdek
from open_webui.utils.rag_crypto import (
    RagEncryptionRequiredError,
    decrypt_result,
    decrypt_result_for_collection,
    encrypt_items,
    encrypt_items_for_collection,
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

    def test_non_filename_metadata_left_plaintext(self):
        kdek = generate_dek()
        items = _items()
        encrypt_items(items, kdek)
        # Opaque identifiers stay queryable (not encrypted).
        assert items[0]["metadata"]["file_id"] == "f1"
        assert items[0]["metadata"]["hash"] == "deadbeef"

    def test_wrong_key_cannot_decrypt(self):
        items = _items()
        encrypt_items(items, generate_dek())
        with pytest.raises(Exception):
            decrypt_result(_result_from(items), generate_dek())


@dataclass
class Accounts:
    session: object
    a: str  # owner
    b: str  # shared member


@pytest.fixture(scope="module")
def accounts() -> Accounts:
    mp = pytest.MonkeyPatch()
    mp.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(
        engine,
        tables=[
            User.__table__,
            Auth.__table__,
            Knowledge.__table__,
            KnowledgeKey.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()

    ids = {}
    for key, pw in (("a", "a-pass-aaa"), ("b", "b-pass-bbb")):
        u = Auths.insert_new_auth(
            email=f"{key}@example.com",
            hashed_password=f"hashed::{key}",
            name=key.upper(),
            raw_password=pw,
            role="user",
            db=session,
        )
        cache_dek(u.user.id, u.dek, f"jti-{key}", time.time() + 3600)
        ids[key] = u.user.id

    yield Accounts(session=session, a=ids["a"], b=ids["b"])

    session.close()
    engine.dispose()
    mp.undo()


@pytest.fixture
def knowledge(accounts):
    k = Knowledges.insert_new_knowledge(
        accounts.a,
        KnowledgeForm(name="KB", description="d", access_control={}),
        db=accounts.session,
    )
    kdek = create_owner_kdek(k.id, accounts.a, db=accounts.session)
    return k.id, kdek


class TestCollectionOrchestration:
    def test_owner_encrypts_then_decrypts_via_real_kdek(self, accounts, knowledge):
        kid, kdek = knowledge
        items = _items()
        encrypt_items_for_collection(kid, accounts.a, items, db=accounts.session)
        assert items[0]["text"] != "patient diagnosis is confidential"

        result = decrypt_result(_result_from(items), kdek)
        assert result.documents[0][0] == "patient diagnosis is confidential"
        assert result.metadatas[0][0]["name"] == "report.pdf"

    def test_non_knowledge_collection_is_passthrough(self, accounts):
        # A standalone file-{id} collection has no KDEK; chunks stay plaintext.
        items = _items()
        encrypt_items_for_collection(
            "file-standalone", accounts.a, items, db=accounts.session
        )
        assert items[0]["text"] == "patient diagnosis is confidential"
        assert items[0]["metadata"]["name"] == "report.pdf"

    def test_missing_user_on_encrypted_collection_raises(self, accounts, knowledge):
        kid, _ = knowledge
        with pytest.raises(RagEncryptionRequiredError):
            encrypt_items_for_collection(kid, None, _items(), db=accounts.session)

    def test_non_member_on_encrypted_collection_raises(self, accounts, knowledge):
        kid, _ = knowledge
        with pytest.raises(RagEncryptionRequiredError):
            encrypt_items_for_collection(
                kid, "ghost-user", _items(), db=accounts.session
            )

    def test_shared_member_can_decrypt_owner_chunks(self, accounts, knowledge):
        from open_webui.utils.knowledge_crypto import sync_shared_keys

        kid, kdek = knowledge
        sync_shared_keys(
            kid,
            accounts.a,
            {"read": {"user_ids": [accounts.b], "group_ids": []}, "write": {}},
            kdek,
            db=accounts.session,
        )
        items = _items()
        encrypt_items_for_collection(kid, accounts.a, items, db=accounts.session)

        kdek_b = resolve_kdek(kid, accounts.b, db=accounts.session)
        result = decrypt_result(_result_from(items), kdek_b)
        assert result.documents[0][0] == "patient diagnosis is confidential"


class TestDecryptForCollection:
    def test_no_current_user_passes_through(self):
        kdek = generate_dek()
        items = _items()
        encrypt_items(items, kdek)
        encrypted = _result_from(items)

        ciphertext = encrypted.documents[0][0]
        set_current_user_id(None)
        out = decrypt_result_for_collection("kid", encrypted)
        # Still ciphertext: no user → cannot resolve a key.
        assert out.documents[0][0] == ciphertext

    def test_member_decrypts_via_context_user(self, monkeypatch):
        kdek = generate_dek()
        items = _items()
        encrypt_items(items, kdek)
        encrypted = _result_from(items)

        monkeypatch.setattr(rag_crypto, "resolve_kdek", lambda c, u, db=None: kdek)
        set_current_user_id("member-1")
        try:
            out = decrypt_result_for_collection("kid", encrypted)
            assert out.documents[0][0] == "patient diagnosis is confidential"
        finally:
            set_current_user_id(None)

    def test_unresolved_key_passes_through(self, monkeypatch):
        kdek = generate_dek()
        items = _items()
        encrypt_items(items, kdek)
        encrypted = _result_from(items)

        ciphertext = encrypted.documents[0][0]
        monkeypatch.setattr(rag_crypto, "resolve_kdek", lambda c, u, db=None: None)
        set_current_user_id("outsider")
        try:
            out = decrypt_result_for_collection("kid", encrypted)
            assert out.documents[0][0] == ciphertext
        finally:
            set_current_user_id(None)
