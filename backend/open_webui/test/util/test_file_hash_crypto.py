"""The content hash stored on a file row.

file.hash is derived from file.data["content"] — a fingerprint of the encrypted
column sitting next to it. Stored as a plain SHA-256 it lets anyone with a copy
of a candidate document confirm that this deployment holds it, and makes the
same file uploaded by two people visibly the same file.

The fix keeps the existing data flow untouched: the fingerprint is keyed to its
owner at the one place it is computed (file_hash_token), and from there every
path — the file row, the vector metadata, the delete filters quoting it back —
carries it opaquely, exactly as the plain hash used to travel. Nothing decrypts
it, so people without the owner's key (a member removing a file from a shared
knowledge base, an administrator deleting without reading) keep working.
"""

import hashlib
import time

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.files import File, Files
from open_webui.retrieval.vector.encrypting_client import _protect_filter
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek, set_current_user_id
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.encrypted_models import (
    ENCRYPTED_MODELS,
    install as install_column_encryption,
)
from open_webui.utils.rag_crypto import encrypt_items, file_hash_token, hash_token

install_column_encryption()

OWNER = "hash-owner"
INTRUDER = "hash-intruder"
CONTENT = "the contents of a document someone might already have a copy of"
SHA256 = hashlib.sha256(CONTENT.encode()).hexdigest()

OWNER_DEK = generate_dek()
INTRUDER_DEK = generate_dek()

TOKEN = file_hash_token(SHA256, OWNER_DEK)


class TestTheToken:
    def test_it_is_not_the_sha256(self):
        """Guards the premise: SHA256 is what an attacker computes from a copy."""
        assert SHA256 == hashlib.sha256(CONTENT.encode()).hexdigest()
        assert TOKEN != SHA256

    def test_holding_the_document_does_not_reproduce_it(self):
        """Without the owner's key there is nothing to compare against."""
        assert file_hash_token(SHA256, INTRUDER_DEK) != TOKEN

    def test_a_reupload_by_the_owner_is_still_recognised(self):
        """Deterministic per owner, which is what duplicate detection needs."""
        assert file_hash_token(SHA256, OWNER_DEK) == TOKEN

    def test_two_owners_of_the_same_file_do_not_look_alike(self):
        """The same document under two accounts must not be visibly the same."""
        tokens = {file_hash_token(SHA256, dek) for dek in (OWNER_DEK, INTRUDER_DEK)}
        assert len(tokens) == 2

    def test_it_is_not_the_vector_stores_token(self):
        """Distinct domains: knowing one token must not give away the other."""
        assert file_hash_token(SHA256, OWNER_DEK) != hash_token(SHA256, OWNER_DEK)


class TestTheDeleteFilterStillMatches:
    """Removing a file from a knowledge base filters vectors by the SQL token.

    The vector store keys metadata.hash once more with the collection's key on
    the way in, and translates filters the same way on the way out — so the
    opaque SQL token, quoted back by anyone holding the collection's key, still
    finds the chunks it was stored with.
    """

    def test_the_quoted_sql_token_finds_the_stored_chunk(self):
        collection_key = generate_dek()

        items = [{"metadata": {"hash": TOKEN}}]
        encrypt_items(items, collection_key)
        stored = items[0]["metadata"]["hash"]

        filter = _protect_filter({"hash": TOKEN}, collection_key, "kb-collection")
        assert filter["hash"] == stored

    def test_the_plain_sha256_finds_nothing(self):
        """An attacker quoting the hash of a document they hold matches no chunk."""
        collection_key = generate_dek()

        items = [{"metadata": {"hash": TOKEN}}]
        encrypt_items(items, collection_key)
        stored = items[0]["metadata"]["hash"]

        filter = _protect_filter({"hash": SHA256}, collection_key, "kb-collection")
        assert filter["hash"] != stored


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[File.__table__])
    session = sessionmaker(bind=engine)()

    cache_dek(OWNER, OWNER_DEK, jti=OWNER, expires_at=time.time() + 3600)
    cache_dek(INTRUDER, INTRUDER_DEK, jti=INTRUDER, expires_at=time.time() + 3600)
    set_current_user_id(OWNER)

    now = int(time.time())
    session.add(
        File(
            id="f1",
            user_id=OWNER,
            filename="plan.txt",
            path="/uploads/f1",
            data={"content": CONTENT},
            meta={"name": "plan.txt"},
            hash=TOKEN,
            created_at=now,
            updated_at=now,
        )
    )
    session.commit()
    session.expire_all()

    yield session

    set_current_user_id(None)
    session.close()
    engine.dispose()
    crypto_context._dek_cache.clear()


class TestAtRest:
    def test_the_row_stores_the_token_as_is(self, db):
        """Already keyed when it arrives, so the column needs no encrypting."""
        raw = db.execute(text("SELECT hash FROM file WHERE id = 'f1'")).scalar()
        assert raw == TOKEN
        assert raw != SHA256

    def test_anyone_may_read_it_without_the_owners_key(self, db):
        """Deleting is not reading: the paths that quote the token back — a
        shared-knowledge member, an administrator cleaning up — hold no key for
        this row and must not need one."""
        set_current_user_id(INTRUDER)
        assert Files.get_file_hash_by_id("f1", db=db) == TOKEN

    def test_a_missing_file_has_no_hash(self, db):
        assert Files.get_file_hash_by_id("no-such-file", db=db) is None

    def test_a_new_token_is_stored_as_given(self, db):
        other = file_hash_token("some-other-sha256", OWNER_DEK)
        Files.update_file_hash_by_id("f1", other, db=db)

        raw = db.execute(text("SELECT hash FROM file WHERE id = 'f1'")).scalar()
        assert raw == other

    def test_clearing_it_is_allowed(self, db):
        """process_file clears the hash on failure so the upload can be retried."""
        Files.update_file_hash_by_id("f1", None, db=db)
        assert Files.get_file_hash_by_id("f1", db=db) is None


def test_the_registry_leaves_the_hash_column_out():
    """Deliberate: the column holds an owner-keyed token, never user content,
    and encrypting it would take the delete paths away from everyone else."""
    assert ENCRYPTED_MODELS[File].text == ("filename",)
