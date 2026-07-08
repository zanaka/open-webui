import time

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from open_webui.internal.db import Base
from open_webui.models.memories import Memory
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek, set_current_user_id
from open_webui.utils.crypto_utils import decrypt_text, generate_dek

# Importing this module registers the SQLAlchemy event listeners for Memory.
import open_webui.utils.memory_hooks  # noqa: F401


USER_ID = "test-user"
CONTENT = "I am allergic to peanuts"


@pytest.fixture
def dek():
    key = generate_dek()
    cache_dek(USER_ID, key, jti="test-jti", expires_at=time.time() + 3600)
    set_current_user_id(USER_ID)
    yield key
    set_current_user_id(None)
    crypto_context._dek_cache.clear()


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[Memory.__table__])
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


def _raw_content(db, memory_id):
    row = db.execute(
        text("SELECT content FROM memory WHERE id = :id"), {"id": memory_id}
    ).first()
    return row[0] if row else None


def _make_memory(memory_id="m1", content=CONTENT):
    now = int(time.time())
    return Memory(
        id=memory_id, user_id=USER_ID, content=content, created_at=now, updated_at=now
    )


class TestInsertEncryption:
    def test_content_stored_as_ciphertext(self, db, dek):
        db.add(_make_memory())
        db.commit()

        raw = _raw_content(db, "m1")
        assert raw is not None
        assert raw != CONTENT
        assert "peanuts" not in raw
        assert decrypt_text(raw, dek) == CONTENT

    def test_inserted_object_returns_plaintext_in_memory(self, db, dek):
        m = _make_memory()
        db.add(m)
        db.commit()
        assert m.content == CONTENT


class TestLoadDecryption:
    def test_query_decrypts(self, db, dek):
        db.add(_make_memory())
        db.commit()
        db.expire_all()
        assert db.query(Memory).filter_by(id="m1").one().content == CONTENT

    def test_db_get_decrypts(self, db, dek):
        db.add(_make_memory())
        db.commit()
        db.expire_all()
        assert db.get(Memory, "m1").content == CONTENT


class TestUpdateEncryption:
    def test_update_re_encrypts(self, db, dek):
        db.add(_make_memory())
        db.commit()
        m = db.get(Memory, "m1")
        m.content = "I moved to Tokyo"
        db.commit()

        raw = _raw_content(db, "m1")
        assert "Tokyo" not in raw
        assert decrypt_text(raw, dek) == "I moved to Tokyo"


class TestAccessControl:
    def test_missing_owner_dek_cannot_decrypt(self, db, dek):
        db.add(_make_memory())
        db.commit()
        db.expire_all()

        crypto_context._dek_cache.clear()
        cache_dek("other-user", generate_dek(), jti="j2", expires_at=time.time() + 3600)
        set_current_user_id("other-user")
        with pytest.raises(Exception):
            db.query(Memory).filter_by(id="m1").one()

    def test_insert_without_dek_raises(self, db):
        crypto_context._dek_cache.clear()
        set_current_user_id(None)
        with pytest.raises(Exception):
            db.add(_make_memory())
            db.commit()
