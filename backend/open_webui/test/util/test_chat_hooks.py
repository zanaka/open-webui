import base64
import json
import time

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from open_webui.internal.db import Base
from open_webui.models.chats import Chat
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek, set_current_user_id
from open_webui.utils.crypto_utils import decrypt_value, generate_dek

# Importing this module registers the SQLAlchemy event listeners for Chat.
from open_webui.utils.encrypted_models import install as install_column_encryption

install_column_encryption()

USER_ID = "chat-user"
TITLE = "Project Phoenix"
BODY = "launch the rocket at dawn"


@pytest.fixture(autouse=True)
def _current_user():
    """Stand in for an authenticated request from USER_ID."""
    set_current_user_id(USER_ID)
    yield
    set_current_user_id(None)


@pytest.fixture
def dek() -> bytes:
    key = generate_dek()
    cache_dek(USER_ID, key, jti="chat-jti", expires_at=time.time() + 3600)
    yield key
    crypto_context._dek_cache.clear()


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[Chat.__table__])
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


def _make_chat(chat_id="c1", title=TITLE, body=BODY):
    now = int(time.time())
    return Chat(
        id=chat_id,
        user_id=USER_ID,
        title=title,
        chat={"messages": [{"role": "user", "content": body}]},
        meta={"tags": []},
        created_at=now,
        updated_at=now,
    )


def _raw_row(db, chat_id):
    return db.execute(
        text("SELECT title, chat FROM chat WHERE id = :id"),
        {"id": chat_id},
    ).first()


def _decrypt_title(raw_title, dek):
    return decrypt_value(base64.b64decode(raw_title), dek).decode("utf-8")


def _decrypt_chat(raw_chat, dek):
    inner = json.loads(raw_chat)
    return json.loads(decrypt_value(base64.b64decode(inner), dek).decode("utf-8"))


def _tamper_b64(b64_str):
    raw = bytearray(base64.b64decode(b64_str))
    raw[-1] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


class TestInsertEncryption:
    def test_title_stored_as_ciphertext(self, db, dek):
        db.add(_make_chat())
        db.commit()

        raw_title, _ = _raw_row(db, "c1")
        assert raw_title != TITLE
        assert "Phoenix" not in raw_title
        assert _decrypt_title(raw_title, dek) == TITLE

    def test_chat_body_stored_as_ciphertext(self, db, dek):
        db.add(_make_chat())
        db.commit()

        _, raw_chat = _raw_row(db, "c1")
        assert "rocket" not in raw_chat
        assert _decrypt_chat(raw_chat, dek) == {
            "messages": [{"role": "user", "content": BODY}]
        }

    def test_inserted_object_returns_plaintext_in_memory(self, db, dek):
        c = _make_chat()
        db.add(c)
        db.commit()

        assert c.title == TITLE
        assert c.chat == {"messages": [{"role": "user", "content": BODY}]}


class TestLoadDecryption:
    def test_query_decrypts(self, db, dek):
        db.add(_make_chat())
        db.commit()
        db.expire_all()

        loaded = db.query(Chat).filter_by(id="c1").one()
        assert loaded.title == TITLE
        assert loaded.chat == {"messages": [{"role": "user", "content": BODY}]}

    def test_db_get_decrypts(self, db, dek):
        db.add(_make_chat())
        db.commit()
        db.expire_all()

        loaded = db.get(Chat, "c1")
        assert loaded.title == TITLE


class TestUpdateEncryption:
    def test_update_re_encrypts(self, db, dek):
        db.add(_make_chat())
        db.commit()

        c = db.query(Chat).filter_by(id="c1").one()
        c.title = "Renamed Title"
        c.chat = {"messages": [{"role": "user", "content": "different secret"}]}
        db.commit()

        raw_title, raw_chat = _raw_row(db, "c1")
        assert "Renamed" not in raw_title
        assert "different secret" not in raw_chat
        assert _decrypt_title(raw_title, dek) == "Renamed Title"
        assert _decrypt_chat(raw_chat, dek) == {
            "messages": [{"role": "user", "content": "different secret"}]
        }


class TestTamperDetection:
    def test_tampered_title_raises_on_load(self, db, dek):
        db.add(_make_chat())
        db.commit()

        raw_title, _ = _raw_row(db, "c1")
        db.execute(
            text("UPDATE chat SET title = :v WHERE id = :id"),
            {"v": _tamper_b64(raw_title), "id": "c1"},
        )
        db.commit()
        db.expire_all()

        with pytest.raises(InvalidTag):
            db.query(Chat).filter_by(id="c1").one()

    def test_tampered_chat_raises_on_load(self, db, dek):
        db.add(_make_chat())
        db.commit()

        _, raw_chat = _raw_row(db, "c1")
        tampered_inner = _tamper_b64(json.loads(raw_chat))
        db.execute(
            text("UPDATE chat SET chat = :v WHERE id = :id"),
            {"v": json.dumps(tampered_inner), "id": "c1"},
        )
        db.commit()
        db.expire_all()

        with pytest.raises(InvalidTag):
            db.query(Chat).filter_by(id="c1").one()


class TestDekRequired:
    def test_insert_without_dek_raises(self, db):
        with pytest.raises(RuntimeError, match="No DEK cached"):
            db.add(_make_chat())
            db.commit()

    def test_load_without_dek_raises(self, db, dek):
        db.add(_make_chat())
        db.commit()
        db.expire_all()
        crypto_context._dek_cache.clear()

        with pytest.raises(RuntimeError, match="No DEK cached"):
            db.query(Chat).filter_by(id="c1").one()
