import time

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from open_webui.internal.db import Base
from open_webui.models.files import File
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek
from open_webui.utils.crypto_utils import (
    decrypt_json_value,
    decrypt_text,
    generate_dek,
)

# Importing this module registers the SQLAlchemy event listeners globally
# for the File model. All File operations in this test module then go
# through the encryption hooks.
import open_webui.utils.file_hooks  # noqa: F401


USER_ID = "test-user"


@pytest.fixture
def dek() -> bytes:
    key = generate_dek()
    cache_dek(USER_ID, key, jti="test-jti", expires_at=time.time() + 3600)
    yield key
    crypto_context._dek_cache.clear()


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[File.__table__])
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.close()
    engine.dispose()


def _raw_row(db, file_id):
    row = db.execute(
        text("SELECT filename, data, meta FROM file WHERE id = :id"),
        {"id": file_id},
    ).first()
    return row  # (filename, data, meta) as raw SQL — no ORM event


def _make_file(file_id="f1", filename="report.pdf"):
    now = int(time.time())
    return File(
        id=file_id,
        user_id=USER_ID,
        filename=filename,
        path=f"/uploads/{file_id}",
        data={"status": "pending"},
        meta={"name": filename, "size": 1234},
        created_at=now,
        updated_at=now,
    )


class TestInsertEncryption:
    def test_filename_stored_as_ciphertext(self, db, dek):
        db.add(_make_file())
        db.commit()

        raw = _raw_row(db, "f1")
        assert raw is not None
        assert raw[0] != "report.pdf"
        assert "report" not in raw[0]
        # Sanity: decrypting the raw value with the test DEK returns the plaintext.
        assert decrypt_text(raw[0], dek) == "report.pdf"

    def test_data_stored_as_ciphertext(self, db, dek):
        db.add(_make_file())
        db.commit()

        raw = _raw_row(db, "f1")
        # JSON column is serialized as JSON-string of an encrypted base64 string.
        assert "pending" not in raw[1]
        # Strip the json.dumps surrounding quotes before decrypting.
        assert decrypt_json_value(raw[1].strip('"'), dek) == {"status": "pending"}

    def test_meta_stored_as_ciphertext(self, db, dek):
        db.add(_make_file())
        db.commit()

        raw = _raw_row(db, "f1")
        assert "report.pdf" not in raw[2]
        assert decrypt_json_value(raw[2].strip('"'), dek) == {
            "name": "report.pdf",
            "size": 1234,
        }

    def test_inserted_object_returns_plaintext_in_memory(self, db, dek):
        # After commit + after_insert hook restores plaintext for in-process callers.
        f = _make_file()
        db.add(f)
        db.commit()

        assert f.filename == "report.pdf"
        assert f.data == {"status": "pending"}
        assert f.meta == {"name": "report.pdf", "size": 1234}


class TestLoadDecryption:
    def test_query_decrypts(self, db, dek):
        db.add(_make_file())
        db.commit()
        db.expire_all()  # force reload from DB on next access

        loaded = db.query(File).filter_by(id="f1").one()
        assert loaded.filename == "report.pdf"
        assert loaded.data == {"status": "pending"}
        assert loaded.meta == {"name": "report.pdf", "size": 1234}

    def test_db_get_decrypts(self, db, dek):
        db.add(_make_file())
        db.commit()
        db.expire_all()

        loaded = db.get(File, "f1")
        assert loaded.filename == "report.pdf"


class TestUpdateEncryption:
    def test_update_re_encrypts(self, db, dek):
        db.add(_make_file())
        db.commit()

        f = db.query(File).filter_by(id="f1").one()
        f.filename = "renamed.pdf"
        f.data = {"status": "completed", "content": "extracted text"}
        db.commit()

        raw = _raw_row(db, "f1")
        assert "renamed" not in raw[0]
        assert "completed" not in raw[1]
        assert decrypt_text(raw[0], dek) == "renamed.pdf"
        assert decrypt_json_value(raw[1].strip('"'), dek) == {
            "status": "completed",
            "content": "extracted text",
        }

    def test_update_then_reload_returns_new_plaintext(self, db, dek):
        db.add(_make_file())
        db.commit()

        f = db.query(File).filter_by(id="f1").one()
        f.filename = "renamed.pdf"
        db.commit()
        db.expire_all()

        loaded = db.query(File).filter_by(id="f1").one()
        assert loaded.filename == "renamed.pdf"


class TestNoneHandling:
    def test_null_data_and_meta_roundtrip(self, db, dek):
        f = _make_file()
        f.data = None
        f.meta = None
        db.add(f)
        db.commit()

        raw = _raw_row(db, "f1")
        # SQLite stores JSON None as JSON null when viewed via raw SQL.
        assert raw[1] == "null"
        assert raw[2] == "null"

        db.expire_all()
        loaded = db.query(File).filter_by(id="f1").one()
        assert loaded.data is None
        assert loaded.meta is None


class TestDekRequired:
    def test_insert_without_dek_raises(self, db):
        # No DEK cached for USER_ID
        with pytest.raises(RuntimeError, match="No DEK cached"):
            db.add(_make_file())
            db.commit()

    def test_load_without_dek_raises(self, db, dek):
        db.add(_make_file())
        db.commit()
        db.expire_all()
        crypto_context._dek_cache.clear()

        with pytest.raises(RuntimeError, match="No DEK cached"):
            db.query(File).filter_by(id="f1").one()

    def test_update_without_dek_raises(self, db, dek):
        db.add(_make_file())
        db.commit()
        f = db.query(File).filter_by(id="f1").one()
        crypto_context._dek_cache.clear()

        f.filename = "renamed.pdf"
        with pytest.raises(RuntimeError, match="No DEK cached"):
            db.commit()
