import time

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.files import File
from open_webui.models.knowledge import Knowledge, KnowledgeFile, Knowledges
from open_webui.models.users import User
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek
from open_webui.utils.crypto_utils import generate_dek

# Ensure File ORM load/save operations transparently encrypt/decrypt columns.
import open_webui.utils.file_hooks  # noqa: F401


USER_ID = "knowledge-user"
KNOWLEDGE_ID = "knowledge-1"


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(
        engine,
        tables=[
            User.__table__,
            File.__table__,
            Knowledge.__table__,
            KnowledgeFile.__table__,
        ],
    )
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    cache_dek(USER_ID, generate_dek(), jti="jti-1", expires_at=time.time() + 3600)
    _insert_user(session)
    _insert_knowledge(session)
    yield session
    session.close()
    engine.dispose()
    crypto_context._dek_cache.clear()


def _insert_user(db):
    now = int(time.time())
    db.add(
        User(
            id=USER_ID,
            email="knowledge-user@example.com",
            role="user",
            name="Knowledge User",
            profile_image_url="/user.png",
            last_active_at=now,
            created_at=now,
            updated_at=now,
        )
    )
    db.commit()


def _insert_knowledge(db):
    now = int(time.time())
    db.add(
        Knowledge(
            id=KNOWLEDGE_ID,
            user_id=USER_ID,
            name="Knowledge",
            description="Knowledge description",
            meta=None,
            access_control=None,
            created_at=now,
            updated_at=now,
        )
    )
    db.commit()


def _insert_files(db, names):
    now = int(time.time())
    for i, name in enumerate(names):
        file_id = f"file-{i}"
        db.add(
            File(
                id=file_id,
                user_id=USER_ID,
                filename=name,
                path=f"/uploads/{file_id}",
                data={"status": "completed", "content": f"content for {name}"},
                meta={"name": name, "content_type": "text/plain"},
                created_at=now + i,
                updated_at=now + i,
            )
        )
        db.add(
            KnowledgeFile(
                id=f"kf-{i}",
                knowledge_id=KNOWLEDGE_ID,
                file_id=file_id,
                user_id=USER_ID,
                created_at=now + i,
                updated_at=now + i,
            )
        )
    db.commit()
    db.expire_all()


def _raw_filename(db, file_id):
    return db.execute(
        text("SELECT filename FROM file WHERE id = :id"),
        {"id": file_id},
    ).scalar_one()


class TestSearchKnowledgeFiles:
    def test_search_uses_decrypted_filename(self, db):
        _insert_files(db, ["report-alpha.txt", "memo-beta.txt"])
        assert "report-alpha" not in _raw_filename(db, "file-0")

        result = Knowledges.search_knowledge_files(
            filter={"user_id": USER_ID, "query": "alpha"},
            db=db,
        )

        assert result.total == 1
        assert [item.filename for item in result.items] == ["report-alpha.txt"]

    def test_search_paginates_after_filename_filter(self, db):
        _insert_files(
            db,
            ["alpha-1.txt", "beta.txt", "alpha-2.txt", "alpha-3.txt"],
        )

        result = Knowledges.search_knowledge_files(
            filter={"user_id": USER_ID, "query": "alpha"},
            skip=1,
            limit=1,
            db=db,
        )

        assert result.total == 3
        assert len(result.items) == 1


class TestSearchFilesById:
    def test_search_uses_decrypted_filename(self, db):
        _insert_files(db, ["report-alpha.txt", "memo-beta.txt"])

        result = Knowledges.search_files_by_id(
            KNOWLEDGE_ID,
            USER_ID,
            filter={"query": "beta"},
            db=db,
        )

        assert result.total == 1
        assert [item.filename for item in result.items] == ["memo-beta.txt"]

    def test_name_sort_uses_decrypted_filename_ascending(self, db):
        _insert_files(db, ["charlie.txt", "alpha.txt", "bravo.txt"])

        result = Knowledges.search_files_by_id(
            KNOWLEDGE_ID,
            USER_ID,
            filter={"order_by": "name", "direction": "asc"},
            db=db,
        )

        assert [item.filename for item in result.items] == [
            "alpha.txt",
            "bravo.txt",
            "charlie.txt",
        ]

    def test_name_sort_uses_decrypted_filename_descending(self, db):
        _insert_files(db, ["charlie.txt", "alpha.txt", "bravo.txt"])

        result = Knowledges.search_files_by_id(
            KNOWLEDGE_ID,
            USER_ID,
            filter={"order_by": "name", "direction": "desc"},
            db=db,
        )

        assert [item.filename for item in result.items] == [
            "charlie.txt",
            "bravo.txt",
            "alpha.txt",
        ]

    def test_search_paginates_after_filename_filter(self, db):
        _insert_files(
            db,
            ["alpha-1.txt", "beta.txt", "alpha-2.txt", "alpha-3.txt"],
        )

        result = Knowledges.search_files_by_id(
            KNOWLEDGE_ID,
            USER_ID,
            filter={"query": "alpha"},
            skip=1,
            limit=1,
            db=db,
        )

        assert result.total == 3
        assert len(result.items) == 1
