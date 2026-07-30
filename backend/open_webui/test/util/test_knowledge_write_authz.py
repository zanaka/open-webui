import asyncio
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.files import File, Files
from open_webui.models.groups import Group, GroupMember
from open_webui.models.knowledge import Knowledge
from open_webui.models.users import User
from open_webui.routers import retrieval
from open_webui.routers.retrieval import (
    BatchProcessFilesForm,
    process_files_batch,
    require_knowledge_write_access,
)
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek, set_current_user_id
from open_webui.utils.crypto_utils import generate_dek

# File columns are encrypted on the way in and out.
import open_webui.utils.file_hooks  # noqa: F401


OWNER = "kb-owner"
WRITER = "kb-writer"
READER = "kb-reader"
STRANGER = "kb-stranger"
KB_ID = "kb-1"
FILE_ID = "file-1"
STORED_CONTENT = "the real contents of the owner's file"


def _user(user_id, role="user"):
    return SimpleNamespace(id=user_id, role=role)


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
            Group.__table__,
            GroupMember.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()

    cache_dek(OWNER, generate_dek(), jti="jti-owner", expires_at=time.time() + 3600)
    set_current_user_id(OWNER)

    now = int(time.time())
    session.add(
        Knowledge(
            id=KB_ID,
            user_id=OWNER,
            name="Shared knowledge",
            description="",
            meta=None,
            # Shared for reading with READER, for writing with WRITER.
            access_control={
                "read": {"user_ids": [READER], "group_ids": []},
                "write": {"user_ids": [WRITER], "group_ids": []},
            },
            created_at=now,
            updated_at=now,
        )
    )
    session.add(
        File(
            id=FILE_ID,
            user_id=OWNER,
            filename="report.txt",
            path=f"/uploads/{FILE_ID}",
            data={"content": STORED_CONTENT},
            meta={"name": "report.txt", "content_type": "text/plain"},
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


class TestRequireKnowledgeWriteAccess:
    def test_owner_may_write(self, db):
        require_knowledge_write_access(KB_ID, _user(OWNER), db=db)

    def test_write_member_may_write(self, db):
        require_knowledge_write_access(KB_ID, _user(WRITER), db=db)

    def test_admin_may_write(self, db):
        require_knowledge_write_access(KB_ID, _user(STRANGER, role="admin"), db=db)

    def test_read_only_member_is_refused(self, db):
        """Read members hold the same key as writers, so the key cannot be the check."""
        with pytest.raises(HTTPException) as raised:
            require_knowledge_write_access(KB_ID, _user(READER), db=db)
        assert raised.value.status_code == 403

    def test_unrelated_user_is_refused(self, db):
        with pytest.raises(HTTPException) as raised:
            require_knowledge_write_access(KB_ID, _user(STRANGER), db=db)
        assert raised.value.status_code == 403

    def test_missing_knowledge_base_is_not_found(self, db):
        with pytest.raises(HTTPException) as raised:
            require_knowledge_write_access("no-such-kb", _user(OWNER), db=db)
        assert raised.value.status_code == 404


class TestProcessFilesBatch:
    def _run(self, db, user, files):
        return asyncio.run(
            process_files_batch(
                request=None,
                form_data=BatchProcessFilesForm(
                    files=files, collection_name=KB_ID
                ),
                user=user,
                db=db,
            )
        )

    def test_read_only_member_cannot_add_chunks(self, db, monkeypatch):
        monkeypatch.setattr(retrieval, "knowledge_key", lambda *a, **kw: b"k" * 32)
        stored = Files.get_file_by_id(FILE_ID, db=db)

        with pytest.raises(HTTPException) as raised:
            self._run(db, _user(READER), [stored])

        assert raised.value.status_code == 403

    def test_indexes_the_stored_file_not_the_submitted_one(self, db, monkeypatch):
        """Only the id is taken from the request; the content comes from the database."""
        captured = {}

        def _fake_save(request, docs, collection_name, **kwargs):
            captured["docs"] = docs
            return True

        monkeypatch.setattr(retrieval, "save_docs_to_vector_db", _fake_save)
        monkeypatch.setattr(retrieval, "knowledge_key", lambda *a, **kw: b"k" * 32)

        stored = Files.get_file_by_id(FILE_ID, db=db)
        tampered = stored.model_copy(
            update={
                "data": {"content": "INJECTED CONTENT"},
                "user_id": STRANGER,
                "filename": "spoofed.txt",
            }
        )

        self._run(db, _user(OWNER), [tampered])

        indexed = captured["docs"][0]
        assert indexed.page_content == STORED_CONTENT
        assert "INJECTED" not in indexed.page_content
        assert indexed.metadata["created_by"] == OWNER
        assert indexed.metadata["name"] == "report.txt"

    def test_another_users_file_is_not_indexed(self, db, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            retrieval,
            "save_docs_to_vector_db",
            lambda request, docs, collection_name, **kw: captured.setdefault(
                "docs", docs
            ),
        )
        monkeypatch.setattr(retrieval, "knowledge_key", lambda *a, **kw: b"k" * 32)

        stored = Files.get_file_by_id(FILE_ID, db=db)
        someone_elses = stored.model_copy(update={"id": "file-not-mine"})

        response = self._run(db, _user(OWNER), [someone_elses])

        assert captured == {}
        assert [error.file_id for error in response.errors] == ["file-not-mine"]
