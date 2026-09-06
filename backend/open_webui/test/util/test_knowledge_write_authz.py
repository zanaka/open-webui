import asyncio
import time
from types import SimpleNamespace

import pytest
from conftest import run
from fastapi import HTTPException

from open_webui.models.access_grants import AccessGrants
from open_webui.models.auths import Auths
from open_webui.models.files import File, Files
from open_webui.models.knowledge import Knowledge
from open_webui.routers import retrieval
from open_webui.routers.retrieval import (
    BatchProcessFilesForm,
    process_files_batch,
    require_knowledge_write_access,
)
from open_webui.utils.crypto_context import cache_dek

# Saving a knowledge base provisions its key and wraps a copy for every named
# recipient, so the people here have to be real accounts with key pairs, not
# invented ids. The conftest supplies the owner and a stranger; the named
# writer and reader are created below. Filled in by the module fixture.
OWNER = None
WRITER = None
READER = None
STRANGER = None
KB_ID = "kb-1"
FILE_ID = "file-1"
STORED_CONTENT = "the real contents of the owner's file"


def _user(user_id, role="user"):
    return SimpleNamespace(id=user_id, role=role)


@pytest.fixture(scope="module", autouse=True)
def people(accounts):
    global OWNER, WRITER, READER, STRANGER
    OWNER, STRANGER = accounts.owner, accounts.intruder

    ids = {}
    for name, password in (
        ("writer", "writer-correct-horse"),
        ("reader", "reader-battery-staple"),
    ):
        auth = run(
            Auths.insert_new_auth(
                email=f"kb-authz-{name}@example.com",
                hashed_password=f"hashed::{name}",
                name=name,
                raw_password=password,
                role="user",
            )
        )
        cache_dek(auth.user.id, auth.dek, f"jti-kb-authz-{name}", time.time() + 3600)
        ids[name] = auth.user.id
    WRITER, READER = ids["writer"], ids["reader"]


@pytest.fixture
def db(db):
    """The conftest database, seeded with the shared knowledge base and file.

    Committing the knowledge row runs the real provisioning path — a key is
    created and wrapped for the reader and the writer — which is what made the
    old self-contained in-memory fixture stop being enough.
    """
    now = int(time.time())
    db.add(
        Knowledge(
            id=KB_ID,
            user_id=OWNER,
            name="Shared knowledge",
            description="",
            meta=None,
            created_at=now,
            updated_at=now,
        )
    )
    db.add(
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
    db.commit()

    # Shared for reading with READER, for writing with WRITER.
    run(
        AccessGrants.set_access_grants(
            "knowledge",
            KB_ID,
            [
                {"principal_type": "user", "principal_id": READER, "permission": "read"},
                {"principal_type": "user", "principal_id": WRITER, "permission": "write"},
            ],
        )
    )
    db.expire_all()

    return db


class TestRequireKnowledgeWriteAccess:
    def test_owner_may_write(self, db):
        run(require_knowledge_write_access(KB_ID, _user(OWNER), db=db))

    def test_write_member_may_write(self, db):
        run(require_knowledge_write_access(KB_ID, _user(WRITER), db=db))

    def test_admin_may_write(self, db):
        run(require_knowledge_write_access(KB_ID, _user(STRANGER, role="admin"), db=db))

    def test_read_only_member_is_refused(self, db):
        """Read members hold the same key as writers, so the key cannot be the check."""
        with pytest.raises(HTTPException) as raised:
            run(require_knowledge_write_access(KB_ID, _user(READER), db=db))
        assert raised.value.status_code == 403

    def test_unrelated_user_is_refused(self, db):
        with pytest.raises(HTTPException) as raised:
            run(require_knowledge_write_access(KB_ID, _user(STRANGER), db=db))
        assert raised.value.status_code == 403

    def test_missing_knowledge_base_is_not_found(self, db):
        with pytest.raises(HTTPException) as raised:
            run(require_knowledge_write_access("no-such-kb", _user(OWNER), db=db))
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
        stored = run(Files.get_file_by_id(FILE_ID))

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

        stored = run(Files.get_file_by_id(FILE_ID))
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

        stored = run(Files.get_file_by_id(FILE_ID))
        someone_elses = stored.model_copy(update={"id": "file-not-mine"})

        response = self._run(db, _user(OWNER), [someone_elses])

        assert captured == {}
        assert [error.file_id for error in response.errors] == ["file-not-mine"]
