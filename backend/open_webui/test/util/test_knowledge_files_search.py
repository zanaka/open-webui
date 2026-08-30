import time

import pytest
from conftest import run
from sqlalchemy import text

from open_webui.models.files import File
from open_webui.models.knowledge import Knowledge, KnowledgeFile, Knowledges

KNOWLEDGE_ID = "knowledge-1"


@pytest.fixture
def knowledge(db, accounts):
    now = int(time.time())
    db.add(
        Knowledge(
            id=KNOWLEDGE_ID,
            user_id=accounts.owner,
            name="Knowledge",
            description="Knowledge description",
            meta=None,
            created_at=now,
            updated_at=now,
        )
    )
    db.commit()
    return KNOWLEDGE_ID


def _insert_files(db, owner, names):
    now = int(time.time())
    for i, name in enumerate(names):
        file_id = f"file-{i}"
        db.add(
            File(
                id=file_id,
                user_id=owner,
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
                user_id=owner,
                created_at=now + i,
                updated_at=now + i,
            )
        )
    db.commit()
    db.expunge_all()


def _raw_filename(db, file_id):
    return db.execute(
        text("SELECT filename FROM file WHERE id = :id"),
        {"id": file_id},
    ).scalar_one()


class TestSearchKnowledgeFiles:
    def test_search_uses_decrypted_filename(self, db, accounts, knowledge):
        _insert_files(db, accounts.owner, ["report-alpha.txt", "memo-beta.txt"])
        assert "report-alpha" not in _raw_filename(db, "file-0")

        result = run(
            Knowledges.search_knowledge_files(
                filter={"user_id": accounts.owner, "query": "alpha"},
            )
        )

        assert result.total == 1
        assert [item.filename for item in result.items] == ["report-alpha.txt"]

    def test_search_paginates_after_filename_filter(self, db, accounts, knowledge):
        _insert_files(
            db,
            accounts.owner,
            ["alpha-1.txt", "beta.txt", "alpha-2.txt", "alpha-3.txt"],
        )

        result = run(
            Knowledges.search_knowledge_files(
                filter={"user_id": accounts.owner, "query": "alpha"},
                skip=1,
                limit=1,
            )
        )

        assert result.total == 3
        assert len(result.items) == 1


class TestSearchFilesById:
    def test_search_uses_decrypted_filename(self, db, accounts, knowledge):
        _insert_files(db, accounts.owner, ["report-alpha.txt", "memo-beta.txt"])

        result = run(
            Knowledges.search_files_by_id(
                KNOWLEDGE_ID,
                accounts.owner,
                filter={"query": "beta"},
            )
        )

        assert result.total == 1
        assert [item.filename for item in result.items] == ["memo-beta.txt"]

    def test_name_sort_uses_decrypted_filename_ascending(self, db, accounts, knowledge):
        _insert_files(db, accounts.owner, ["charlie.txt", "alpha.txt", "bravo.txt"])

        result = run(
            Knowledges.search_files_by_id(
                KNOWLEDGE_ID,
                accounts.owner,
                filter={"order_by": "name", "direction": "asc"},
            )
        )

        assert [item.filename for item in result.items] == [
            "alpha.txt",
            "bravo.txt",
            "charlie.txt",
        ]

    def test_name_sort_uses_decrypted_filename_descending(self, db, accounts, knowledge):
        _insert_files(db, accounts.owner, ["charlie.txt", "alpha.txt", "bravo.txt"])

        result = run(
            Knowledges.search_files_by_id(
                KNOWLEDGE_ID,
                accounts.owner,
                filter={"order_by": "name", "direction": "desc"},
            )
        )

        assert [item.filename for item in result.items] == [
            "charlie.txt",
            "bravo.txt",
            "alpha.txt",
        ]

    def test_search_paginates_after_filename_filter(self, db, accounts, knowledge):
        _insert_files(
            db,
            accounts.owner,
            ["alpha-1.txt", "beta.txt", "alpha-2.txt", "alpha-3.txt"],
        )

        result = run(
            Knowledges.search_files_by_id(
                KNOWLEDGE_ID,
                accounts.owner,
                filter={"query": "alpha"},
                skip=1,
                limit=1,
            )
        )

        assert result.total == 3
        assert len(result.items) == 1
