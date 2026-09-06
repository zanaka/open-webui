import time

import pytest
from conftest import run, sqlite_test_database

from open_webui.models.files import File, Files
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import (
    cache_dek,
    set_current_user_id,
)
from open_webui.utils.crypto_utils import generate_dek

# Ensure the encryption hooks are registered before File operations run.
from open_webui.utils.encrypted_models import install as install_column_encryption

install_column_encryption()


USER_ID = "test-user"


@pytest.fixture
def db(monkeypatch, tmp_path):
    with sqlite_test_database(
        monkeypatch, tmp_path / "test.db", tables=[File.__table__]
    ) as session:
        cache_dek(USER_ID, generate_dek(), jti="jti-1", expires_at=time.time() + 3600)
        set_current_user_id(USER_ID)
        yield session
        set_current_user_id(None)
        crypto_context._dek_cache.clear()


def _insert_files(db, names):
    now = int(time.time())
    for i, name in enumerate(names):
        # Spread updated_at so ordering is deterministic.
        db.add(
            File(
                id=f"f{i}",
                user_id=USER_ID,
                filename=name,
                path=f"/uploads/f{i}",
                data={},
                meta={"name": name},
                created_at=now,
                updated_at=now + i,
            )
        )
    db.commit()


class TestSearchFiles:
    def test_default_pattern_matches_all(self, db):
        _insert_files(db, ["a.txt", "b.pdf", "c.md"])
        results = run(Files.search_files(user_id=USER_ID))
        assert {r.filename for r in results} == {"a.txt", "b.pdf", "c.md"}

    def test_glob_extension_match(self, db):
        _insert_files(db, ["a.txt", "b.pdf", "c.txt"])
        results = run(Files.search_files(user_id=USER_ID, filename="*.txt"))
        assert {r.filename for r in results} == {"a.txt", "c.txt"}

    def test_glob_single_char(self, db):
        _insert_files(db, ["a.txt", "ab.txt", "abc.txt"])
        results = run(Files.search_files(user_id=USER_ID, filename="a?.txt"))
        assert {r.filename for r in results} == {"ab.txt"}

    def test_case_insensitive(self, db):
        _insert_files(db, ["Report.PDF", "memo.pdf"])
        results = run(Files.search_files(user_id=USER_ID, filename="*.pdf"))
        assert {r.filename for r in results} == {"Report.PDF", "memo.pdf"}

    def test_results_ordered_by_updated_at_desc(self, db):
        _insert_files(db, ["old.txt", "new.txt"])
        results = run(Files.search_files(user_id=USER_ID))
        # "new.txt" was inserted last (updated_at + 1).
        assert results[0].filename == "new.txt"

    def test_pagination(self, db):
        _insert_files(db, [f"{i}.txt" for i in range(10)])
        page1 = run(Files.search_files(user_id=USER_ID, skip=0, limit=3))
        page2 = run(Files.search_files(user_id=USER_ID, skip=3, limit=3))
        assert len(page1) == 3
        assert len(page2) == 3
        assert {f.filename for f in page1} & {f.filename for f in page2} == set()

    def test_user_filter(self, db):
        # Insert files for the test user, then add one for a different user.
        _insert_files(db, ["mine.txt"])
        other_dek = generate_dek()
        cache_dek("other-user", other_dek, jti="j2", expires_at=time.time() + 3600)
        set_current_user_id("other-user")
        try:
            db.add(
                File(
                    id="other",
                    user_id="other-user",
                    filename="theirs.txt",
                    path="/uploads/other",
                    data={},
                    meta={"name": "theirs.txt"},
                    created_at=int(time.time()),
                    updated_at=int(time.time()),
                )
            )
            db.commit()
        finally:
            set_current_user_id(USER_ID)

        results = run(Files.search_files(user_id=USER_ID))
        assert {r.filename for r in results} == {"mine.txt"}
