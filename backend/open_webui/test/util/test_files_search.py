import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.files import File, Files
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek
from open_webui.utils.crypto_utils import generate_dek

# Ensure the encryption hooks are registered before File operations run.
import open_webui.utils.file_hooks  # noqa: F401


USER_ID = "test-user"


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[File.__table__])
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    cache_dek(USER_ID, generate_dek(), jti="jti-1", expires_at=time.time() + 3600)
    yield session
    session.close()
    engine.dispose()
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
        results = Files.search_files(user_id=USER_ID, db=db)
        assert {r.filename for r in results} == {"a.txt", "b.pdf", "c.md"}

    def test_glob_extension_match(self, db):
        _insert_files(db, ["a.txt", "b.pdf", "c.txt"])
        results = Files.search_files(user_id=USER_ID, filename="*.txt", db=db)
        assert {r.filename for r in results} == {"a.txt", "c.txt"}

    def test_glob_single_char(self, db):
        _insert_files(db, ["a.txt", "ab.txt", "abc.txt"])
        results = Files.search_files(user_id=USER_ID, filename="a?.txt", db=db)
        assert {r.filename for r in results} == {"ab.txt"}

    def test_case_insensitive(self, db):
        _insert_files(db, ["Report.PDF", "memo.pdf"])
        results = Files.search_files(user_id=USER_ID, filename="*.pdf", db=db)
        assert {r.filename for r in results} == {"Report.PDF", "memo.pdf"}

    def test_results_ordered_by_updated_at_desc(self, db):
        _insert_files(db, ["old.txt", "new.txt"])
        results = Files.search_files(user_id=USER_ID, db=db)
        # "new.txt" was inserted last (updated_at + 1).
        assert results[0].filename == "new.txt"

    def test_pagination(self, db):
        _insert_files(db, [f"{i}.txt" for i in range(10)])
        page1 = Files.search_files(user_id=USER_ID, skip=0, limit=3, db=db)
        page2 = Files.search_files(user_id=USER_ID, skip=3, limit=3, db=db)
        assert len(page1) == 3
        assert len(page2) == 3
        assert {f.filename for f in page1} & {f.filename for f in page2} == set()

    def test_user_filter(self, db):
        # Insert files for the test user, then add one for a different user.
        _insert_files(db, ["mine.txt"])
        other_dek = generate_dek()
        cache_dek("other-user", other_dek, jti="j2", expires_at=time.time() + 3600)
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

        results = Files.search_files(user_id=USER_ID, db=db)
        assert {r.filename for r in results} == {"mine.txt"}
