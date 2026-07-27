import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.knowledge import Knowledge, Knowledges
from open_webui.models.users import User

USER_ID = "kb-search-user"


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[User.__table__, Knowledge.__table__])
    session = sessionmaker(bind=engine)()

    now = int(time.time())
    session.add(
        User(
            id=USER_ID,
            email="kb-search@example.com",
            role="user",
            name="KB Search User",
            profile_image_url="/user.png",
            last_active_at=now,
            created_at=now,
            updated_at=now,
        )
    )
    session.commit()

    yield session

    session.close()
    engine.dispose()


def _add(db, knowledge_id, name, description="", ts=None):
    now = ts if ts is not None else int(time.time())
    db.add(
        Knowledge(
            id=knowledge_id,
            user_id=USER_ID,
            name=name,
            description=description,
            meta=None,
            access_control={},
            created_at=now,
            updated_at=now,
        )
    )
    db.commit()
    db.expire_all()


def _search(db, query, **kwargs):
    return Knowledges.search_knowledge_bases(
        USER_ID, filter={"query": query, "user_id": USER_ID}, db=db, **kwargs
    )


class TestSearch:
    """Names and descriptions are matched after they are read, so that this
    keeps working when they are encrypted at rest."""

    def test_matches_the_name(self, db):
        _add(db, "k1", "Project Falcon")
        _add(db, "k2", "Something Else")

        result = _search(db, "falcon")

        assert [item.id for item in result.items] == ["k1"]
        assert result.total == 1

    def test_matches_the_description(self, db):
        _add(db, "k1", "Untitled", description="notes about Falcon")
        _add(db, "k2", "Untitled", description="unrelated")

        result = _search(db, "falcon")

        assert [item.id for item in result.items] == ["k1"]

    def test_is_case_insensitive(self, db):
        _add(db, "k1", "Project Falcon")

        assert [item.id for item in _search(db, "FALCON").items] == ["k1"]

    def test_no_match_returns_nothing(self, db):
        _add(db, "k1", "Project Falcon")

        result = _search(db, "condor")

        assert result.items == []
        assert result.total == 0

    def test_total_counts_matches_not_rows(self, db):
        _add(db, "k1", "Falcon one", ts=100)
        _add(db, "k2", "Falcon two", ts=200)
        _add(db, "k3", "Something else", ts=300)

        result = _search(db, "falcon")

        assert result.total == 2

    def test_paginates_after_filtering(self, db):
        _add(db, "k1", "Falcon one", ts=100)
        _add(db, "k2", "Falcon two", ts=200)
        _add(db, "k3", "Falcon three", ts=300)

        result = _search(db, "falcon", skip=1, limit=1)

        assert result.total == 3
        assert len(result.items) == 1
        # Ordered by updated_at desc, so skipping one lands on the middle entry.
        assert result.items[0].id == "k2"

    def test_no_query_returns_everything(self, db):
        _add(db, "k1", "Project Falcon")
        _add(db, "k2", "Something Else")

        result = Knowledges.search_knowledge_bases(
            USER_ID, filter={"user_id": USER_ID}, db=db
        )

        assert result.total == 2
