"""Searching archived chats.

The title and the messages are encrypted at rest, so the `ilike` this used to
run in SQL matched ciphertext and the search returned nothing — on a screen a
person reaches from the sidebar. Matching now happens after the rows are read,
the same way the ordinary chat search already worked.
"""

import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.chats import Chat, Chats
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek, set_current_user_id
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.encrypted_models import install as install_column_encryption

install_column_encryption()

USER_ID = "archive-user"


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[Chat.__table__])
    session = sessionmaker(bind=engine)()

    cache_dek(USER_ID, generate_dek(), jti="jti-1", expires_at=time.time() + 3600)
    set_current_user_id(USER_ID)

    yield session

    set_current_user_id(None)
    session.close()
    engine.dispose()
    crypto_context._dek_cache.clear()


def _add(db, chat_id, title, body="", archived=True, ts=None):
    now = ts if ts is not None else int(time.time())
    db.add(
        Chat(
            id=chat_id,
            user_id=USER_ID,
            title=title,
            chat={
                "history": {
                    "messages": {"m1": {"role": "user", "content": body}},
                }
            },
            meta={},
            archived=archived,
            created_at=now,
            updated_at=now,
        )
    )
    db.commit()
    db.expire_all()


def _search(db, query, **kwargs):
    return Chats.get_archived_chat_list_by_user_id(
        USER_ID, filter={"query": query}, db=db, **kwargs
    )


class TestSearch:
    def test_matches_the_title(self, db):
        _add(db, "c1", "Project Falcon")
        _add(db, "c2", "Something else")

        assert [chat.id for chat in _search(db, "falcon")] == ["c1"]

    def test_matches_a_message(self, db):
        _add(db, "c1", "Untitled", body="we should call it Falcon")
        _add(db, "c2", "Untitled", body="unrelated")

        assert [chat.id for chat in _search(db, "falcon")] == ["c1"]

    def test_is_case_insensitive(self, db):
        _add(db, "c1", "Project Falcon")

        assert [chat.id for chat in _search(db, "FALCON")] == ["c1"]

    def test_no_match_returns_nothing(self, db):
        _add(db, "c1", "Project Falcon")

        assert _search(db, "condor") == []

    def test_only_archived_chats_are_searched(self, db):
        _add(db, "c1", "Falcon archived", archived=True)
        _add(db, "c2", "Falcon current", archived=False)

        assert [chat.id for chat in _search(db, "falcon")] == ["c1"]

    def test_another_users_chat_is_not_searched(self, db):
        _add(db, "c1", "Falcon mine")

        # Written as its own owner, because a row is only ever written by the
        # person the request is running as.
        other = "someone-else"
        cache_dek(other, generate_dek(), jti="jti-2", expires_at=time.time() + 3600)
        set_current_user_id(other)
        db.add(
            Chat(
                id="c2",
                user_id=other,
                title="Falcon theirs",
                chat={},
                meta={},
                archived=True,
                created_at=1,
                updated_at=1,
            )
        )
        db.commit()
        db.expire_all()
        set_current_user_id(USER_ID)

        assert [chat.id for chat in _search(db, "falcon")] == ["c1"]

    def test_paginates_after_filtering(self, db):
        _add(db, "c1", "Falcon one", ts=100)
        _add(db, "c2", "Falcon two", ts=200)
        _add(db, "c3", "Not a match", ts=300)

        page = _search(db, "falcon", skip=1, limit=1)

        assert len(page) == 1
        # Ordered by updated_at desc, so skipping one lands on the older match.
        assert page[0].id == "c1"


class TestOrdering:
    def _ordered(self, db, direction):
        return [
            chat.title
            for chat in Chats.get_archived_chat_list_by_user_id(
                USER_ID,
                filter={"order_by": "title", "direction": direction},
                db=db,
            )
        ]

    def test_sorts_by_the_readable_title(self, db):
        """Sorting the ciphertext would put them in an arbitrary order."""
        for title in ("charlie", "alpha", "bravo"):
            _add(db, title, title)

        assert self._ordered(db, "asc") == ["alpha", "bravo", "charlie"]

    def test_sorts_descending_too(self, db):
        for title in ("charlie", "alpha", "bravo"):
            _add(db, title, title)

        assert self._ordered(db, "desc") == ["charlie", "bravo", "alpha"]

    def test_other_columns_still_sort_in_sql(self, db):
        _add(db, "old", "old", ts=100)
        _add(db, "new", "new", ts=200)

        result = Chats.get_archived_chat_list_by_user_id(
            USER_ID,
            filter={"order_by": "updated_at", "direction": "asc"},
            db=db,
        )

        assert [chat.id for chat in result] == ["old", "new"]

    def test_a_column_without_a_direction_falls_back(self, db):
        """`?order_by=title` with no direction is a shape the route can pass on."""
        _add(db, "old", "old", ts=100)
        _add(db, "new", "new", ts=200)

        result = Chats.get_archived_chat_list_by_user_id(
            USER_ID, filter={"order_by": "title"}, db=db
        )

        assert [chat.id for chat in result] == ["new", "old"]

    def test_a_sql_column_without_a_direction_falls_back(self, db):
        _add(db, "old", "old", ts=100)
        _add(db, "new", "new", ts=200)

        result = Chats.get_archived_chat_list_by_user_id(
            USER_ID, filter={"order_by": "updated_at"}, db=db
        )

        assert [chat.id for chat in result] == ["new", "old"]

    def test_a_direction_without_a_column_falls_back(self, db):
        _add(db, "old", "old", ts=100)
        _add(db, "new", "new", ts=200)

        result = Chats.get_archived_chat_list_by_user_id(
            USER_ID, filter={"direction": "asc"}, db=db
        )

        assert [chat.id for chat in result] == ["new", "old"]

    def test_an_unknown_column_is_refused(self, db):
        with pytest.raises(ValueError):
            Chats.get_archived_chat_list_by_user_id(
                USER_ID,
                filter={"order_by": "nonsense", "direction": "asc"},
                db=db,
            )

    def test_an_unknown_direction_is_refused(self, db):
        with pytest.raises(ValueError):
            Chats.get_archived_chat_list_by_user_id(
                USER_ID,
                filter={"order_by": "title", "direction": "sideways"},
                db=db,
            )


class TestHowMuchIsDecrypted:
    """Every row read here is decrypted, body and all, by the load hook.

    Searching has to pay that for the whole archive — a match cannot be
    decided on ciphertext. Merely opening the archive must not.
    """

    @pytest.fixture
    def counted(self, db, monkeypatch):
        import open_webui.utils.encrypted_models as em

        counts = {"bodies": 0}
        original = em.decrypt_json_value

        def counting(value, dek):
            counts["bodies"] += 1
            return original(value, dek)

        for i in range(20):
            _add(db, f"c{i}", f"title {i}", body="hello", ts=i)

        monkeypatch.setattr(em, "decrypt_json_value", counting)
        return db, counts

    def test_a_plain_page_only_reads_its_own_page(self, counted):
        db, counts = counted

        page = Chats.get_archived_chat_list_by_user_id(
            USER_ID, filter={}, skip=0, limit=5, db=db
        )

        assert len(page) == 5
        assert counts["bodies"] == 5, "the whole archive was decrypted for one page"

    def test_a_sql_ordered_page_only_reads_its_own_page(self, counted):
        db, counts = counted

        Chats.get_archived_chat_list_by_user_id(
            USER_ID,
            filter={"order_by": "updated_at", "direction": "desc"},
            skip=0,
            limit=5,
            db=db,
        )

        assert counts["bodies"] == 5

    def test_searching_pays_for_the_whole_archive(self, counted):
        """Not a regression — a match cannot be found without the plaintext."""
        db, counts = counted

        Chats.get_archived_chat_list_by_user_id(
            USER_ID, filter={"query": "hello"}, skip=0, limit=5, db=db
        )

        assert counts["bodies"] == 20
