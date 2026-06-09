import time

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.chats import Chat, Chats
from open_webui.models.users import User
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek
from open_webui.utils.crypto_utils import generate_dek

# Ensure Chat ORM load/save operations transparently encrypt/decrypt columns.
import open_webui.utils.chat_hooks  # noqa: F401


USER_ID = "chat-user"


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(
        engine,
        tables=[
            User.__table__,
            Chat.__table__,
        ],
    )
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    cache_dek(USER_ID, generate_dek(), jti="jti-1", expires_at=time.time() + 3600)
    _insert_user(session)
    yield session
    session.close()
    engine.dispose()
    crypto_context._dek_cache.clear()


def _insert_user(db):
    now = int(time.time())
    db.add(
        User(
            id=USER_ID,
            email="chat-user@example.com",
            role="user",
            name="Chat User",
            profile_image_url="/user.png",
            last_active_at=now,
            created_at=now,
            updated_at=now,
        )
    )
    db.commit()


def _chat_json(turns):
    messages = {}
    flat = []
    prev = None
    for i, (role, content) in enumerate(turns):
        mid = f"m{i}"
        node = {"id": mid, "role": role, "content": content, "parentId": prev}
        messages[mid] = node
        flat.append(node)
        prev = mid
    return {"history": {"messages": messages, "currentId": prev}, "messages": flat}


def _insert_chat(
    db,
    chat_id,
    title,
    turns=None,
    tags=None,
    pinned=False,
    archived=False,
    ts=None,
):
    now = ts if ts is not None else int(time.time())
    db.add(
        Chat(
            id=chat_id,
            user_id=USER_ID,
            title=title,
            chat=_chat_json(turns or [("user", "hello")]),
            meta={"tags": tags or []},
            pinned=pinned,
            archived=archived,
            created_at=now,
            updated_at=now,
        )
    )
    db.commit()
    db.expire_all()


def _raw_title(db, chat_id):
    return db.execute(
        text("SELECT title FROM chat WHERE id = :id"),
        {"id": chat_id},
    ).scalar_one()


def _search(db, query, **kwargs):
    return Chats.get_chats_by_user_id_and_search_text(
        USER_ID, query, db=db, **kwargs
    )


class TestTitleSearch:
    def test_filters_by_decrypted_title(self, db):
        _insert_chat(db, "c1", "Alpha project notes")
        _insert_chat(db, "c2", "Beta meeting log")

        # title is encrypted at rest -> the plaintext must not appear in the column
        assert "Alpha" not in _raw_title(db, "c1")
        result = _search(db, "alpha")
        assert [c.id for c in result] == ["c1"]


class TestBodySearch:
    def test_matches_body_when_title_does_not(self, db):
        _insert_chat(
            db,
            "c1",
            "Untitled chat",
            turns=[("user", "How do I configure pgvector?"), ("assistant", "Set it here")],
        )
        _insert_chat(db, "c2", "Untitled chat", turns=[("user", "unrelated")])

        assert "pgvector" not in _raw_title(db, "c1")
        result = _search(db, "pgvector")
        assert [c.id for c in result] == ["c1"]

    def test_matches_multimodal_text_content(self, db):
        _insert_chat(
            db,
            "c1",
            "Untitled chat",
            turns=[("user", [{"type": "text", "text": "look at this diagram"}])],
        )

        result = _search(db, "diagram")
        assert [c.id for c in result] == ["c1"]


class TestSpecialTokensSearch:
    def test_text_combined_with_tag_token(self, db):
        _insert_chat(db, "c1", "Alpha report", tags=["foo"])
        _insert_chat(db, "c2", "Alpha summary", tags=["bar"])
        _insert_chat(db, "c3", "Beta report", tags=["foo"])

        # "alpha" (text) AND tag:foo -> only c1 satisfies both
        result = _search(db, "alpha tag:foo")
        assert [c.id for c in result] == ["c1"]

    def test_text_combined_with_pinned_token(self, db):
        _insert_chat(db, "c1", "Alpha pinned", pinned=True)
        _insert_chat(db, "c2", "Alpha normal", pinned=False)

        result = _search(db, "alpha pinned:true")
        assert [c.id for c in result] == ["c1"]


class TestTokenOnlySearch:
    def test_tag_token_only_returns_all_tag_matches(self, db):
        _insert_chat(db, "c1", "Completely different title", tags=["foo"], ts=100)
        _insert_chat(db, "c2", "Another title", tags=["foo"], ts=200)
        _insert_chat(db, "c3", "Has no tag", tags=["bar"], ts=300)

        result = _search(db, "tag:foo")

        # order is updated_at desc; title text is irrelevant for a token-only query
        assert [c.id for c in result] == ["c2", "c1"]


class TestPagination:
    def test_pages_cover_all_matches_without_overlap(self, db):
        # 5 matching chats with increasing updated_at
        for i in range(5):
            _insert_chat(db, f"c{i}", f"Alpha note {i}", ts=1000 + i)

        page1 = _search(db, "alpha", skip=0, limit=2)
        page2 = _search(db, "alpha", skip=2, limit=2)
        page3 = _search(db, "alpha", skip=4, limit=2)

        ids1 = [c.id for c in page1]
        ids2 = [c.id for c in page2]
        ids3 = [c.id for c in page3]

        # expected order: newest first
        assert ids1 == ["c4", "c3"]
        assert ids2 == ["c2", "c1"]
        assert ids3 == ["c0"]

        all_ids = ids1 + ids2 + ids3
        assert len(all_ids) == 5  # no gaps
        assert len(set(all_ids)) == 5  # no overlap
