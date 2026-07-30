import time

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.tags import Tag, Tags
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek, set_current_user_id
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.encrypted_models import install
from open_webui.utils.tag_tokens import normalize_tag_name, tag_id

install()

USER_ID = "tag-user"
OTHER_USER_ID = "other-tag-user"
TAG_NAME = "Project Falcon"


@pytest.fixture(autouse=True)
def _keys():
    """Two signed-in users; the request belongs to USER_ID."""
    cache_dek(USER_ID, generate_dek(), jti="jti-1", expires_at=time.time() + 3600)
    cache_dek(
        OTHER_USER_ID, generate_dek(), jti="jti-2", expires_at=time.time() + 3600
    )
    set_current_user_id(USER_ID)

    yield

    set_current_user_id(None)
    crypto_context._dek_cache.clear()


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[Tag.__table__])
    session = sessionmaker(bind=engine)()

    yield session

    session.close()
    engine.dispose()


def _raw(db):
    return " ".join(
        f"{row[0]} {row[1]}"
        for row in db.execute(text("SELECT id, name FROM tag")).all()
    )


class TestTagId:
    def test_is_the_same_every_time(self):
        assert tag_id(TAG_NAME, USER_ID) == tag_id(TAG_NAME, USER_ID)

    def test_ignores_case_and_underscores_like_the_old_slug_did(self):
        assert tag_id("Project Falcon", USER_ID) == tag_id("project_falcon", USER_ID)

    def test_differs_between_users(self):
        set_current_user_id(OTHER_USER_ID)
        theirs = tag_id(TAG_NAME, OTHER_USER_ID)
        set_current_user_id(USER_ID)

        assert tag_id(TAG_NAME, USER_ID) != theirs

    def test_does_not_contain_the_name(self):
        token = tag_id(TAG_NAME, USER_ID)

        assert "falcon" not in token.lower()
        assert normalize_tag_name(TAG_NAME) not in token

    def test_is_lowercase_hex(self):
        """Callers re-normalise ids with .lower(), so the token must survive it."""
        token = tag_id(TAG_NAME, USER_ID)

        assert token == token.lower()
        assert all(character in "0123456789abcdef" for character in token)

    def test_refuses_another_users_tag(self):
        with pytest.raises(Exception):
            tag_id(TAG_NAME, OTHER_USER_ID)


class TestAtRest:
    def test_neither_the_id_nor_the_name_spells_the_tag(self, db):
        Tags.insert_new_tag(TAG_NAME, USER_ID, db=db)

        stored = _raw(db).lower()
        assert "falcon" not in stored

    def test_round_trips(self, db):
        created = Tags.insert_new_tag(TAG_NAME, USER_ID, db=db)

        assert created.name == TAG_NAME
        assert Tags.get_tag_by_name_and_user_id(TAG_NAME, USER_ID, db=db).name == (
            TAG_NAME
        )


class TestLookup:
    def test_finds_the_tag_by_name(self, db):
        created = Tags.insert_new_tag(TAG_NAME, USER_ID, db=db)

        found = Tags.get_tag_by_name_and_user_id(TAG_NAME, USER_ID, db=db)

        assert found.id == created.id

    def test_normalisation_still_applies(self, db):
        created = Tags.insert_new_tag(TAG_NAME, USER_ID, db=db)

        found = Tags.get_tag_by_name_and_user_id("project_falcon", USER_ID, db=db)

        assert found.id == created.id

    def test_unknown_name_is_not_found(self, db):
        Tags.insert_new_tag(TAG_NAME, USER_ID, db=db)

        assert Tags.get_tag_by_name_and_user_id("no such tag", USER_ID, db=db) is None

    def test_lookup_by_id_still_works(self, db):
        created = Tags.insert_new_tag(TAG_NAME, USER_ID, db=db)

        found = Tags.get_tags_by_ids_and_user_id([created.id], USER_ID, db=db)

        assert [tag.name for tag in found] == [TAG_NAME]

    def test_delete_by_name(self, db):
        Tags.insert_new_tag(TAG_NAME, USER_ID, db=db)

        assert Tags.delete_tag_by_name_and_user_id(TAG_NAME, USER_ID, db=db) is True
        assert Tags.get_tag_by_name_and_user_id(TAG_NAME, USER_ID, db=db) is None
