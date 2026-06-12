from dataclasses import dataclass

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.auths import Auth, Auths
from open_webui.models.users import User
from open_webui.utils.crypto_utils import derive_kek, unwrap_dek

EMAIL = "alice@example.com"
NAME = "Alice"
OLD_RAW_PASSWORD = "alice-old-passphrase"
OLD_HASH_PASSWORD = "hashed::alice-old"
NEW_RAW_PASSWORD = "alice-new-passphrase"
NEW_HASH_PASSWORD = "hashed::alice-new"


def _raw_auth_row(session, user_id):
    return session.execute(
        text("SELECT kdf_salt, wrapped_dek, password FROM auth WHERE id = :id"),
        {"id": user_id},
    ).one()


def _make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[User.__table__, Auth.__table__])
    return engine, sessionmaker(bind=engine)()


@dataclass
class Changed:
    session: object
    user_id: str
    result: bool
    original_dek: bytes
    original_salt: bytes
    original_wrapped_dek: bytes
    new_salt: bytes
    new_wrapped_dek: bytes
    new_password: str


@pytest.fixture(scope="module")
def changed() -> Changed:
    mp = pytest.MonkeyPatch()
    mp.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)
    engine, session = _make_session()

    created = Auths.insert_new_auth(
        email=EMAIL,
        hashed_password=OLD_HASH_PASSWORD,
        name=NAME,
        raw_password=OLD_RAW_PASSWORD,
        role="user",
        db=session,
    )
    user_id = created.user.id
    original_salt, original_wrapped_dek, _ = _raw_auth_row(session, user_id)

    result = Auths.update_user_password_by_id(
        user_id,
        NEW_HASH_PASSWORD,
        NEW_RAW_PASSWORD,
        OLD_RAW_PASSWORD,
        db=session,
    )

    new_salt, new_wrapped_dek, new_password = _raw_auth_row(session, user_id)

    yield Changed(
        session=session,
        user_id=user_id,
        result=result,
        original_dek=created.dek,
        original_salt=original_salt,
        original_wrapped_dek=original_wrapped_dek,
        new_salt=new_salt,
        new_wrapped_dek=new_wrapped_dek,
        new_password=new_password,
    )

    session.close()
    engine.dispose()
    mp.undo()


@dataclass
class Rejected:
    result: bool
    before: tuple
    after: tuple


@pytest.fixture(scope="module")
def rejected() -> Rejected:
    mp = pytest.MonkeyPatch()
    mp.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)
    engine, session = _make_session()

    created = Auths.insert_new_auth(
        email=EMAIL,
        hashed_password=OLD_HASH_PASSWORD,
        name=NAME,
        raw_password=OLD_RAW_PASSWORD,
        role="user",
        db=session,
    )
    user_id = created.user.id
    before = _raw_auth_row(session, user_id)

    result = Auths.update_user_password_by_id(
        user_id,
        NEW_HASH_PASSWORD,
        NEW_RAW_PASSWORD,
        "wrong-current-password",
        db=session,
    )

    after = _raw_auth_row(session, user_id)

    yield Rejected(result=result, before=before, after=after)

    session.close()
    engine.dispose()
    mp.undo()


class TestSuccessfulChange:
    def test_returns_true(self, changed):
        assert changed.result is True

    def test_password_hash_updated(self, changed):
        assert changed.new_password == NEW_HASH_PASSWORD

    def test_wrapped_dek_is_rewrapped(self, changed):
        assert changed.new_wrapped_dek != changed.original_wrapped_dek

    def test_kdf_salt_is_reused(self, changed):
        assert changed.new_salt == changed.original_salt

    def test_dek_is_preserved_under_new_password(self, changed):
        new_kek = derive_kek(NEW_RAW_PASSWORD, changed.new_salt)
        assert unwrap_dek(changed.new_wrapped_dek, new_kek) == changed.original_dek


class TestRejectedChange:
    def test_wrong_current_password_returns_false(self, rejected):
        assert rejected.result is False

    def test_wrong_current_password_does_not_mutate(self, rejected):
        assert rejected.after == rejected.before

    def test_unknown_user_returns_false(self, changed):
        result = Auths.update_user_password_by_id(
            "no-such-user",
            NEW_HASH_PASSWORD,
            NEW_RAW_PASSWORD,
            OLD_RAW_PASSWORD,
            db=changed.session,
        )
        assert result is False
