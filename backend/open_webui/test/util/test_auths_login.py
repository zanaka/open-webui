from dataclasses import dataclass

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.auths import Auth, Auths, UserWithDek
from open_webui.models.users import User

NOW = 1_700_000_000

ACTIVE = {
    "email": "alice@example.com",
    "name": "Alice",
    "hashed_password": "hashed::alice",
    "raw_password": "alice-correct-horse",
}
INACTIVE = {
    "id": "inactive-user",
    "name": "Ghost",
    "email": "ghost@example.com",
    "hashed_password": "hashed::ghost",
}


def _always_true(_stored_hash):
    return True


def _always_false(_stored_hash):
    return False


@dataclass
class Accounts:
    session: object
    created: UserWithDek


@pytest.fixture(scope="module")
def accounts() -> Accounts:
    mp = pytest.MonkeyPatch()
    mp.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[User.__table__, Auth.__table__])
    session = sessionmaker(bind=engine)()

    created = Auths.insert_new_auth(
        email=ACTIVE["email"],
        hashed_password=ACTIVE["hashed_password"],
        name=ACTIVE["name"],
        raw_password=ACTIVE["raw_password"],
        role="user",
        db=session,
    )

    # Inactive account
    session.add(
        User(
            id=INACTIVE["id"],
            email=INACTIVE["email"],
            role="user",
            name=INACTIVE["name"],
            profile_image_url="/user.png",
            last_active_at=NOW,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    session.add(
        Auth(
            id=INACTIVE["id"],
            email=INACTIVE["email"],
            password=INACTIVE["hashed_password"],
            active=False,
            kdf_salt=b"\x00" * 16,
            wrapped_dek=b"\x00" * 60,
        )
    )
    session.commit()

    yield Accounts(session=session, created=created)

    session.close()
    engine.dispose()
    mp.undo()


@pytest.fixture(scope="module")
def login_ok(accounts) -> UserWithDek:
    return Auths.authenticate_user(
        ACTIVE["email"],
        ACTIVE["raw_password"],
        verify_password=_always_true,
        db=accounts.session,
    )


class TestSuccessfulLogin:
    def test_returns_user_with_dek(self, login_ok):
        assert isinstance(login_ok, UserWithDek)
        assert login_ok.user.email == ACTIVE["email"]

    def test_recovers_the_signup_dek(self, login_ok, accounts):
        assert login_ok.dek == accounts.created.dek


class TestVerifyPasswordContract:
    def test_verify_password_receives_stored_hash(self, accounts):
        captured = {}

        def verify(stored_hash):
            captured["arg"] = stored_hash
            return False

        Auths.authenticate_user(
            ACTIVE["email"],
            ACTIVE["raw_password"],
            verify_password=verify,
            db=accounts.session,
        )
        assert captured["arg"] == ACTIVE["hashed_password"]


class TestFailedLogin:
    def test_wrong_password_hash_returns_none(self, accounts):
        result = Auths.authenticate_user(
            ACTIVE["email"],
            ACTIVE["raw_password"],
            verify_password=_always_false,
            db=accounts.session,
        )
        assert result is None

    def test_unknown_email_returns_none(self, accounts):
        result = Auths.authenticate_user(
            "nobody@example.com",
            "whatever_pass",
            verify_password=_always_true,
            db=accounts.session,
        )
        assert result is None

    def test_inactive_user_returns_none(self, accounts):
        result = Auths.authenticate_user(
            INACTIVE["email"],
            "whatever_pass",
            verify_password=_always_true,
            db=accounts.session,
        )
        assert result is None

    def test_hash_ok_but_wrong_raw_password_cannot_recover_dek(self, accounts):
        result = Auths.authenticate_user(
            ACTIVE["email"],
            "not-the-real-password",
            verify_password=_always_true,
            db=accounts.session,
        )
        assert result is None
