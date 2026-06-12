from dataclasses import dataclass

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.auths import Auth, Auths, UserWithDek
from open_webui.models.users import User
from open_webui.utils.crypto_utils import NONCE_SIZE, derive_kek, unwrap_dek

USER_A = {
    "email": "alice@example.com",
    "name": "Alice",
    "hashed_password": "hashed::alice",
    "raw_password": "alice-correct-horse",
}
USER_B = {
    "email": "bob@example.com",
    "name": "Bob",
    "hashed_password": "hashed::bob",
    "raw_password": "bob-battery-staple",
}


@dataclass
class Created:
    session: object
    a: UserWithDek
    b: UserWithDek


@pytest.fixture(scope="module")
def created() -> Created:
    """Create two accounts once (2 Argon2id derivations) and reuse them."""
    mp = pytest.MonkeyPatch()
    mp.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[User.__table__, Auth.__table__])
    session = sessionmaker(bind=engine)()

    a = Auths.insert_new_auth(
        email=USER_A["email"],
        hashed_password=USER_A["hashed_password"],
        name=USER_A["name"],
        raw_password=USER_A["raw_password"],
        role="user",
        db=session,
    )
    b = Auths.insert_new_auth(
        email=USER_B["email"],
        hashed_password=USER_B["hashed_password"],
        name=USER_B["name"],
        raw_password=USER_B["raw_password"],
        role="user",
        db=session,
    )

    yield Created(session=session, a=a, b=b)

    session.close()
    engine.dispose()
    mp.undo()


def _raw_auth_row(session, user_id):
    """Read the stored auth columns directly from SQL (bypassing the ORM)."""
    return session.execute(
        text(
            "SELECT kdf_salt, wrapped_dek, password FROM auth WHERE id = :id"
        ),
        {"id": user_id},
    ).one()


class TestReturnValue:
    def test_returns_user_with_dek(self, created):
        assert isinstance(created.a, UserWithDek)
        assert created.a.user.email == USER_A["email"]

    def test_returned_dek_is_256_bits(self, created):
        assert isinstance(created.a.dek, bytes)
        assert len(created.a.dek) == 32


class TestPersistence:
    def test_kdf_salt_persisted_as_16_bytes(self, created):
        kdf_salt, _, _ = _raw_auth_row(created.session, created.a.user.id)
        assert isinstance(kdf_salt, bytes)
        assert len(kdf_salt) == 16

    def test_wrapped_dek_persisted_with_expected_length(self, created):
        _, wrapped_dek, _ = _raw_auth_row(created.session, created.a.user.id)
        # nonce(12) + ciphertext(32, == DEK size) + GCM tag(16)
        assert len(wrapped_dek) == NONCE_SIZE + 32 + 16


class TestNoPlaintextLeak:
    def test_dek_is_stored_wrapped_not_plaintext(self, created):
        _, wrapped_dek, _ = _raw_auth_row(created.session, created.a.user.id)
        assert wrapped_dek != created.a.dek

    def test_password_column_is_hashed_not_raw(self, created):
        _, _, password = _raw_auth_row(created.session, created.a.user.id)
        assert password == USER_A["hashed_password"]
        assert USER_A["raw_password"] not in password


class TestWrappedDekRoundtrip:
    def test_wrapped_dek_unwraps_to_returned_dek(self, created):
        kdf_salt, wrapped_dek, _ = _raw_auth_row(
            created.session, created.a.user.id
        )
        kek = derive_kek(USER_A["raw_password"], kdf_salt)
        assert unwrap_dek(wrapped_dek, kek) == created.a.dek

    def test_wrong_password_cannot_unwrap(self, created):
        kdf_salt, wrapped_dek, _ = _raw_auth_row(
            created.session, created.a.user.id
        )
        wrong_kek = derive_kek("not-the-password", kdf_salt)
        with pytest.raises(InvalidTag):
            unwrap_dek(wrapped_dek, wrong_kek)


class TestKeySeparation:
    def test_two_users_get_distinct_dek(self, created):
        assert created.a.dek != created.b.dek

    def test_two_users_get_distinct_salt_and_wrapped_dek(self, created):
        salt_a, wrapped_a, _ = _raw_auth_row(created.session, created.a.user.id)
        salt_b, wrapped_b, _ = _raw_auth_row(created.session, created.b.user.id)
        assert salt_a != salt_b
        assert wrapped_a != wrapped_b
