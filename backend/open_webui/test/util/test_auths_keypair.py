import os
from dataclasses import dataclass

import pytest
from conftest import run, sqlite_test_database
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from sqlalchemy import text

from open_webui.models.auths import Auth, Auths, UserWithDek
from open_webui.models.users import User
from open_webui.utils.crypto_utils import (
    decrypt_value,
    generate_rsa_keypair,
    rsa_unwrap_key,
    rsa_wrap_key,
)

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
def created(tmp_path_factory) -> Created:
    mp = pytest.MonkeyPatch()
    db_path = tmp_path_factory.mktemp("auths-keypair") / "test.db"
    with sqlite_test_database(
        mp, db_path, tables=[User.__table__, Auth.__table__]
    ) as session:
        a = run(
            Auths.insert_new_auth(
                email=USER_A["email"],
                hashed_password=USER_A["hashed_password"],
                name=USER_A["name"],
                raw_password=USER_A["raw_password"],
                role="user",
            )
        )
        b = run(
            Auths.insert_new_auth(
                email=USER_B["email"],
                hashed_password=USER_B["hashed_password"],
                name=USER_B["name"],
                raw_password=USER_B["raw_password"],
                role="user",
            )
        )

        yield Created(session=session, a=a, b=b)

    mp.undo()


def _raw_keypair(session, user_id):
    return session.execute(
        text(
            "SELECT public_key, wrapped_private_key FROM auth WHERE id = :id"
        ),
        {"id": user_id},
    ).one()


class TestPersistence:
    def test_public_key_persisted_as_loadable_spki(self, created):
        public_key, _ = _raw_keypair(created.session, created.a.user.id)
        assert isinstance(public_key, bytes)
        loaded = serialization.load_der_public_key(public_key)
        assert loaded.key_size == 3072


class TestPrivateKeyAtRest:
    def test_private_key_is_not_stored_as_plaintext(self, created):
        _, wrapped_private_key = _raw_keypair(created.session, created.a.user.id)
        with pytest.raises(Exception):
            serialization.load_der_private_key(wrapped_private_key, password=None)

    def test_private_key_decrypts_with_owner_dek(self, created):
        _, wrapped_private_key = _raw_keypair(created.session, created.a.user.id)
        private_der = decrypt_value(wrapped_private_key, created.a.dek)
        loaded = serialization.load_der_private_key(private_der, password=None)
        assert loaded.key_size == 3072

    def test_private_key_does_not_decrypt_with_other_users_dek(self, created):
        _, wrapped_private_key = _raw_keypair(created.session, created.a.user.id)
        with pytest.raises(InvalidTag):
            decrypt_value(wrapped_private_key, created.b.dek)


class TestStoredKeypairRoundtrip:
    def test_stored_pub_and_decrypted_priv_form_a_working_pair(self, created):
        public_key, wrapped_private_key = _raw_keypair(
            created.session, created.a.user.id
        )
        private_der = decrypt_value(wrapped_private_key, created.a.dek)

        material = os.urandom(32)
        wrapped = rsa_wrap_key(material, public_key)
        assert rsa_unwrap_key(wrapped, private_der) == material


class TestKeySeparation:
    def test_two_users_get_distinct_public_keys(self, created):
        pub_a, _ = _raw_keypair(created.session, created.a.user.id)
        pub_b, _ = _raw_keypair(created.session, created.b.user.id)
        assert pub_a != pub_b


class TestKeypairPrimitives:
    def test_generate_keypair_roundtrip(self):
        private_der, public_der = generate_rsa_keypair()
        material = os.urandom(32)
        wrapped = rsa_wrap_key(material, public_der)
        assert wrapped != material
        assert rsa_unwrap_key(wrapped, private_der) == material

    def test_wrong_private_key_cannot_unwrap(self):
        _, public_der = generate_rsa_keypair()
        other_private_der, _ = generate_rsa_keypair()
        wrapped = rsa_wrap_key(os.urandom(32), public_der)
        with pytest.raises(ValueError):
            rsa_unwrap_key(wrapped, other_private_der)
