import time
from dataclasses import dataclass

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.auths import Auth, Auths
from open_webui.models.users import User
from open_webui.models.knowledge import (
    Knowledge,
    KnowledgeForm,
    KnowledgeKey,
    KnowledgeKeys,
    Knowledges,
)
from open_webui.routers.knowledge import validate_encryptable_access_control
from open_webui.utils.crypto_context import cache_dek
from open_webui.utils.knowledge_crypto import create_owner_kdek, resolve_kdek


@dataclass
class Setup:
    session: object
    owner_id: str
    other_id: str
    knowledge_id: str
    kdek: bytes


@pytest.fixture(scope="module")
def setup() -> Setup:
    mp = pytest.MonkeyPatch()
    mp.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(
        engine,
        tables=[
            User.__table__,
            Auth.__table__,
            Knowledge.__table__,
            KnowledgeKey.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()

    owner = Auths.insert_new_auth(
        email="owner@example.com",
        hashed_password="hashed::owner",
        name="Owner",
        raw_password="owner-correct-horse",
        role="user",
        db=session,
    )
    other = Auths.insert_new_auth(
        email="other@example.com",
        hashed_password="hashed::other",
        name="Other",
        raw_password="other-battery-staple",
        role="user",
        db=session,
    )
    # Both users are "logged in": their DEKs are cached.
    cache_dek(owner.user.id, owner.dek, "jti-owner", time.time() + 3600)
    cache_dek(other.user.id, other.dek, "jti-other", time.time() + 3600)

    kb = Knowledges.insert_new_knowledge(
        owner.user.id,
        KnowledgeForm(name="KB", description="d", access_control={}),
        db=session,
    )
    kdek = create_owner_kdek(kb.id, owner.user.id, db=session)

    yield Setup(
        session=session,
        owner_id=owner.user.id,
        other_id=other.user.id,
        knowledge_id=kb.id,
        kdek=kdek,
    )

    session.close()
    engine.dispose()
    mp.undo()


class TestOwnerKdek:
    def test_kdek_is_256_bits(self, setup):
        assert isinstance(setup.kdek, bytes)
        assert len(setup.kdek) == 32

    def test_owner_can_resolve_kdek(self, setup):
        resolved = resolve_kdek(setup.knowledge_id, setup.owner_id, db=setup.session)
        assert resolved == setup.kdek


class TestWrappedStorage:
    def test_wrapped_kdek_is_not_plaintext(self, setup):
        wrapped = KnowledgeKeys.get_wrapped_kdek(
            setup.knowledge_id, setup.owner_id, db=setup.session
        )
        assert wrapped is not None
        assert wrapped != setup.kdek
        # RSA-OAEP wrap of a 32-byte key under a 3072-bit key is 384 bytes.
        assert len(wrapped) > len(setup.kdek)


class TestNonMember:
    def test_non_member_resolve_returns_none(self, setup):
        assert (
            resolve_kdek(setup.knowledge_id, setup.other_id, db=setup.session) is None
        )


class TestAccessControlGuard:
    def test_public_none_rejected(self):
        with pytest.raises(HTTPException):
            validate_encryptable_access_control(None)

    def test_group_read_rejected(self):
        with pytest.raises(HTTPException):
            validate_encryptable_access_control(
                {"read": {"group_ids": ["g1"], "user_ids": []}}
            )

    def test_group_write_rejected(self):
        with pytest.raises(HTTPException):
            validate_encryptable_access_control({"write": {"group_ids": ["g1"]}})

    def test_user_sharing_is_allowed(self):
        validate_encryptable_access_control(
            {
                "read": {"user_ids": ["u1"], "group_ids": []},
                "write": {"user_ids": [], "group_ids": []},
            }
        )

    def test_private_empty_is_allowed(self):
        validate_encryptable_access_control({})
