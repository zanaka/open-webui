import time
from dataclasses import dataclass

import pytest
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
from open_webui.utils.crypto_context import cache_dek
from open_webui.utils.knowledge_crypto import (
    KdekAccessError,
    create_owner_kdek,
    resolve_kdek,
    sync_shared_keys,
)


@dataclass
class Accounts:
    session: object
    a: str  # owner
    b: str
    c: str


@pytest.fixture(scope="module")
def accounts() -> Accounts:
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

    ids = {}
    for key, pw in (("a", "a-correct-horse"), ("b", "b-battery-staple"), ("c", "c-zebra-cloud")):
        u = Auths.insert_new_auth(
            email=f"{key}@example.com",
            hashed_password=f"hashed::{key}",
            name=key.upper(),
            raw_password=pw,
            role="user",
            db=session,
        )
        cache_dek(u.user.id, u.dek, f"jti-{key}", time.time() + 3600)
        ids[key] = u.user.id

    yield Accounts(session=session, a=ids["a"], b=ids["b"], c=ids["c"])

    session.close()
    engine.dispose()
    mp.undo()


def _read_ac(*user_ids):
    return {
        "read": {"user_ids": list(user_ids), "group_ids": []},
        "write": {"user_ids": [], "group_ids": []},
    }


@pytest.fixture
def kb(accounts):
    # Fresh knowledge + owner KDEK per test, so sharing state never leaks.
    k = Knowledges.insert_new_knowledge(
        accounts.a,
        KnowledgeForm(name="KB", description="d", access_control={}),
        db=accounts.session,
    )
    kdek = create_owner_kdek(k.id, accounts.a, db=accounts.session)
    return k.id, kdek


class TestShare:
    def test_shared_member_can_resolve_same_kdek(self, accounts, kb):
        kid, kdek = kb
        sync_shared_keys(kid, accounts.a, _read_ac(accounts.b), kdek, db=accounts.session)
        assert resolve_kdek(kid, accounts.b, db=accounts.session) == kdek

    def test_owner_row_untouched_after_share(self, accounts, kb):
        kid, kdek = kb
        sync_shared_keys(kid, accounts.a, _read_ac(accounts.b), kdek, db=accounts.session)
        assert resolve_kdek(kid, accounts.a, db=accounts.session) == kdek

    def test_recipient_wrap_differs_but_same_kdek(self, accounts, kb):
        kid, kdek = kb
        sync_shared_keys(kid, accounts.a, _read_ac(accounts.b), kdek, db=accounts.session)
        w_a = KnowledgeKeys.get_wrapped_kdek(kid, accounts.a, db=accounts.session)
        w_b = KnowledgeKeys.get_wrapped_kdek(kid, accounts.b, db=accounts.session)
        assert w_a != w_b  # wrapped with different public keys
        assert resolve_kdek(kid, accounts.b, db=accounts.session) == kdek


class TestUnshare:
    def test_unshare_removes_access(self, accounts, kb):
        kid, kdek = kb
        sync_shared_keys(kid, accounts.a, _read_ac(accounts.b), kdek, db=accounts.session)
        sync_shared_keys(kid, accounts.a, {}, kdek, db=accounts.session)
        assert resolve_kdek(kid, accounts.b, db=accounts.session) is None

class TestDiff:
    def test_partial_resync_keeps_and_removes(self, accounts, kb):
        kid, kdek = kb
        sync_shared_keys(
            kid, accounts.a, _read_ac(accounts.b, accounts.c), kdek, db=accounts.session
        )
        assert resolve_kdek(kid, accounts.b, db=accounts.session) == kdek
        assert resolve_kdek(kid, accounts.c, db=accounts.session) == kdek

        sync_shared_keys(kid, accounts.a, _read_ac(accounts.b), kdek, db=accounts.session)
        assert resolve_kdek(kid, accounts.b, db=accounts.session) == kdek
        assert resolve_kdek(kid, accounts.c, db=accounts.session) is None

    def test_resync_is_idempotent(self, accounts, kb):
        kid, kdek = kb
        sync_shared_keys(kid, accounts.a, _read_ac(accounts.b), kdek, db=accounts.session)
        sync_shared_keys(kid, accounts.a, _read_ac(accounts.b), kdek, db=accounts.session)
        assert set(KnowledgeKeys.get_user_ids(kid, db=accounts.session)) == {
            accounts.a,
            accounts.b,
        }


class TestActorWithoutKey:
    def test_adding_member_without_kdek_raises(self, accounts, kb):
        kid, _ = kb
        with pytest.raises(KdekAccessError):
            sync_shared_keys(kid, accounts.a, _read_ac(accounts.b), None, db=accounts.session)

    def test_removing_member_without_kdek_raises(self, accounts, kb):
        kid, kdek = kb
        sync_shared_keys(kid, accounts.a, _read_ac(accounts.b), kdek, db=accounts.session)
        # A non-member (no KDEK) must not be able to revoke either.
        with pytest.raises(KdekAccessError):
            sync_shared_keys(kid, accounts.a, {}, None, db=accounts.session)
        # The rejection left the membership unchanged.
        assert resolve_kdek(kid, accounts.b, db=accounts.session) == kdek
