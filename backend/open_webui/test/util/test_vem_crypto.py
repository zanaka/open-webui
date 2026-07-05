import time
from dataclasses import dataclass

import numpy as np
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
    Knowledges,
)
from open_webui.utils import vem_crypto
from open_webui.utils.crypto_context import cache_dek, set_current_user_id
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.knowledge_crypto import create_owner_kdek
from open_webui.utils.vem_crypto import (
    _build_matrix,
    _get_matrix,
    rotate_items_for_collection,
    rotate_query_for_collection,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    vem_crypto._matrix_cache.clear()
    yield
    vem_crypto._matrix_cache.clear()


def _dist(a, b):
    return float(np.linalg.norm(np.asarray(a) - np.asarray(b)))


def _items(vectors):
    return [
        {"id": f"c{i}", "text": "t", "vector": v, "metadata": {}}
        for i, v in enumerate(vectors)
    ]


class TestMatrix:
    def test_matrix_is_orthogonal(self):
        q = _build_matrix(generate_dek(), 16)
        assert np.allclose(q @ q.T, np.eye(16), atol=1e-9)

    def test_same_key_is_deterministic(self):
        key = generate_dek()
        assert np.array_equal(_build_matrix(key, 16), _build_matrix(key, 16))

    def test_different_keys_differ(self):
        a = _build_matrix(generate_dek(), 16)
        b = _build_matrix(generate_dek(), 16)
        assert not np.allclose(a, b)

    def test_cache_returns_same_object(self):
        key = generate_dek()
        first = _get_matrix("col-x", key, 16)
        second = _get_matrix("col-x", key, 16)
        assert first is second


@dataclass
class Accounts:
    session: object
    a: str
    b: str


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
    for key, pw in (("a", "a-pass-aaa"), ("b", "b-pass-bbb")):
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

    yield Accounts(session=session, a=ids["a"], b=ids["b"])

    session.close()
    engine.dispose()
    mp.undo()


@pytest.fixture
def knowledge(accounts):
    k = Knowledges.insert_new_knowledge(
        accounts.a,
        KnowledgeForm(name="KB", description="d", access_control={}),
        db=accounts.session,
    )
    kdek = create_owner_kdek(k.id, accounts.a, db=accounts.session)
    return k.id, kdek


def _sample_vectors(rng):
    return [list(rng.standard_normal(8)) for _ in range(5)]


class TestCollectionRotation:
    def test_knowledge_rotation_preserves_distances(self, accounts, knowledge):
        kid, _ = knowledge
        rng = np.random.default_rng(0)
        vectors = _sample_vectors(rng)
        originals = [list(v) for v in vectors]
        items = _items(vectors)

        rotate_items_for_collection(kid, accounts.a, items, db=accounts.session)

        # Vectors are actually rotated...
        assert items[0]["vector"] != originals[0]
        # ...but every pairwise distance is preserved (orthogonal rotation).
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                assert _dist(items[i]["vector"], items[j]["vector"]) == pytest.approx(
                    _dist(originals[i], originals[j]), abs=1e-6
                )

    def test_query_and_stored_rotated_same_matrix_keep_nn(self, accounts, knowledge):
        kid, kdek = knowledge
        rng = np.random.default_rng(1)
        originals = _sample_vectors(rng)
        query = list(rng.standard_normal(8))
        items = _items([list(v) for v in originals])

        rotate_items_for_collection(kid, accounts.a, items, db=accounts.session)
        q_matrix = _build_matrix(kdek, 8)
        rotated_query = (np.asarray(query) @ q_matrix.T).tolist()

        plain_nn = sorted(range(len(originals)), key=lambda i: _dist(originals[i], query))
        rot_nn = sorted(
            range(len(items)),
            key=lambda i: _dist(items[i]["vector"], rotated_query),
        )
        assert plain_nn == rot_nn

    def test_user_file_collection_rotates_with_dek(self, accounts):
        rng = np.random.default_rng(2)
        vectors = _sample_vectors(rng)
        originals = [list(v) for v in vectors]
        items = _items(vectors)

        rotate_items_for_collection(
            "file-abc", accounts.a, items, db=accounts.session
        )
        assert items[0]["vector"] != originals[0]
        assert _dist(items[0]["vector"], items[1]["vector"]) == pytest.approx(
            _dist(originals[0], originals[1]), abs=1e-6
        )

    def test_non_vem_collection_is_passthrough(self, accounts):
        rng = np.random.default_rng(3)
        vectors = _sample_vectors(rng)
        originals = [list(v) for v in vectors]
        items = _items(vectors)

        rotate_items_for_collection(
            "web-search-xyz", accounts.a, items, db=accounts.session
        )
        assert items[0]["vector"] == originals[0]


class TestQueryRotation:
    def test_no_current_user_passes_through(self):
        set_current_user_id(None)
        q = [0.1, 0.2, 0.3]
        assert rotate_query_for_collection("kid", q) == q

    def test_no_key_passes_through(self, monkeypatch):
        monkeypatch.setattr(vem_crypto, "_resolve_vem_key", lambda c, u, db=None: None)
        set_current_user_id("u1")
        try:
            q = [0.1, 0.2, 0.3]
            assert rotate_query_for_collection("kid", q) == q
        finally:
            set_current_user_id(None)

    def test_rotates_consistently_with_key(self, monkeypatch):
        key = generate_dek()
        monkeypatch.setattr(vem_crypto, "_resolve_vem_key", lambda c, u, db=None: key)
        set_current_user_id("u1")
        try:
            q = list(np.random.default_rng(4).standard_normal(8))
            out = rotate_query_for_collection("kid", q)
            expected = (np.asarray(q) @ _build_matrix(key, 8).T).tolist()
            assert out != q
            assert np.allclose(out, expected)
        finally:
            set_current_user_id(None)
