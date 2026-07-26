import time

import numpy as np
import pytest

from open_webui.utils import vem_crypto
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.vem_crypto import (
    _build_matrix,
    _resolve_matrix,
    _seed_from_key,
    purge_expired_vems,
    rotate_items,
    rotate_vectors,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    vem_crypto._matrix_cache.clear()
    vem_crypto._cache_bytes = 0
    yield
    vem_crypto._matrix_cache.clear()
    vem_crypto._cache_bytes = 0


def _dist(a, b):
    return float(np.linalg.norm(np.asarray(a) - np.asarray(b)))


def _items(vectors):
    return [
        {"id": f"c{i}", "text": "t", "vector": v, "metadata": {}}
        for i, v in enumerate(vectors)
    ]


class TestMatrix:
    def test_matrix_is_orthogonal(self):
        q = _build_matrix(_seed_from_key(generate_dek()), 16)
        assert np.allclose(q @ q.T, np.eye(16), atol=1e-5)

    def test_matrix_is_float32(self):
        assert _build_matrix(_seed_from_key(generate_dek()), 8).dtype == np.float32

    def test_same_seed_is_deterministic(self):
        seed = _seed_from_key(generate_dek())
        assert np.array_equal(_build_matrix(seed, 16), _build_matrix(seed, 16))

    def test_different_keys_differ(self):
        a = _build_matrix(_seed_from_key(generate_dek()), 16)
        b = _build_matrix(_seed_from_key(generate_dek()), 16)
        assert not np.allclose(a, b)

    def test_cache_returns_same_object(self):
        key = generate_dek()
        assert _resolve_matrix(key, 16) is _resolve_matrix(key, 16)


class TestRotation:
    def test_rotation_preserves_distances(self):
        key = generate_dek()
        a, b = list(np.random.rand(8)), list(np.random.rand(8))

        rotated_a, rotated_b = rotate_vectors([a, b], key)

        assert _dist(rotated_a, rotated_b) == pytest.approx(_dist(a, b), abs=1e-4)

    def test_query_and_stored_use_the_same_matrix(self):
        key = generate_dek()
        near = [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80]
        far = [0.90, 0.10, 0.90, 0.10, 0.90, 0.10, 0.90, 0.10]
        query = [0.11, 0.21, 0.31, 0.41, 0.51, 0.61, 0.71, 0.81]

        rotated_near, rotated_far = rotate_vectors([near, far], key)
        (rotated_query,) = rotate_vectors([query], key)

        # The nearest neighbour is still the nearest neighbour after rotation.
        assert _dist(rotated_query, rotated_near) < _dist(rotated_query, rotated_far)

    def test_different_keys_land_elsewhere(self):
        vector = [0.1] * 8

        (mine,) = rotate_vectors([vector], generate_dek())
        (theirs,) = rotate_vectors([vector], generate_dek())

        assert not np.allclose(mine, theirs)

    def test_items_are_rotated_in_place(self):
        key = generate_dek()
        items = _items([[0.1] * 8])
        original = list(items[0]["vector"])

        rotate_items(items, key)

        assert items[0]["vector"] != original

    def test_items_without_vectors_are_refused(self):
        items = [{"id": "c0", "text": "t", "metadata": {}}]

        with pytest.raises(ValueError):
            rotate_items(items, generate_dek())

    def test_empty_input_is_left_alone(self):
        key = generate_dek()
        assert rotate_vectors([], key) == []
        rotate_items([], key)  # must not raise


class TestCache:
    def test_same_key_collapses_to_one_entry(self):
        key = generate_dek()
        for _ in range(3):
            rotate_items(_items([[0.1] * 8]), key)
        assert len(vem_crypto._matrix_cache) == 1

    def test_byte_cap_bounds_size(self, monkeypatch):
        monkeypatch.setattr(vem_crypto, "_MATRIX_CACHE_MAX_BYTES", 8 * 8 * 4 * 2)
        for _ in range(5):
            _resolve_matrix(generate_dek(), 8)  # 5 distinct keys
        assert len(vem_crypto._matrix_cache) <= 2
        assert vem_crypto._cache_bytes <= vem_crypto._MATRIX_CACHE_MAX_BYTES

    def test_lru_evicts_least_recently_used(self, monkeypatch):
        monkeypatch.setattr(vem_crypto, "_MATRIX_CACHE_MAX_BYTES", 8 * 8 * 4 * 2)
        k1, k2, k3 = generate_dek(), generate_dek(), generate_dek()
        _resolve_matrix(k1, 8)
        _resolve_matrix(k2, 8)  # cache full: [k1, k2]
        _resolve_matrix(k1, 8)  # touch k1 -> k2 becomes least-recently-used
        _resolve_matrix(k3, 8)  # inserting k3 evicts k2 (LRU), not k1
        keys = set(vem_crypto._matrix_cache.keys())
        assert (_seed_from_key(k1), 8) in keys
        assert (_seed_from_key(k2), 8) not in keys
        assert (_seed_from_key(k3), 8) in keys

    def test_purge_expired_vems(self):
        _resolve_matrix(generate_dek(), 8)
        assert len(vem_crypto._matrix_cache) == 1
        ck, (matrix, _) = next(iter(vem_crypto._matrix_cache.items()))
        vem_crypto._matrix_cache[ck] = (matrix, time.time() - 1)  # force expired
        purge_expired_vems(time.time())
        assert len(vem_crypto._matrix_cache) == 0
        assert vem_crypto._cache_bytes == 0
