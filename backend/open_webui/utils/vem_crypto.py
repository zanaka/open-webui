"""Rotating vectors with a collection's key, so the stored geometry is not the
embedding model's own.

Which key protects which collection is decided by the caller, not here; see
open_webui.utils.vector_keys.
"""

import hashlib
import hmac
import logging
import threading
import time
from collections import OrderedDict
from typing import Optional

import numpy as np

try:
    from threadpoolctl import threadpool_limits
except Exception:
    threadpool_limits = None

log = logging.getLogger(__name__)

_VEM_INFO = b"owui-vem-rotation-v1"

_MATRIX_CACHE_MAX_BYTES = 1024 * 1024 * 1024  # 1 GB ceiling
_matrix_cache: "OrderedDict[tuple, tuple]" = OrderedDict()
_cache_bytes = 0
_cache_lock = threading.Lock()


def _cache_ttl_seconds() -> Optional[float]:
    # VEM entries expire on the same schedule as sessions (JWT lifetime).
    from open_webui.config import JWT_EXPIRES_IN
    from open_webui.utils.misc import parse_duration

    try:
        td = parse_duration(JWT_EXPIRES_IN.value)
    except Exception:
        td = None
    return td.total_seconds() if td is not None else None


def _seed_from_key(key: bytes) -> int:
    digest = hmac.new(key, _VEM_INFO, hashlib.sha256).digest()
    return int.from_bytes(digest, "big")


def _build_matrix(secret_seed: int, dim: int) -> np.ndarray:
    rng = np.random.default_rng(secret_seed)
    a = rng.standard_normal((dim, dim))
    # A small matrix can be slower under many BLAS threads than a single one.
    if threadpool_limits is not None:
        with threadpool_limits(limits=1):
            q, _ = np.linalg.qr(a)
    else:
        q, _ = np.linalg.qr(a)
    return q.astype(np.float32)


def _resolve_matrix(key: bytes, dim: int) -> np.ndarray:
    global _cache_bytes
    secret_seed = _seed_from_key(key)
    cache_key = (secret_seed, dim)
    now = time.time()
    ttl = _cache_ttl_seconds()
    expires_at = None if ttl is None else now + ttl
    with _cache_lock:
        entry = _matrix_cache.get(cache_key)
        if entry is not None:
            matrix, entry_expires = entry
            if entry_expires is None or entry_expires > now:
                _matrix_cache[cache_key] = (matrix, expires_at)  # slide TTL
                _matrix_cache.move_to_end(cache_key)  # LRU
                return matrix
            del _matrix_cache[cache_key]
            _cache_bytes -= matrix.nbytes

        matrix = _build_matrix(secret_seed, dim)
        _matrix_cache[cache_key] = (matrix, expires_at)
        _cache_bytes += matrix.nbytes
        while _cache_bytes > _MATRIX_CACHE_MAX_BYTES and len(_matrix_cache) > 1:
            _, (evicted, _) = _matrix_cache.popitem(last=False)
            _cache_bytes -= evicted.nbytes
        return matrix


def purge_expired_vems(now: float) -> None:
    global _cache_bytes
    with _cache_lock:
        expired = [
            k
            for k, (_, exp) in _matrix_cache.items()
            if exp is not None and exp <= now
        ]
        for k in expired:
            matrix, _ = _matrix_cache.pop(k)
            _cache_bytes -= matrix.nbytes


def rotate_vectors(vectors: list, key: bytes) -> list:
    """Rotate vectors into the key's frame of reference."""
    if not vectors:
        return vectors
    matrix = _resolve_matrix(key, len(vectors[0]))
    return (np.asarray(vectors, dtype=float) @ matrix.T).tolist()


def rotate_items(items: list[dict], key: bytes) -> None:
    """Rotate each item's vector in place."""
    if not items:
        return

    vectors = [item.get("vector") for item in items]
    if any(vector is None for vector in vectors):
        raise ValueError("Cannot rotate items: some carry no vector.")

    for item, rotated in zip(items, rotate_vectors(vectors, key)):
        item["vector"] = rotated


