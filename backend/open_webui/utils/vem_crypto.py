import hashlib
import hmac
import logging
import threading
import time
from collections import OrderedDict
from typing import Optional

import numpy as np
from sqlalchemy.orm import Session

from open_webui.models.knowledge import KnowledgeKeys
from open_webui.utils.crypto_context import get_cached_dek, get_current_user_id
from open_webui.utils.knowledge_crypto import resolve_kdek

try:
    from threadpoolctl import threadpool_limits
except Exception:
    threadpool_limits = None

log = logging.getLogger(__name__)

_VEM_INFO = b"owui-vem-rotation-v1"
_USER_COLLECTION_PREFIXES = ("file-",)

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


def _get_matrix(key: bytes, dim: int) -> np.ndarray:
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


def _resolve_vem_key(
    collection_name: str, user_id: Optional[str], db: Optional[Session] = None
) -> Optional[bytes]:
    # Shared knowledge collections are keyed by the per-knowledge KDEK.
    if KnowledgeKeys.get_user_ids(collection_name, db=db):
        if user_id is None:
            return None
        try:
            return resolve_kdek(collection_name, user_id, db=db)
        except Exception as e:
            log.debug(f"VEM: could not resolve KDEK for {collection_name}: {e}")
            return None
    # User-specific collections are keyed by the owner's DEK.
    if collection_name.startswith(_USER_COLLECTION_PREFIXES):
        if user_id is None:
            return None
        return get_cached_dek(user_id)
    return None


def rotate_items_for_collection(
    collection_name: str,
    user_id: Optional[str],
    items: list[dict],
    db: Optional[Session] = None,
) -> None:
    if not items:
        return
    key = _resolve_vem_key(collection_name, user_id, db=db)
    if key is None:
        return
    vectors = [item.get("vector") for item in items]
    if any(v is None for v in vectors):
        return
    matrix = _get_matrix(key, len(vectors[0]))
    rotated = np.asarray(vectors, dtype=float) @ matrix.T
    for item, row in zip(items, rotated):
        item["vector"] = row.tolist()


def rotate_query_for_collection(collection_name: str, query_embedding: list):
    if not query_embedding:
        return query_embedding
    user_id = get_current_user_id()
    if not user_id:
        return query_embedding
    key = _resolve_vem_key(collection_name, user_id)
    if key is None:
        return query_embedding
    matrix = _get_matrix(key, len(query_embedding))
    return (np.asarray(query_embedding, dtype=float) @ matrix.T).tolist()
