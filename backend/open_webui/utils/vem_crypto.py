import hashlib
import hmac
import logging
import threading
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

_matrix_cache: dict[str, np.ndarray] = {}
_cache_lock = threading.Lock()


def _seed_from_key(key: bytes) -> int:
    digest = hmac.new(key, _VEM_INFO, hashlib.sha256).digest()
    return int.from_bytes(digest, "big")


def _build_matrix(key: bytes, dim: int) -> np.ndarray:
    rng = np.random.default_rng(_seed_from_key(key))
    a = rng.standard_normal((dim, dim))
    # A small matrix can be slower under many BLAS threads than a single one.
    if threadpool_limits is not None:
        with threadpool_limits(limits=1):
            q, _ = np.linalg.qr(a)
    else:
        q, _ = np.linalg.qr(a)
    return q


def _get_matrix(collection_name: str, key: bytes, dim: int) -> np.ndarray:
    cached = _matrix_cache.get(collection_name)
    if cached is not None and cached.shape[0] == dim:
        return cached
    with _cache_lock:
        cached = _matrix_cache.get(collection_name)
        if cached is not None and cached.shape[0] == dim:
            return cached
        matrix = _build_matrix(key, dim)
        _matrix_cache[collection_name] = matrix
        return matrix


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
    matrix = _get_matrix(collection_name, key, len(vectors[0]))
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
    matrix = _get_matrix(collection_name, key, len(query_embedding))
    return (np.asarray(query_embedding, dtype=float) @ matrix.T).tolist()
