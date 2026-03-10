import threading
import time
from typing import Optional

# ---------------------------------------------------------------------------
# In-memory DEK cache (user_id -> DEK)
# Protected by mlockall (swap disabled). No Redis required.
# ---------------------------------------------------------------------------

_cache_lock = threading.Lock()
_dek_cache: dict[str, tuple[bytes, float]] = {}  # user_id -> (dek, expires_at)


def cache_dek(user_id: str, dek: bytes, ttl_seconds: float) -> None:
    with _cache_lock:
        _dek_cache[user_id] = (dek, time.time() + ttl_seconds)


def get_cached_dek(user_id: str) -> Optional[bytes]:
    with _cache_lock:
        entry = _dek_cache.get(user_id)
        if entry is None:
            return None
        dek, expires_at = entry
        if time.time() > expires_at:
            del _dek_cache[user_id]
            return None
        return dek


def evict_dek(user_id: str) -> None:
    with _cache_lock:
        _dek_cache.pop(user_id, None)
