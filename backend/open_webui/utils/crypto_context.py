import threading
from typing import Optional

# ---------------------------------------------------------------------------
# In-memory DEK cache with per-session (JTI) tracking.
# Protected by mlockall (swap disabled). No Redis required.
#
# Structure: user_id -> (dek, {jti: expires_at, jti: expires_at...})
# The DEK stays cached as long as at least one session is active.
# ---------------------------------------------------------------------------

_cache_lock = threading.Lock()
_dek_cache: dict[str, tuple[bytes, dict[str, float]]] = {}


def cache_dek(user_id: str, dek: bytes, jti: str, expires_at: float) -> None:
    with _cache_lock:
        entry = _dek_cache.get(user_id)
        if entry is not None:
            entry[1][jti] = expires_at
        else:
            _dek_cache[user_id] = (dek, {jti: expires_at})


def get_cached_dek(user_id: str) -> Optional[bytes]:
    with _cache_lock:
        entry = _dek_cache.get(user_id)
        if entry is None:
            return None
        dek, sessions = entry
        if not sessions:
            return None
        return dek


def remove_session(user_id: str, jti: str) -> None:
    with _cache_lock:
        entry = _dek_cache.get(user_id)
        if entry is None:
            return
        entry[1].pop(jti, None)
