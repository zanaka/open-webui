import threading
from typing import Optional

# ---------------------------------------------------------------------------
# In-memory DEK cache with per-session (JTI) tracking.
# Protected by mlockall (swap disabled). No Redis required.
#
# Structure: user_id -> (dek, {jti: expires_at, jti: expires_at...})
# The DEK stays cached as long as at least one session is active.
# ---------------------------------------------------------------------------


class UserSessions:
    def __init__(self, jti: str, expires_at: float):
        self._sessions: dict[str, float] = {}
        self.register(jti, expires_at)

    def register(self, jti: str, expires_at: float) -> None:
        self._sessions[jti] = expires_at

    def get_expired_jtis(self, now: float) -> list[str]:
        expired_jtis: list[str] = []
        for jti, expired_at in self._sessions.items():
            expired: bool = expired_at < now
            if expired:
                expired_jtis.append(jti)

        return expired_jtis

    def delete_by(self, jti: str) -> None:
        del self._sessions[jti]

    def delete_expired(self, now: float) -> None:
        for jti in self.get_expired_jtis(now):
            self.delete_by(jti)

    def is_empty(self) -> bool:
        return not any(self._sessions)


_cache_lock = threading.Lock()
_dek_cache: dict[str, tuple[bytes, UserSessions]] = {}


def cache_dek(user_id: str, dek: bytes, jti: str, expires_at: float) -> None:
    with _cache_lock:
        entry = _dek_cache.get(user_id)
        if entry is not None:
            sessions = entry[1]
            sessions.register(jti, expires_at)
        else:
            _dek_cache[user_id] = (dek, UserSessions(jti, expires_at))


def get_cached_dek(user_id: str) -> Optional[bytes]:
    with _cache_lock:
        entry = _dek_cache.get(user_id)
        if entry is None:
            return None
        dek, sessions = entry
        if sessions.is_empty():
            return None
        return dek


def require_cached_dek(user_id: str) -> bytes:
    dek = get_cached_dek(user_id)
    if dek is None:
        raise RuntimeError(f"No DEK cached for user {user_id}. User must re-login.")
    return dek


def remove_session(user_id: str, jti: str) -> None:
    with _cache_lock:
        entry = _dek_cache.get(user_id)
        if entry is None:
            return

        sessions = entry[1]
        sessions.delete_by(jti)
        if sessions.is_empty():
            del _dek_cache[user_id]


def purge_expired_sessions(now: float) -> None:
    empty_users = []

    with _cache_lock:
        for user_id, (_, sessions) in _dek_cache.items():
            sessions.delete_expired(now)
            if sessions.is_empty():
                empty_users.append(user_id)

        for user_id in empty_users:
            del _dek_cache[user_id]
