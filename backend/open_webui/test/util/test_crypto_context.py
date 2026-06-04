import time

import pytest

from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import (
    cache_dek,
    get_cached_dek,
    purge_expired_sessions,
    remove_session,
    require_cached_dek,
)
from open_webui.utils.crypto_utils import generate_dek


@pytest.fixture(autouse=True)
def _isolate_cache():
    crypto_context._dek_cache.clear()
    yield
    crypto_context._dek_cache.clear()


class TestRequireCachedDek:
    def test_returns_cached_dek(self):
        dek = generate_dek()
        cache_dek("user-1", dek, jti="jti-1", expires_at=time.time() + 60)

        assert require_cached_dek("user-1") == dek

    def test_raises_when_user_not_cached(self):
        with pytest.raises(RuntimeError, match="No DEK cached for user user-missing"):
            require_cached_dek("user-missing")

    def test_raises_when_all_sessions_expired(self):
        dek = generate_dek()
        cache_dek("user-1", dek, jti="jti-1", expires_at=time.time() - 1)
        purge_expired_sessions(time.time())

        with pytest.raises(RuntimeError, match="No DEK cached for user user-1"):
            require_cached_dek("user-1")

    def test_raises_after_last_session_removed(self):
        dek = generate_dek()
        cache_dek("user-1", dek, jti="jti-1", expires_at=time.time() + 60)
        remove_session("user-1", "jti-1")

        with pytest.raises(RuntimeError):
            require_cached_dek("user-1")

    def test_get_cached_dek_returns_none_in_same_conditions(self):
        # Sanity: require_cached_dek and get_cached_dek must agree on "missing"
        assert get_cached_dek("user-missing") is None
        with pytest.raises(RuntimeError):
            require_cached_dek("user-missing")
