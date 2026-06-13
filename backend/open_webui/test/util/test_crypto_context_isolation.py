import asyncio
import time

import pytest

from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import (
    cache_dek,
    get_cached_dek,
    get_current_user_id,
    purge_expired_sessions,
    remove_session,
    require_cached_dek,
    require_current_user_dek,
    set_current_user_id,
)
from open_webui.crypto_exceptions import EncryptedDataAccessDeniedError
from open_webui.utils.crypto_utils import generate_dek

USER_A = "user-a"
USER_B = "user-b"


@pytest.fixture(autouse=True)
def _isolate_cache():
    crypto_context._dek_cache.clear()
    set_current_user_id(None)
    yield
    set_current_user_id(None)
    crypto_context._dek_cache.clear()


@pytest.fixture
def two_users():
    dek_a = generate_dek()
    dek_b = generate_dek()
    cache_dek(USER_A, dek_a, jti="a-jti", expires_at=time.time() + 60)
    cache_dek(USER_B, dek_b, jti="b-jti", expires_at=time.time() + 60)
    return dek_a, dek_b


class TestMultiUserCacheSeparation:
    def test_each_user_gets_their_own_dek(self, two_users):
        dek_a, dek_b = two_users
        assert dek_a != dek_b
        assert require_cached_dek(USER_A) == dek_a
        assert require_cached_dek(USER_B) == dek_b

    def test_removing_one_session_leaves_other_user_intact(self, two_users):
        dek_a, dek_b = two_users
        remove_session(USER_A, "a-jti")

        assert get_cached_dek(USER_A) is None
        assert require_cached_dek(USER_B) == dek_b

    def test_expiring_one_user_leaves_other_user_intact(self):
        dek_a = generate_dek()
        dek_b = generate_dek()
        cache_dek(USER_A, dek_a, jti="a-jti", expires_at=time.time() - 1)  # expired
        cache_dek(USER_B, dek_b, jti="b-jti", expires_at=time.time() + 60)

        purge_expired_sessions(time.time())

        assert get_cached_dek(USER_A) is None
        assert require_cached_dek(USER_B) == dek_b


class TestCurrentUserDekSelection:
    def test_context_selects_the_matching_users_dek(self, two_users):
        dek_a, dek_b = two_users

        set_current_user_id(USER_A)
        assert get_current_user_id() == USER_A
        assert require_current_user_dek(USER_A) == dek_a

        set_current_user_id(USER_B)
        assert require_current_user_dek(USER_B) == dek_b

    def test_cross_user_denied_even_when_target_is_cached(self, two_users):
        set_current_user_id(USER_A)
        with pytest.raises(EncryptedDataAccessDeniedError):
            require_current_user_dek(USER_B)


class TestContextVarTaskIsolation:
    def test_concurrent_asyncio_tasks_do_not_share_current_user(self):
        results: dict[str, str] = {}

        async def worker(user_id: str) -> None:
            set_current_user_id(user_id)
            await asyncio.sleep(0)
            results[user_id] = get_current_user_id()

        async def main() -> None:
            await asyncio.gather(worker(USER_A), worker(USER_B))

        asyncio.run(main())

        assert results[USER_A] == USER_A
        assert results[USER_B] == USER_B
        assert get_current_user_id() is None
