"""Fixtures for the tests that exercise encryption against a real database.

Models keyed by their owner's DEK can be tested against an in-memory database,
because the key comes from a cache in this process. Models keyed by a key of
their own cannot: resolving one reads the resource_key table and the holder's
wrapped private key through open_webui.internal.db, which opens its own
session. Two sessions on sqlite:///:memory: are two different databases, so
these fixtures use a file and point the global session factories at it.

The table APIs are async since the v0.11.1 merge, while the encryption hooks
— and therefore most of what these tests assert — stay sync. Tests drive the
async APIs through the ``run`` bridge and keep their assertions on the sync
session, which shares the same database file.
"""

import asyncio
import time
from contextlib import contextmanager

import pytest
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.auths import Auths
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek, set_current_user_id
from open_webui.utils.encrypted_models import install

install()

# The two accounts live for the whole module, so their rows survive the cleaning
# between tests. Everything else goes.
KEEP_BETWEEN_TESTS = {"user", "auth"}


def run(coro):
    """Drive an async table API from a sync test.

    Each call gets its own event loop, so the async engine must not pool
    connections across calls — the fixture below builds it with NullPool.
    """
    return asyncio.run(coro)


@pytest.fixture(name="run")
def run_fixture():
    return run


@contextmanager
def sqlite_test_database(monkeypatch, db_path, tables=None):
    """A file-backed test database both session factories point at.

    A file rather than :memory:, because the sync test session, the async
    table APIs, and the key lookups each open their own connections — on
    :memory: those would be three different databases.
    """
    engine = create_engine(f"sqlite:///{db_path}")
    async_engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_path}", poolclass=NullPool
    )
    session_factory = sessionmaker(bind=engine)
    async_session_factory = async_sessionmaker(
        bind=async_engine,
        class_=AsyncSession,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )

    monkeypatch.setattr(internal_db, "SessionLocal", session_factory)
    monkeypatch.setattr(internal_db, "AsyncSessionLocal", async_session_factory)
    monkeypatch.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)

    Base.metadata.create_all(engine, tables=tables)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
        run(async_engine.dispose())
        engine.dispose()


def _import_every_model():
    """Whole schema, so a test never has to list the tables it happens to touch."""
    import importlib
    import pkgutil

    import open_webui.config  # noqa: F401  (defines the Config model)
    import open_webui.models as models

    for module in pkgutil.iter_modules(models.__path__):
        importlib.import_module(f"open_webui.models.{module.name}")


class Accounts:
    """Two people who are signed in, and a session on their database."""

    def __init__(self, session, owner, intruder):
        self.session = session
        self.owner = owner
        self.intruder = intruder


@pytest.fixture(scope="module")
def accounts(tmp_path_factory) -> Accounts:
    monkeypatch = pytest.MonkeyPatch()
    db_path = tmp_path_factory.mktemp("encrypted") / "test.db"
    engine = create_engine(f"sqlite:///{db_path}")
    session_factory = sessionmaker(bind=engine)

    # aiosqlite connections belong to the loop they were opened on, and the
    # run() bridge uses one loop per call: NullPool keeps a connection from
    # outliving its loop.
    async_engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_path}", poolclass=NullPool
    )
    async_session_factory = async_sessionmaker(
        bind=async_engine,
        class_=AsyncSession,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )

    # Both the sessions handed to tests and the sessions the table APIs and
    # key lookups open for themselves have to land on this database.
    monkeypatch.setattr(internal_db, "SessionLocal", session_factory)
    monkeypatch.setattr(internal_db, "AsyncSessionLocal", async_session_factory)
    monkeypatch.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)

    _import_every_model()
    Base.metadata.create_all(engine)
    session = session_factory()

    # Real accounts, because a shared resource's key is wrapped with the RSA
    # public key of everyone allowed to open it. Generating those is slow, so
    # this fixture is per module and each test clears the tables instead.
    people = {}
    for name, password in (
        ("owner", "owner-correct-horse"),
        ("intruder", "intruder-battery-staple"),
    ):
        auth = run(
            Auths.insert_new_auth(
                email=f"{name}@example.com",
                hashed_password=f"hashed::{name}",
                name=name,
                raw_password=password,
                role="user",
            )
        )
        cache_dek(auth.user.id, auth.dek, f"jti-{name}", time.time() + 3600)
        people[name] = auth.user.id

    yield Accounts(session, people["owner"], people["intruder"])

    session.close()
    run(async_engine.dispose())
    engine.dispose()
    crypto_context._dek_cache.clear()
    monkeypatch.undo()


@pytest.fixture
def db(accounts):
    """A clean set of tables, with the owner as the person making the request."""
    set_current_user_id(accounts.owner)

    yield accounts.session

    set_current_user_id(None)
    accounts.session.rollback()

    # Every table, in reverse dependency order, rather than only the ones the
    # encryption registry knows about: a test that writes a row of some other
    # kind would otherwise leak into the next one. Emptied by statement so no
    # row is loaded, and therefore decrypted, on the way out.
    for table in reversed(Base.metadata.sorted_tables):
        if table.name not in KEEP_BETWEEN_TESTS:
            accounts.session.execute(table.delete())

    accounts.session.commit()
    accounts.session.expunge_all()
