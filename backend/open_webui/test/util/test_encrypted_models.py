import time

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from open_webui.crypto_exceptions import EncryptedDataAccessDeniedError
from open_webui.internal.db import Base
from open_webui.models.chats import Chat
from open_webui.models.files import File
from open_webui.models.memories import Memory
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek, set_current_user_id
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.encrypted_models import ENCRYPTED_MODELS, install

install()

OWNER = "registry-owner"
INTRUDER = "registry-intruder"
MARKER = "SECRET-MARKER-PHRASE"


def _now():
    return int(time.time())


# One builder per registered model. The first test below fails if a model is
# added to the registry without being covered here.
BUILDERS = {
    Chat: lambda: Chat(
        id="c1",
        user_id=OWNER,
        title=f"{MARKER} title",
        chat={"messages": [{"role": "user", "content": f"{MARKER} body"}]},
        meta={"tags": []},
        created_at=_now(),
        updated_at=_now(),
    ),
    File: lambda: File(
        id="f1",
        user_id=OWNER,
        filename=f"{MARKER}.txt",
        path="/uploads/f1",
        data={"content": f"{MARKER} contents"},
        meta={"name": f"{MARKER}.txt"},
        created_at=_now(),
        updated_at=_now(),
    ),
    Memory: lambda: Memory(
        id="m1",
        user_id=OWNER,
        content=f"{MARKER} memory",
        created_at=_now(),
        updated_at=_now(),
    ),
}


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(
        engine, tables=[model.__table__ for model in ENCRYPTED_MODELS]
    )
    session = sessionmaker(bind=engine)()

    cache_dek(OWNER, generate_dek(), jti="jti-owner", expires_at=time.time() + 3600)
    cache_dek(
        INTRUDER, generate_dek(), jti="jti-intruder", expires_at=time.time() + 3600
    )
    set_current_user_id(OWNER)

    yield session

    set_current_user_id(None)
    session.close()
    engine.dispose()
    crypto_context._dek_cache.clear()


def _raw(db, model, columns):
    row = db.execute(
        text(f"SELECT {', '.join(columns)} FROM {model.__tablename__}")
    ).first()
    return " ".join("" if value is None else str(value) for value in row)


MODELS = list(BUILDERS)
IDS = [model.__name__ for model in MODELS]


def test_every_registered_model_is_covered_here():
    """Adding a model to the registry must come with coverage."""
    assert set(ENCRYPTED_MODELS) == set(BUILDERS)


@pytest.mark.parametrize("model", MODELS, ids=IDS)
class TestRegisteredModels:
    def test_declared_columns_are_ciphertext_at_rest(self, db, model):
        db.add(BUILDERS[model]())
        db.commit()

        stored = _raw(db, model, ENCRYPTED_MODELS[model].columns)
        assert MARKER not in stored

    def test_round_trips_for_the_owner(self, db, model):
        db.add(BUILDERS[model]())
        db.commit()
        db.expire_all()

        loaded = db.query(model).one()
        policy = ENCRYPTED_MODELS[model]
        expected = BUILDERS[model]()
        for column in policy.columns:
            assert getattr(loaded, column) == getattr(expected, column)

    def test_object_reads_as_plaintext_after_save(self, db, model):
        instance = BUILDERS[model]()
        expected = BUILDERS[model]()
        db.add(instance)
        db.commit()

        for column in ENCRYPTED_MODELS[model].columns:
            assert getattr(instance, column) == getattr(expected, column)

    def test_another_user_cannot_decrypt(self, db, model):
        db.add(BUILDERS[model]())
        db.commit()
        db.expire_all()

        set_current_user_id(INTRUDER)
        with pytest.raises(EncryptedDataAccessDeniedError):
            db.query(model).one()

    def test_without_a_user_context_it_refuses(self, db, model):
        db.add(BUILDERS[model]())
        db.commit()
        db.expire_all()

        set_current_user_id(None)
        with pytest.raises(RuntimeError):
            db.query(model).one()

    def test_update_re_encrypts(self, db, model):
        db.add(BUILDERS[model]())
        db.commit()

        loaded = db.query(model).one()
        column = ENCRYPTED_MODELS[model].text[0]
        setattr(loaded, column, f"{MARKER} changed")
        db.commit()

        assert MARKER not in _raw(db, model, [column])
        db.expire_all()
        assert getattr(db.query(model).one(), column) == f"{MARKER} changed"


def test_install_is_idempotent(db):
    """A second install must not stack a second round of encryption."""
    install()
    install()

    db.add(BUILDERS[Chat]())
    db.commit()
    db.expire_all()

    loaded = db.query(Chat).one()
    assert loaded.title == f"{MARKER} title"
