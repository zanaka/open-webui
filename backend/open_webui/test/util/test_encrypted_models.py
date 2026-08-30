import time

import pytest
from sqlalchemy import text

from open_webui.crypto_exceptions import EncryptedDataAccessDeniedError
from open_webui.models.calendar import Calendar, CalendarEvent
from open_webui.models.chat_messages import ChatMessage
from open_webui.models.chats import Chat
from open_webui.models.files import File
from open_webui.models.folders import Folder
from open_webui.models.knowledge import Knowledge
from open_webui.models.memories import Memory
from open_webui.models.notes import Note
from open_webui.models.prompts import Prompt
from open_webui.models.skills import Skill
from open_webui.models.tags import Tag
from open_webui.utils.crypto_context import set_current_user_id
from open_webui.utils import encrypted_models
from open_webui.utils.encrypted_models import (
    BORROWED_KEYS,
    ENCRYPTED_MODELS,
    UnclassifiedModelError,
    assert_models_are_covered,
    install,
)

MARKER = "SECRET-MARKER-PHRASE"


def _now():
    return int(time.time())


# One builder per registered model, taking the owner's id. The first test below
# fails if a model is added to the registry without being covered here.
BUILDERS = {
    Chat: lambda owner: Chat(
        id="c1",
        user_id=owner,
        title=f"{MARKER} title",
        chat={"messages": [{"role": "user", "content": f"{MARKER} body"}]},
        summary=f"{MARKER} summary",
        tasks={"note": f"{MARKER} task"},
        meta={"tags": []},
        created_at=_now(),
        updated_at=_now(),
    ),
    ChatMessage: lambda owner: ChatMessage(
        id="c1-m1",
        chat_id="c1",
        user_id=owner,
        role="user",
        content=f"{MARKER} message",
        output={"text": f"{MARKER} output"},
        files=[{"name": f"{MARKER}.txt"}],
        sources=[{"snippet": MARKER}],
        embeds=[{"url": MARKER}],
        meta={"note": MARKER},
        status_history=[{"description": MARKER}],
        error={"message": MARKER},
        context_summary=f"{MARKER} checkpoint",
        created_at=_now(),
        updated_at=_now(),
    ),
    File: lambda owner: File(
        id="f1",
        user_id=owner,
        filename=f"{MARKER}.txt",
        path="/uploads/f1",
        data={"content": f"{MARKER} contents"},
        meta={"name": f"{MARKER}.txt"},
        created_at=_now(),
        updated_at=_now(),
    ),
    Folder: lambda owner: Folder(
        id="fo1",
        parent_id=None,
        user_id=owner,
        name=f"{MARKER} folder",
        items={"chat_ids": [f"{MARKER}-chat"]},
        meta={"icon": MARKER},
        data={"note": f"{MARKER} data"},
        created_at=_now(),
        updated_at=_now(),
    ),
    Tag: lambda owner: Tag(
        id="t1",
        user_id=owner,
        name=f"{MARKER} tag",
        meta={"note": MARKER},
    ),
    Memory: lambda owner: Memory(
        id="m1",
        user_id=owner,
        content=f"{MARKER} memory",
        created_at=_now(),
        updated_at=_now(),
    ),
    Note: lambda owner: Note(
        id="n1",
        user_id=owner,
        title=f"{MARKER} note",
        data={"content": {"md": f"{MARKER} body", "html": "", "json": None}},
        meta={"tags": [MARKER]},
        created_at=_now(),
        updated_at=_now(),
    ),
    Prompt: lambda owner: Prompt(
        id="p1",
        command="/marker",
        user_id=owner,
        name=f"{MARKER} prompt",
        content=f"{MARKER} content",
        created_at=_now(),
        updated_at=_now(),
    ),
    Knowledge: lambda owner: Knowledge(
        id="k1",
        user_id=owner,
        name=f"{MARKER} knowledge",
        description=f"{MARKER} description",
        meta={"note": MARKER},
        created_at=_now(),
        updated_at=_now(),
    ),
    Skill: lambda owner: Skill(
        id="sk1",
        user_id=owner,
        name=f"{MARKER} skill",
        description=f"{MARKER} description",
        content=f"{MARKER} content",
        meta={"note": MARKER},
        created_at=_now(),
        updated_at=_now(),
    ),
    Calendar: lambda owner: Calendar(
        id="cal1",
        user_id=owner,
        name=f"{MARKER} calendar",
        data={"note": MARKER},
        meta={"note": MARKER},
        created_at=_now(),
        updated_at=_now(),
    ),
    CalendarEvent: lambda owner: CalendarEvent(
        id="ev1",
        calendar_id="cal1",
        user_id=owner,
        title=f"{MARKER} event",
        description=f"{MARKER} description",
        location=f"{MARKER} location",
        rrule=f"FREQ=DAILY;{MARKER}",
        data={"note": MARKER},
        meta={"note": MARKER},
        start_at=_now(),
        created_at=_now(),
        updated_at=_now(),
    ),
}


def _raw(db, model, columns):
    row = db.execute(
        text(f"SELECT {', '.join(columns)} FROM {model.__tablename__}")
    ).first()
    return " ".join("" if value is None else str(value) for value in row)


MODELS = list(BUILDERS)
IDS = [model.__name__ for model in MODELS]


def test_every_registered_model_is_covered_here():
    """Adding a model to the registry must come with coverage.

    Models that borrow another row's key cannot be built standalone — their
    key comes from the row they duplicate — so each has a dedicated test file
    instead (e.g. test_prompt_history_encryption.py for PromptHistory).
    """
    assert set(ENCRYPTED_MODELS) == set(BUILDERS) | set(BORROWED_KEYS)


@pytest.mark.parametrize("model", MODELS, ids=IDS)
class TestRegisteredModels:
    def test_declared_columns_are_ciphertext_at_rest(self, db, accounts, model):
        db.add(BUILDERS[model](accounts.owner))
        db.commit()

        stored = _raw(db, model, ENCRYPTED_MODELS[model].columns)
        assert MARKER not in stored

    def test_round_trips_for_the_owner(self, db, accounts, model):
        db.add(BUILDERS[model](accounts.owner))
        db.commit()
        db.expunge_all()

        loaded = db.query(model).one()
        policy = ENCRYPTED_MODELS[model]
        expected = BUILDERS[model](accounts.owner)
        for column in policy.columns:
            assert getattr(loaded, column) == getattr(expected, column)

    def test_object_reads_as_plaintext_after_save(self, db, accounts, model):
        instance = BUILDERS[model](accounts.owner)
        expected = BUILDERS[model](accounts.owner)
        db.add(instance)
        db.commit()

        for column in ENCRYPTED_MODELS[model].columns:
            assert getattr(instance, column) == getattr(expected, column)

    def test_another_user_cannot_decrypt(self, db, accounts, model):
        db.add(BUILDERS[model](accounts.owner))
        db.commit()
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        with pytest.raises(EncryptedDataAccessDeniedError):
            db.query(model).one()

    def test_without_a_user_context_it_refuses(self, db, accounts, model):
        db.add(BUILDERS[model](accounts.owner))
        db.commit()
        db.expunge_all()

        set_current_user_id(None)
        with pytest.raises(RuntimeError):
            db.query(model).one()

    def test_update_re_encrypts(self, db, accounts, model):
        db.add(BUILDERS[model](accounts.owner))
        db.commit()

        loaded = db.query(model).one()
        column = ENCRYPTED_MODELS[model].text[0]
        setattr(loaded, column, f"{MARKER} changed")
        db.commit()

        assert MARKER not in _raw(db, model, [column])
        db.expunge_all()
        assert getattr(db.query(model).one(), column) == f"{MARKER} changed"


class TestCoverage:
    @staticmethod
    def _import_every_model():
        """The check only sees models that have been imported."""
        import importlib
        import pkgutil

        import open_webui.config  # noqa: F401  (defines the Config model)
        import open_webui.models as models

        for module in pkgutil.iter_modules(models.__path__):
            importlib.import_module(f"open_webui.models.{module.name}")

    def test_every_model_in_the_schema_is_classified(self):
        self._import_every_model()
        assert_models_are_covered()

    def test_an_unclassified_model_stops_startup(self, monkeypatch):
        self._import_every_model()
        without_feedback = {
            name: reason
            for name, reason in encrypted_models.NOT_ENCRYPTED.items()
            if name != "Feedback"
        }
        monkeypatch.setattr(encrypted_models, "NOT_ENCRYPTED", without_feedback)

        with pytest.raises(UnclassifiedModelError, match="Feedback"):
            assert_models_are_covered()

    def test_encrypted_and_exempt_do_not_overlap(self):
        encrypted = {model.__name__ for model in ENCRYPTED_MODELS}
        assert encrypted.isdisjoint(encrypted_models.NOT_ENCRYPTED)

    def test_every_exemption_states_a_reason(self):
        assert all(
            reason.strip() for reason in encrypted_models.NOT_ENCRYPTED.values()
        )


def test_install_is_idempotent(db, accounts):
    """A second install must not stack a second round of encryption."""
    install()
    install()

    db.add(BUILDERS[Chat](accounts.owner))
    db.commit()
    db.expunge_all()

    loaded = db.query(Chat).one()
    assert loaded.title == f"{MARKER} title"
