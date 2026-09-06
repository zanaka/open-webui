"""Prompt history, the first model that borrows another row's key.

A history entry duplicates its prompt's content, so it is encrypted with the
prompt's resource key: readable by exactly whoever can read the prompt, and
sharing follows the prompt's grants with nothing extra stored or revoked.
"""

import pytest
from conftest import run
from sqlalchemy import text

from open_webui.crypto_exceptions import EncryptedDataAccessDeniedError
from open_webui.models.prompt_history import PromptHistories, PromptHistory
from open_webui.models.prompts import PromptForm, Prompts
from open_webui.models.resource_keys import ResourceKey
from open_webui.utils.crypto_context import set_current_user_id

MARKER = "GNEISS-CANARY"
COMMAND = "/history-report"


def _shared_with(*user_ids, permission="read"):
    return [
        {"principal_type": "user", "principal_id": user_id, "permission": permission}
        for user_id in user_ids
    ]


def _add_prompt(db, owner, access_grants=None):
    """Creating a prompt writes its first history entry as a side effect."""
    set_current_user_id(owner)
    try:
        return run(
            Prompts.insert_new_prompt(
                owner,
                PromptForm(
                    command=COMMAND,
                    name=f"{MARKER} name",
                    content=f"{MARKER} content",
                    access_grants=[] if access_grants is None else access_grants,
                ),
            )
        )
    finally:
        db.expunge_all()


class TestAtRest:
    def test_the_snapshot_is_ciphertext(self, db, accounts):
        _add_prompt(db, accounts.owner)

        stored = db.execute(text("SELECT snapshot FROM prompt_history")).scalar()

        assert stored is not None
        assert MARKER not in str(stored)

    def test_the_owner_reads_it_back(self, db, accounts):
        prompt = _add_prompt(db, accounts.owner)
        db.expunge_all()

        entries = run(PromptHistories.get_history_by_prompt_id(prompt.id))

        assert entries[0].snapshot["content"] == f"{MARKER} content"

    def test_no_own_key_rows_are_stored(self, db, accounts):
        """The entry rides on the prompt's key; a key of its own would have to
        be granted and revoked separately and would drift."""
        _add_prompt(db, accounts.owner)

        assert (
            db.query(ResourceKey).filter_by(resource_type="PromptHistory").count()
            == 0
        )


class TestWhoCanOpenIt:
    def test_a_named_recipient_of_the_prompt_can_read_the_history(self, db, accounts):
        prompt = _add_prompt(
            db, accounts.owner, access_grants=_shared_with(accounts.intruder)
        )
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        entries = run(PromptHistories.get_history_by_prompt_id(prompt.id))

        assert entries[0].snapshot["content"] == f"{MARKER} content"

    def test_someone_not_named_cannot(self, db, accounts):
        _add_prompt(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        with pytest.raises(EncryptedDataAccessDeniedError):
            db.query(PromptHistory).one()

    def test_without_a_user_context_it_refuses(self, db, accounts):
        _add_prompt(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(None)
        with pytest.raises(RuntimeError):
            db.query(PromptHistory).one()


class TestDeleting:
    def test_deleting_the_prompt_takes_the_history_with_it_without_a_key(
        self, db, accounts
    ):
        _add_prompt(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        assert run(Prompts.delete_prompt_by_command(COMMAND)) is True
        assert db.execute(text("SELECT COUNT(*) FROM prompt_history")).scalar() == 0
