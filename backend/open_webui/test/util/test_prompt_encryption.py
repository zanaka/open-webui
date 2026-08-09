"""Prompts, the first registered model not identified by a column called "id".

A prompt is reached by the command a person types, which is also its primary
key. That is why EncryptionPolicy carries an `identity` field: the registry has
to know which column names a row before it can ask who holds its key.
"""

import pytest
from sqlalchemy import text

from open_webui.crypto_exceptions import EncryptedDataAccessDeniedError
from open_webui.models.prompts import Prompt, PromptForm, Prompts
from open_webui.models.resource_keys import ResourceKey
from open_webui.utils.crypto_context import set_current_user_id
from open_webui.utils.encrypted_models import ENCRYPTED_MODELS
from open_webui.utils.resource_crypto import SharingNotSupportedError, resolve_key

MARKER = "OBSIDIAN-CANARY"
COMMAND = "/report"


def _form(command=COMMAND, access_control=None):
    return PromptForm(
        command=command,
        title=f"{MARKER} title",
        content=f"{MARKER} content",
        access_control={} if access_control is None else access_control,
    )


def _shared_with(*user_ids, permission="read"):
    return {permission: {"user_ids": list(user_ids), "group_ids": []}}


def _add(db, owner, **kwargs):
    """Created by its owner, because that is the only way it happens.

    insert_new_prompt reads the row back before returning it, so whoever writes
    a prompt has to be the person the request is running as.
    """
    set_current_user_id(owner)
    try:
        return Prompts.insert_new_prompt(owner, _form(**kwargs), db=db)
    finally:
        db.expunge_all()


class TestIdentity:
    def test_the_policy_names_the_command_column(self):
        assert ENCRYPTED_MODELS[Prompt].identity == "command"

    def test_the_key_is_stored_against_the_command(self, db, accounts):
        _add(db, accounts.owner)

        row = (
            db.query(ResourceKey)
            .filter_by(resource_type="Prompt", resource_id=COMMAND)
            .one()
        )
        assert row.user_id == accounts.owner


class TestAtRest:
    def test_the_title_and_content_are_ciphertext(self, db, accounts):
        _add(db, accounts.owner)

        stored = db.execute(text("SELECT title, content FROM prompt")).first()

        assert MARKER not in f"{stored[0]} {stored[1]}"

    def test_the_command_stays_readable(self, db, accounts):
        """It is what a person types to find the row, so it cannot be a token
        that only the row's key could produce."""
        _add(db, accounts.owner)

        assert db.execute(text("SELECT command FROM prompt")).scalar() == COMMAND

    def test_the_owner_reads_it_back(self, db, accounts):
        _add(db, accounts.owner)
        db.expunge_all()

        prompt = Prompts.get_prompt_by_command(COMMAND, db=db)

        assert prompt.title == f"{MARKER} title"
        assert prompt.content == f"{MARKER} content"


class TestNamedSharing:
    def test_a_named_recipient_can_open_it(self, db, accounts):
        _add(db, accounts.owner, access_control=_shared_with(accounts.intruder))
        db.expunge_all()

        set_current_user_id(accounts.intruder)

        assert (
            Prompts.get_prompt_by_command(COMMAND, db=db).content
            == f"{MARKER} content"
        )

    def test_someone_not_named_cannot_open_it(self, db, accounts):
        _add(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        with pytest.raises(EncryptedDataAccessDeniedError):
            db.query(Prompt).filter_by(command=COMMAND).one()

    def test_a_prompt_shared_with_me_by_name_is_listed(self, db, accounts):
        _add(db, accounts.intruder, access_control=_shared_with(accounts.owner))
        set_current_user_id(accounts.owner)

        listed = Prompts.get_prompts_by_user_id(accounts.owner, "read", db=db)

        assert [prompt.command for prompt in listed] == [COMMAND]

    def test_someone_elses_private_prompt_is_not_listed(self, db, accounts):
        _add(db, accounts.intruder)
        set_current_user_id(accounts.owner)

        assert Prompts.get_prompts_by_user_id(accounts.owner, "read", db=db) == []

    def test_unsharing_takes_the_key_back(self, db, accounts):
        _add(db, accounts.owner, access_control=_shared_with(accounts.intruder))
        assert resolve_key("Prompt", COMMAND, accounts.intruder, db=db) is not None

        Prompts.update_prompt_by_command(COMMAND, _form(access_control={}), db=db)

        assert resolve_key("Prompt", COMMAND, accounts.intruder, db=db) is None


class TestRefusedAudiences:
    def test_sharing_with_everyone_is_refused(self, db, accounts):
        with pytest.raises(SharingNotSupportedError):
            Prompts.insert_new_prompt(
                accounts.owner,
                PromptForm(
                    command=COMMAND, title="t", content="c", access_control=None
                ),
                db=db,
            )

    def test_sharing_with_a_group_is_refused(self, db, accounts):
        with pytest.raises(SharingNotSupportedError):
            _add(
                db,
                accounts.owner,
                access_control={"read": {"user_ids": [], "group_ids": ["engineering"]}},
            )


class TestDeletingWithoutReading:
    def test_ownership_can_be_read_without_a_key(self, db, accounts):
        """What the delete route checks. Loading the row would decrypt it,
        refuse, and have the refusal swallowed into a misleading "not found"."""
        _add(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        access = Prompts.get_prompt_access_by_command(COMMAND, db=db)

        assert access.user_id == accounts.owner

    def test_someone_holding_no_key_can_still_delete_it(self, db, accounts):
        _add(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        assert Prompts.delete_prompt_by_command(COMMAND, db=db) is True
        assert db.query(Prompt).filter_by(command=COMMAND).count() == 0

    def test_deleting_takes_the_key_copies_with_it(self, db, accounts):
        _add(db, accounts.owner, access_control=_shared_with(accounts.intruder))

        Prompts.delete_prompt_by_command(COMMAND, db=db)

        assert (
            db.query(ResourceKey)
            .filter_by(resource_type="Prompt", resource_id=COMMAND)
            .count()
            == 0
        )
