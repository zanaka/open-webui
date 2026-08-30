"""Skills, encrypted like prompts: a person's instructions, shared by name.

Unlike Tools and Functions — administrator code loaded with no user signed in
— a skill is only ever read inside a request where the user who picked it is
signed in, so a key is always in hand. The grants-scoped listing keeps rows
the requester cannot open out of every query.
"""

import pytest
from conftest import run
from sqlalchemy import text

from open_webui.crypto_exceptions import EncryptedDataAccessDeniedError
from open_webui.models.resource_keys import ResourceKey
from open_webui.models.skills import Skill, SkillForm, Skills
from open_webui.utils.crypto_context import set_current_user_id
from open_webui.utils.encrypted_models import ENCRYPTED_MODELS
from open_webui.utils.resource_crypto import SharingNotSupportedError, resolve_key

MARKER = "BASALT-CANARY"
SKILL_ID = "sk1"


def _form(access_grants=None):
    return SkillForm(
        id=SKILL_ID,
        name=f"{MARKER} name",
        description=f"{MARKER} description",
        content=f"{MARKER} content",
        access_grants=[] if access_grants is None else access_grants,
    )


def _shared_with(*user_ids, permission="read"):
    return [
        {"principal_type": "user", "principal_id": user_id, "permission": permission}
        for user_id in user_ids
    ]


def _add(db, owner, **kwargs):
    set_current_user_id(owner)
    try:
        return run(Skills.insert_new_skill(owner, _form(**kwargs)))
    finally:
        db.expunge_all()


class TestAtRest:
    def test_the_declared_columns_are_ciphertext(self, db, accounts):
        _add(db, accounts.owner)

        stored = db.execute(text("SELECT name, description, content FROM skill")).first()

        assert MARKER not in " ".join(str(value) for value in stored)

    def test_the_owner_reads_it_back(self, db, accounts):
        _add(db, accounts.owner)
        db.expunge_all()

        skill = run(Skills.get_skill_by_id(SKILL_ID))

        assert skill.name == f"{MARKER} name"
        assert skill.content == f"{MARKER} content"

    def test_the_key_is_stored_against_the_id(self, db, accounts):
        _add(db, accounts.owner)

        row = (
            db.query(ResourceKey)
            .filter_by(resource_type="Skill", resource_id=SKILL_ID)
            .one()
        )
        assert row.user_id == accounts.owner


class TestNamedSharing:
    def test_a_named_recipient_can_open_it(self, db, accounts):
        _add(db, accounts.owner, access_grants=_shared_with(accounts.intruder))
        db.expunge_all()

        set_current_user_id(accounts.intruder)

        assert run(Skills.get_skill_by_id(SKILL_ID)).content == f"{MARKER} content"

    def test_someone_not_named_cannot_open_it(self, db, accounts):
        _add(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        with pytest.raises(EncryptedDataAccessDeniedError):
            db.query(Skill).filter_by(id=SKILL_ID).one()

    def test_the_listing_shows_only_what_the_requester_can_open(self, db, accounts):
        _add(db, accounts.intruder)
        set_current_user_id(accounts.owner)

        listed = run(Skills.get_skills(user_id=accounts.owner))

        assert listed == []

    def test_unsharing_takes_the_key_back(self, db, accounts):
        _add(db, accounts.owner, access_grants=_shared_with(accounts.intruder))
        assert resolve_key("Skill", SKILL_ID, accounts.intruder, db=db) is not None

        run(
            Skills.update_skill_by_id(
                SKILL_ID, _form(access_grants=[]).model_dump(exclude={"id"})
            )
        )

        assert resolve_key("Skill", SKILL_ID, accounts.intruder, db=db) is None


class TestRefusedAudiences:
    def test_sharing_with_everyone_is_refused(self, db, accounts):
        with pytest.raises(SharingNotSupportedError):
            _add(
                db,
                accounts.owner,
                access_grants=[
                    {"principal_type": "user", "principal_id": "*", "permission": "read"}
                ],
            )

    def test_sharing_with_a_group_is_refused(self, db, accounts):
        with pytest.raises(SharingNotSupportedError):
            _add(
                db,
                accounts.owner,
                access_grants=[
                    {
                        "principal_type": "group",
                        "principal_id": "engineering",
                        "permission": "read",
                    }
                ],
            )


class TestDeletingWithoutReading:
    def test_someone_holding_no_key_can_still_delete_it(self, db, accounts):
        _add(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        assert run(Skills.delete_skill_by_id(SKILL_ID)) is True
        assert db.query(Skill).filter_by(id=SKILL_ID).count() == 0

    def test_deleting_takes_the_key_copies_with_it(self, db, accounts):
        _add(db, accounts.owner, access_grants=_shared_with(accounts.intruder))

        run(Skills.delete_skill_by_id(SKILL_ID))

        assert (
            db.query(ResourceKey)
            .filter_by(resource_type="Skill", resource_id=SKILL_ID)
            .count()
            == 0
        )
