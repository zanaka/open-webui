"""Knowledge directories borrow their knowledge base's key.

A directory names part of a base's structure, so it is readable by exactly
whoever can open the base — the owner, and anyone the base is shared with by
name — with no key rows of its own to grant or revoke.
"""

import pytest
from conftest import run
from sqlalchemy import text

from open_webui.crypto_exceptions import EncryptedDataAccessDeniedError
from open_webui.models.knowledge import (
    KnowledgeDirectory,
    KnowledgeForm,
    Knowledges,
)
from open_webui.models.access_grants import AccessGrants
from open_webui.models.resource_keys import ResourceKey
from open_webui.utils.crypto_context import set_current_user_id

MARKER = "SCHIST-CANARY"


def _add_base(db, owner):
    set_current_user_id(owner)
    try:
        return run(
            Knowledges.insert_new_knowledge(
                owner,
                KnowledgeForm(name=f"{MARKER} base", description="d"),
            )
        )
    finally:
        db.expunge_all()


def _add_directory(db, owner, knowledge_id):
    set_current_user_id(owner)
    try:
        return run(
            Knowledges.create_directory(
                knowledge_id, f"{MARKER} directory", owner
            )
        )
    finally:
        db.expunge_all()


class TestBorrowedKey:
    def test_the_name_is_ciphertext_at_rest(self, db, accounts):
        base = _add_base(db, accounts.owner)
        _add_directory(db, accounts.owner, base.id)

        stored = db.execute(text("SELECT name FROM knowledge_directory")).scalar()

        assert MARKER not in str(stored)

    def test_the_owner_reads_it_back(self, db, accounts):
        base = _add_base(db, accounts.owner)
        _add_directory(db, accounts.owner, base.id)

        listed = run(Knowledges.get_directories(base.id))

        assert [d.name for d in listed] == [f"{MARKER} directory"]

    def test_no_own_key_rows_are_stored(self, db, accounts):
        base = _add_base(db, accounts.owner)
        _add_directory(db, accounts.owner, base.id)

        assert (
            db.query(ResourceKey)
            .filter_by(resource_type="KnowledgeDirectory")
            .count()
            == 0
        )

    def test_a_named_recipient_of_the_base_can_read_it(self, db, accounts):
        base = _add_base(db, accounts.owner)
        _add_directory(db, accounts.owner, base.id)
        run(
            AccessGrants.set_access_grants(
                "knowledge",
                base.id,
                [
                    {
                        "principal_type": "user",
                        "principal_id": accounts.intruder,
                        "permission": "read",
                    }
                ],
            )
        )
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        listed = run(Knowledges.get_directories(base.id))

        assert [d.name for d in listed] == [f"{MARKER} directory"]

    def test_someone_not_named_cannot(self, db, accounts):
        base = _add_base(db, accounts.owner)
        _add_directory(db, accounts.owner, base.id)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        with pytest.raises(EncryptedDataAccessDeniedError):
            db.query(KnowledgeDirectory).one()
