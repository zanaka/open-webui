"""Knowledge bases, as the first resource keyed by a key of its own.

Nothing in routers/knowledge.py provisions, hands out or revokes a key: saving
the row does all of it, or refuses. These tests go through the ordinary save
path for that reason — if the rule only held when a router remembered to call
something, it would not be a rule.
"""

import pytest
from sqlalchemy import text

from open_webui.crypto_exceptions import EncryptedDataAccessDeniedError
from open_webui.models.knowledge import Knowledge, KnowledgeForm, Knowledges
from open_webui.models.resource_keys import ResourceKey
from open_webui.utils.crypto_context import set_current_user_id
from open_webui.utils.encrypted_models import read_without_decrypting
from open_webui.utils.resource_crypto import SharingNotSupportedError, resolve_key
from open_webui.utils.vector_keys import VectorKeyError, knowledge_key

MARKER = "PROJECT-FALCON-SECRET"


def _form(**overrides):
    return KnowledgeForm(
        **{
            "name": f"{MARKER} name",
            "description": f"{MARKER} description",
            "access_control": {},
            **overrides,
        }
    )


def _shared_with(*user_ids, permission="read"):
    return {permission: {"user_ids": list(user_ids), "group_ids": []}}


def _create(db, owner, **overrides):
    return Knowledges.insert_new_knowledge(owner, _form(**overrides), db=db)


class TestOwner:
    def test_the_owner_reads_back_what_they_wrote(self, db, accounts):
        created = _create(db, accounts.owner)

        read = Knowledges.get_knowledge_by_id(created.id, db=db)

        assert read.name == f"{MARKER} name"
        assert read.description == f"{MARKER} description"

    def test_it_is_ciphertext_at_rest(self, db, accounts):
        _create(db, accounts.owner)

        stored = db.execute(text("SELECT name, description FROM knowledge")).first()

        assert MARKER not in f"{stored[0]} {stored[1]}"

    def test_a_key_is_provisioned_without_anyone_asking(self, db, accounts):
        created = _create(db, accounts.owner)

        assert resolve_key("Knowledge", created.id, accounts.owner, db=db) is not None

    def test_the_vectors_use_the_same_key_as_the_row(self, db, accounts):
        created = _create(db, accounts.owner)

        assert knowledge_key(created.id, accounts.owner, db=db) == resolve_key(
            "Knowledge", created.id, accounts.owner, db=db
        )


class TestNamedSharing:
    def test_a_named_recipient_can_open_it(self, db, accounts):
        created = _create(db, accounts.owner, access_control=_shared_with(accounts.intruder))

        set_current_user_id(accounts.intruder)
        db.expunge_all()

        assert Knowledges.get_knowledge_by_id(created.id, db=db).name == f"{MARKER} name"

    def test_the_recipient_gets_the_same_key_wrapped_differently(self, db, accounts):
        created = _create(db, accounts.owner, access_control=_shared_with(accounts.intruder))

        wrapped = {
            row.user_id: row.wrapped_key
            for row in db.query(ResourceKey).filter_by(
                resource_type="Knowledge", resource_id=created.id
            )
        }
        assert wrapped[accounts.owner] != wrapped[accounts.intruder]
        assert resolve_key("Knowledge", created.id, accounts.intruder, db=db) == (
            resolve_key("Knowledge", created.id, accounts.owner, db=db)
        )

    def test_someone_not_named_cannot_open_it(self, db, accounts):
        created = _create(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        with pytest.raises(EncryptedDataAccessDeniedError):
            db.query(Knowledge).filter_by(id=created.id).one()

    def test_someone_not_named_gets_no_vector_key(self, db, accounts):
        created = _create(db, accounts.owner)

        with pytest.raises(VectorKeyError):
            knowledge_key(created.id, accounts.intruder, db=db)

    def test_sharing_later_hands_out_a_key(self, db, accounts):
        created = _create(db, accounts.owner)
        assert resolve_key("Knowledge", created.id, accounts.intruder, db=db) is None

        Knowledges.update_knowledge_by_id(
            created.id,
            _form(access_control=_shared_with(accounts.intruder)),
            db=db,
        )

        assert resolve_key("Knowledge", created.id, accounts.intruder, db=db) is not None

    def test_unsharing_takes_the_key_back(self, db, accounts):
        created = _create(db, accounts.owner, access_control=_shared_with(accounts.intruder))

        Knowledges.update_knowledge_by_id(created.id, _form(access_control={}), db=db)

        assert resolve_key("Knowledge", created.id, accounts.intruder, db=db) is None


class TestRefusedAudiences:
    """The feature side offers these; the save path is where they are refused."""

    def test_sharing_with_everyone_is_refused_on_create(self, db, accounts):
        with pytest.raises(SharingNotSupportedError):
            _create(db, accounts.owner, access_control=None)

    def test_sharing_with_a_group_is_refused_on_create(self, db, accounts):
        with pytest.raises(SharingNotSupportedError):
            _create(
                db,
                accounts.owner,
                access_control={"read": {"user_ids": [], "group_ids": ["engineering"]}},
            )

    def test_sharing_with_everyone_is_refused_on_update(self, db, accounts):
        created = _create(db, accounts.owner)

        with pytest.raises(SharingNotSupportedError):
            Knowledges.update_knowledge_by_id(
                created.id, _form(access_control=None), db=db
            )

    def test_a_refused_update_leaves_the_row_alone(self, db, accounts):
        created = _create(db, accounts.owner)

        with pytest.raises(SharingNotSupportedError):
            Knowledges.update_knowledge_by_id(
                created.id,
                _form(name="renamed", access_control=None),
                db=db,
            )

        db.rollback()
        db.expunge_all()
        assert Knowledges.get_knowledge_by_id(created.id, db=db).name == f"{MARKER} name"


class TestDeletingWithoutReading:
    """Deleting does not need the contents, so it must not need the key."""

    def test_ownership_can_be_read_without_a_key(self, db, accounts):
        created = _create(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        access = Knowledges.get_knowledge_access_by_id(created.id, db=db)

        assert access.user_id == accounts.owner
        assert access.access_control == {}

    def test_asking_for_an_encrypted_column_that_way_is_refused(self, db, accounts):
        created = _create(db, accounts.owner)

        with pytest.raises(ValueError, match="name"):
            read_without_decrypting(db, Knowledge, created.id, "id", "name")

    def test_someone_holding_no_key_can_still_delete_it(self, db, accounts):
        created = _create(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        assert Knowledges.delete_knowledge_by_id(created.id, db=db) is True

        assert db.query(Knowledge).filter_by(id=created.id).count() == 0

    def test_deleting_takes_the_key_copies_with_it(self, db, accounts):
        created = _create(db, accounts.owner, access_control=_shared_with(accounts.intruder))

        Knowledges.delete_knowledge_by_id(created.id, db=db)

        assert (
            db.query(ResourceKey)
            .filter_by(resource_type="Knowledge", resource_id=created.id)
            .count()
            == 0
        )
