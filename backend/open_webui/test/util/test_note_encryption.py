"""Notes, keyed by a key of their own like knowledge bases.

The search used to filter the title and the note body in SQL, which cannot work
once both are ciphertext. It also carried its own copy of the access-control
filter, which never looked at user_ids, so a note shared with someone by name
was invisible to them. Both are covered here.
"""

import time

import pytest
from conftest import run
from sqlalchemy import text

from open_webui.crypto_exceptions import EncryptedDataAccessDeniedError
from open_webui.models.access_grants import AccessGrants
from open_webui.models.notes import Note, NoteForm, NoteUpdateForm, Notes
from open_webui.models.resource_keys import ResourceKey
from open_webui.utils.crypto_context import set_current_user_id
from open_webui.utils.resource_crypto import SharingNotSupportedError, resolve_key

MARKER = "GRANITE-CANARY"


def _form(title=f"{MARKER} title", body=f"{MARKER} body", access_grants=None):
    return NoteForm(
        title=title,
        data={"content": {"md": body, "html": body, "json": None}},
        meta=None,
        access_grants=[] if access_grants is None else access_grants,
    )


def _shared_with(*user_ids, permission="read"):
    return [
        {"principal_type": "user", "principal_id": user_id, "permission": permission}
        for user_id in user_ids
    ]


def _add(db, owner, **kwargs):
    """Created by its owner, because that is the only way it happens.

    Wrapping key copies for the named recipients needs the key in the hands of
    whoever the request is running as, so the creator has to be that person.
    """
    set_current_user_id(owner)
    try:
        return run(Notes.insert_new_note(owner, _form(**kwargs)))
    finally:
        db.expunge_all()


def _search(db, user_id, query=None, **kwargs):
    set_current_user_id(user_id)
    filter = {"user_id": user_id, "permission": "read"}
    if query is not None:
        filter["query"] = query
    return run(Notes.search_notes(user_id, filter=filter, **kwargs))


class TestAtRest:
    def test_the_title_and_body_are_ciphertext(self, db, accounts):
        _add(db, accounts.owner)

        stored = db.execute(text("SELECT title, data FROM note")).first()

        assert MARKER not in f"{stored[0]} {stored[1]}"

    def test_the_owner_reads_it_back(self, db, accounts):
        created = _add(db, accounts.owner)
        db.expunge_all()

        note = run(Notes.get_note_by_id(created.id))

        assert note.title == f"{MARKER} title"
        assert note.data["content"]["md"] == f"{MARKER} body"

    def test_a_key_is_provisioned_without_anyone_asking(self, db, accounts):
        created = _add(db, accounts.owner)

        assert resolve_key("Note", created.id, accounts.owner, db=db) is not None


class TestSearch:
    """Matched after the rows are read, because they are encrypted at rest."""

    def test_matches_the_title(self, db, accounts):
        wanted = _add(db, accounts.owner, title="Project Falcon")
        _add(db, accounts.owner, title="Something else")

        result = _search(db, accounts.owner, "falcon")

        assert [item.id for item in result.items] == [wanted.id]

    def test_matches_the_note_body(self, db, accounts):
        wanted = _add(db, accounts.owner, title="Untitled", body="notes about Falcon")
        _add(db, accounts.owner, title="Untitled", body="unrelated")

        result = _search(db, accounts.owner, "falcon")

        assert [item.id for item in result.items] == [wanted.id]

    def test_hyphens_and_spaces_are_ignored(self, db, accounts):
        """The behaviour the SQL version had, kept after moving into Python."""
        wanted = _add(db, accounts.owner, title="to-do list")

        assert [item.id for item in _search(db, accounts.owner, "todo").items] == [
            wanted.id
        ]

    def test_no_match_returns_nothing(self, db, accounts):
        _add(db, accounts.owner, title="Project Falcon")

        result = _search(db, accounts.owner, "condor")

        assert result.items == []
        assert result.total == 0

    def test_total_counts_matches_not_rows(self, db, accounts):
        _add(db, accounts.owner, title="Falcon one")
        _add(db, accounts.owner, title="Falcon two")
        _add(db, accounts.owner, title="Something else")

        assert _search(db, accounts.owner, "falcon").total == 2

    def test_paginates_after_filtering(self, db, accounts):
        for name in ("Falcon one", "Falcon two", "Falcon three"):
            _add(db, accounts.owner, title=name)
            time.sleep(0.001)

        result = _search(db, accounts.owner, "falcon", skip=1, limit=1)

        assert result.total == 3
        assert len(result.items) == 1

    def test_sorts_by_decrypted_title(self, db, accounts):
        for name in ("charlie", "alpha", "bravo"):
            _add(db, accounts.owner, title=name)

        result = run(
            Notes.search_notes(
                accounts.owner,
                filter={
                    "user_id": accounts.owner,
                    "permission": "read",
                    "order_by": "name",
                    "direction": "asc",
                },
            )
        )

        assert [item.title for item in result.items] == ["alpha", "bravo", "charlie"]


class TestNamedSharing:
    def test_a_note_shared_with_me_by_name_is_listed(self, db, accounts):
        """The old per-model filter never looked at user_ids, so this was
        invisible to the person it was shared with."""
        shared = _add(
            db,
            accounts.intruder,
            access_grants=_shared_with(accounts.owner),
        )

        result = _search(db, accounts.owner)

        assert [item.id for item in result.items] == [shared.id]

    def test_someone_elses_private_note_is_not_listed(self, db, accounts):
        _add(db, accounts.intruder)

        assert _search(db, accounts.owner).items == []

    def test_a_named_recipient_can_open_it(self, db, accounts):
        created = _add(db, accounts.owner, access_grants=_shared_with(accounts.intruder))
        db.expunge_all()

        set_current_user_id(accounts.intruder)

        assert run(Notes.get_note_by_id(created.id)).title == f"{MARKER} title"

    def test_someone_not_named_cannot_open_it(self, db, accounts):
        created = _add(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        with pytest.raises(EncryptedDataAccessDeniedError):
            db.query(Note).filter_by(id=created.id).one()

    def test_unsharing_takes_the_key_back(self, db, accounts):
        created = _add(db, accounts.owner, access_grants=_shared_with(accounts.intruder))
        assert resolve_key("Note", created.id, accounts.intruder, db=db) is not None

        run(Notes.update_note_by_id(created.id, NoteUpdateForm(access_grants=[])))

        assert resolve_key("Note", created.id, accounts.intruder, db=db) is None


class TestRefusedAudiences:
    def test_sharing_with_everyone_is_refused(self, db, accounts):
        """A wildcard grant is Open WebUI's "public": there is nobody to wrap
        a key for."""
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


class TestDeleting:
    def test_ownership_can_be_read_without_a_key(self, db, accounts):
        """What the delete route checks before deleting. Loading the row would
        decrypt it and refuse, so the route reads only ownership and reach."""
        created = _add(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        access = run(Notes.get_note_access_by_id(created.id))

        assert access.user_id == accounts.owner
        assert run(AccessGrants.get_grants_by_resource("note", created.id)) == []

    def test_someone_holding_no_key_can_still_delete_it(self, db, accounts):
        created = _add(db, accounts.owner)
        db.expunge_all()

        set_current_user_id(accounts.intruder)
        assert run(Notes.delete_note_by_id(created.id)) is True
        assert db.query(Note).filter_by(id=created.id).count() == 0

    def test_deleting_takes_the_key_copies_with_it(self, db, accounts):
        created = _add(db, accounts.owner, access_grants=_shared_with(accounts.intruder))

        run(Notes.delete_note_by_id(created.id))

        assert (
            db.query(ResourceKey)
            .filter_by(resource_type="Note", resource_id=created.id)
            .count()
            == 0
        )
