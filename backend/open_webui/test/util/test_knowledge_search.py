import time

from conftest import run

from open_webui.models.access_grants import AccessGrants
from open_webui.models.knowledge import Knowledge, Knowledges
from open_webui.utils.crypto_context import set_current_user_id


def _add(
    db,
    knowledge_id,
    name,
    owner,
    description="",
    ts=None,
    access_grants=None,
):
    # Written as its owner, because that is the only way it happens: wrapping
    # key copies for named recipients needs the key in the writer's hands.
    set_current_user_id(owner)
    now = ts if ts is not None else int(time.time())
    db.add(
        Knowledge(
            id=knowledge_id,
            user_id=owner,
            name=name,
            description=description,
            meta=None,
            created_at=now,
            updated_at=now,
        )
    )
    db.commit()
    if access_grants:
        run(AccessGrants.set_access_grants("knowledge", knowledge_id, access_grants))
    db.expunge_all()


def _search(db, user_id, query, **kwargs):
    set_current_user_id(user_id)
    return run(
        Knowledges.search_knowledge_bases(
            user_id, filter={"query": query, "user_id": user_id}, **kwargs
        )
    )


class TestSearch:
    """Names and descriptions are matched after they are read, because they are
    encrypted at rest."""

    def test_matches_the_name(self, db, accounts):
        _add(db, "k1", "Project Falcon", accounts.owner)
        _add(db, "k2", "Something Else", accounts.owner)

        result = _search(db, accounts.owner, "falcon")

        assert [item.id for item in result.items] == ["k1"]
        assert result.total == 1

    def test_matches_the_description(self, db, accounts):
        _add(db, "k1", "Untitled", accounts.owner, description="notes about Falcon")
        _add(db, "k2", "Untitled", accounts.owner, description="unrelated")

        result = _search(db, accounts.owner, "falcon")

        assert [item.id for item in result.items] == ["k1"]

    def test_is_case_insensitive(self, db, accounts):
        _add(db, "k1", "Project Falcon", accounts.owner)

        assert [item.id for item in _search(db, accounts.owner, "FALCON").items] == [
            "k1"
        ]

    def test_no_match_returns_nothing(self, db, accounts):
        _add(db, "k1", "Project Falcon", accounts.owner)

        result = _search(db, accounts.owner, "condor")

        assert result.items == []
        assert result.total == 0

    def test_total_counts_matches_not_rows(self, db, accounts):
        _add(db, "k1", "Falcon one", accounts.owner, ts=100)
        _add(db, "k2", "Falcon two", accounts.owner, ts=200)
        _add(db, "k3", "Something else", accounts.owner, ts=300)

        result = _search(db, accounts.owner, "falcon")

        assert result.total == 2

    def test_paginates_after_filtering(self, db, accounts):
        _add(db, "k1", "Falcon one", accounts.owner, ts=100)
        _add(db, "k2", "Falcon two", accounts.owner, ts=200)
        _add(db, "k3", "Falcon three", accounts.owner, ts=300)

        result = _search(db, accounts.owner, "falcon", skip=1, limit=1)

        assert result.total == 3
        assert len(result.items) == 1
        # Ordered by updated_at desc, so skipping one lands on the middle entry.
        assert result.items[0].id == "k2"

    def test_a_knowledge_base_shared_with_me_by_name_is_listed(self, db, accounts):
        """Named sharing is the only kind allowed for encrypted knowledge, so it
        has to be the kind the listing can find."""
        _add(
            db,
            "k1",
            "Their Falcon",
            accounts.intruder,
            access_grants=[
                {
                    "principal_type": "user",
                    "principal_id": accounts.owner,
                    "permission": "read",
                }
            ],
        )

        set_current_user_id(accounts.owner)
        result = run(
            Knowledges.search_knowledge_bases(
                accounts.owner, filter={"user_id": accounts.owner}
            )
        )

        assert [item.id for item in result.items] == ["k1"]

    def test_someone_elses_private_knowledge_base_is_not_listed(self, db, accounts):
        _add(db, "k1", "Their Falcon", accounts.intruder)

        set_current_user_id(accounts.owner)
        result = run(
            Knowledges.search_knowledge_bases(
                accounts.owner, filter={"user_id": accounts.owner}
            )
        )

        assert result.items == []

    def test_no_query_returns_everything(self, db, accounts):
        _add(db, "k1", "Project Falcon", accounts.owner)
        _add(db, "k2", "Something Else", accounts.owner)

        result = run(
            Knowledges.search_knowledge_bases(
                accounts.owner, filter={"user_id": accounts.owner}
            )
        )

        assert result.total == 2
