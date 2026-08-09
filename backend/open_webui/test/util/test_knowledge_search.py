import time

from open_webui.models.knowledge import Knowledge, Knowledges


def _add(
    db,
    knowledge_id,
    name,
    owner,
    description="",
    ts=None,
    access_control=None,
):
    now = ts if ts is not None else int(time.time())
    db.add(
        Knowledge(
            id=knowledge_id,
            user_id=owner,
            name=name,
            description=description,
            meta=None,
            access_control={} if access_control is None else access_control,
            created_at=now,
            updated_at=now,
        )
    )
    db.commit()
    db.expunge_all()


def _search(db, user_id, query, **kwargs):
    return Knowledges.search_knowledge_bases(
        user_id, filter={"query": query, "user_id": user_id}, db=db, **kwargs
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
            access_control={
                "read": {"user_ids": [accounts.owner], "group_ids": []}
            },
        )

        result = Knowledges.search_knowledge_bases(
            accounts.owner, filter={"user_id": accounts.owner}, db=db
        )

        assert [item.id for item in result.items] == ["k1"]

    def test_someone_elses_private_knowledge_base_is_not_listed(self, db, accounts):
        _add(db, "k1", "Their Falcon", accounts.intruder, access_control={})

        result = Knowledges.search_knowledge_bases(
            accounts.owner, filter={"user_id": accounts.owner}, db=db
        )

        assert result.items == []

    def test_no_query_returns_everything(self, db, accounts):
        _add(db, "k1", "Project Falcon", accounts.owner)
        _add(db, "k2", "Something Else", accounts.owner)

        result = Knowledges.search_knowledge_bases(
            accounts.owner, filter={"user_id": accounts.owner}, db=db
        )

        assert result.total == 2
