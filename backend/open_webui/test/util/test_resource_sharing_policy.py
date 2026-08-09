import pytest

from open_webui.utils.resource_crypto import (
    SharingNotSupportedError,
    named_recipients,
    validate_shareable_access_control,
)


def _shared_with(*user_ids, permission="read"):
    return {permission: {"user_ids": list(user_ids), "group_ids": []}}


class TestWhatMayBeShared:
    def test_named_people_are_allowed(self):
        validate_shareable_access_control(_shared_with("alice", "bob"))

    def test_private_is_allowed(self):
        validate_shareable_access_control({})

    def test_everyone_is_refused(self):
        """`None` means public in Open WebUI: there is nobody to wrap a key for."""
        with pytest.raises(SharingNotSupportedError):
            validate_shareable_access_control(None)

    @pytest.mark.parametrize("permission", ["read", "write"])
    def test_a_group_is_refused(self, permission):
        """A group's membership moves, so its members cannot all be wrapped for."""
        access_control = {permission: {"user_ids": [], "group_ids": ["engineering"]}}

        with pytest.raises(SharingNotSupportedError):
            validate_shareable_access_control(access_control)

    def test_a_group_is_refused_even_alongside_named_people(self):
        access_control = {
            "read": {"user_ids": ["alice"], "group_ids": ["engineering"]},
        }

        with pytest.raises(SharingNotSupportedError):
            validate_shareable_access_control(access_control)


class TestRecipients:
    def test_collects_readers_and_writers(self):
        access_control = {
            "read": {"user_ids": ["alice"], "group_ids": []},
            "write": {"user_ids": ["bob"], "group_ids": []},
        }

        assert named_recipients(access_control) == {"alice", "bob"}

    def test_private_has_no_recipients(self):
        assert named_recipients({}) == set()
        assert named_recipients(None) == set()

    def test_the_same_person_in_both_counts_once(self):
        access_control = {
            "read": {"user_ids": ["alice"], "group_ids": []},
            "write": {"user_ids": ["alice"], "group_ids": []},
        }

        assert named_recipients(access_control) == {"alice"}
