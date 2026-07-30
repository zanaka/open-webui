"""How a file may be reached.

routers/files.py carried a has_access_to_file() that granted access through a
channel the file was posted in, or through a shared chat it was attached to.
Both paths were closed elsewhere, so neither could happen; the function itself
had no callers at all. Worse, granting on those grounds was incoherent: a file
is encrypted with its owner's key, so someone let in that way would have been
handed a row they cannot open.

These tests pin the two facts that made the removal safe, so that reopening
channels or chat sharing does not quietly bring the dead grant back with them.
"""

import inspect

import pytest
from fastapi import HTTPException

from open_webui.models.chats import Chats
from open_webui.routers import files as files_router
from open_webui.routers.channels import check_channels_access
from open_webui.routers.chats import (
    get_shared_chat_by_id,
    share_chat_by_id,
)
from open_webui.utils.encrypted_models import ENCRYPTED_MODELS


class TestTheGrantIsGone:
    def test_there_is_no_file_access_check_to_call(self):
        """It had no callers, so leaving it would only invite one."""
        assert not hasattr(files_router, "has_access_to_file")

    def test_nothing_in_the_router_asks_a_channel_about_a_file(self):
        source = inspect.getsource(files_router)

        assert "get_channels_by_file_id_and_user_id" not in source

    def test_nothing_in_the_router_asks_for_shared_chats(self):
        source = inspect.getsource(files_router)

        assert "get_shared_chats_by_file_id" not in source


class TestWhyItWasUnreachable:
    def test_channels_are_closed(self):
        """No channel can be created, so no file is posted in one."""
        with pytest.raises(HTTPException) as raised:
            check_channels_access(request=None)

        assert raised.value.status_code == 501

    def test_no_chat_can_be_shared(self):
        """Both ends of chat sharing refuse, so Chat.share_id stays null."""
        for endpoint in (share_chat_by_id, get_shared_chat_by_id):
            assert "501" in inspect.getsource(endpoint) or "NOT_IMPLEMENTED" in (
                inspect.getsource(endpoint)
            )

    def test_the_shared_chat_lookup_only_finds_shared_chats(self):
        """Which is why it can never return anything while sharing is closed."""
        source = inspect.getsource(Chats.get_shared_chats_by_file_id)

        assert "share_id.isnot(None)" in source


class TestWhyTheGrantWasWrong:
    def test_a_file_is_opened_with_its_owners_key(self):
        """So letting a non-owner in would hand them something unreadable."""
        from open_webui.models.files import File

        assert ENCRYPTED_MODELS[File].owner == "user_id"
