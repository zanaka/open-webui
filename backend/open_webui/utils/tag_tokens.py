"""Tag ids that do not spell out the tag.

A tag's id used to be its own name with the spaces turned into underscores, so
the name stayed legible in the primary key and in every chat's tag list — both
of which are columns that are not encrypted. The id is now a keyed digest of the
name instead: the same value every time for a given user, so the equality
lookups that chat search depends on keep working, but meaningless to anyone
without that user's key.

Being deterministic, it does reveal that two chats carry the same tag, and how
many tags a user has. That is the price of matching them in SQL at all.
"""

import hashlib
import hmac

from open_webui.utils.crypto_context import require_current_user_dek

_TAG_INFO = b"owui-tag-id-v1:"


def normalize_tag_name(name: str) -> str:
    return name.replace(" ", "_").lower()


def tag_id(name: str, user_id: str) -> str:
    """The id under which this user stores this tag.

    Lowercase hex, so callers that re-normalise ids with `.lower()` stay correct.
    """
    dek = require_current_user_dek(user_id)
    return hmac.new(
        dek, _TAG_INFO + normalize_tag_name(name).encode("utf-8"), hashlib.sha256
    ).hexdigest()
