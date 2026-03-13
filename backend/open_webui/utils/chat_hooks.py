"""
SQLAlchemy event hooks for transparent Chat column encryption.

Encrypts chat and title on INSERT/UPDATE and decrypts on load/refresh,
using the per-user DEK from the in-memory cache.
"""

import json
import base64

from sqlalchemy import event

from open_webui.models.chats import Chat
from open_webui.utils.crypto_utils import encrypt_value, decrypt_value
from open_webui.utils.crypto_context import get_cached_dek


def _encrypt_fields(target: Chat) -> None:
    dek = get_cached_dek(target.user_id)
    if dek is None:
        raise RuntimeError(
            f"No DEK cached for user {target.user_id}. "
            "User must be authenticated to save chat data."
        )

    # chat
    target._chat_plaintext = target.chat
    plaintext = json.dumps(target.chat).encode("utf-8")
    target.chat = base64.b64encode(encrypt_value(plaintext, dek)).decode("ascii")

    # title
    target._title_plaintext = target.title
    plaintext = target.title.encode("utf-8")
    target.title = base64.b64encode(encrypt_value(plaintext, dek)).decode("ascii")


def _decrypt_fields(target: Chat) -> None:
    dek = get_cached_dek(target.user_id)
    if dek is None:
        raise RuntimeError(
            f"No DEK cached for user {target.user_id}. "
            "User must re-login to access encrypted data."
        )

    # chat
    encrypted_bytes = base64.b64decode(target.chat)
    target.chat = json.loads(decrypt_value(encrypted_bytes, dek).decode("utf-8"))

    # title
    encrypted_bytes = base64.b64decode(target.title)
    target.title = decrypt_value(encrypted_bytes, dek).decode("utf-8")


def _restore_plaintext(target: Chat) -> None:
    if hasattr(target, "_chat_plaintext"):
        target.chat = target._chat_plaintext
        del target._chat_plaintext
    if hasattr(target, "_title_plaintext"):
        target.title = target._title_plaintext
        del target._title_plaintext


# -- Event listeners --------------------------------------------------------

@event.listens_for(Chat, "before_insert")
def on_before_insert(mapper, connection, target):
    _encrypt_fields(target)


@event.listens_for(Chat, "after_insert")
def on_after_insert(mapper, connection, target):
    _restore_plaintext(target)


@event.listens_for(Chat, "before_update")
def on_before_update(mapper, connection, target):
    _encrypt_fields(target)


@event.listens_for(Chat, "after_update")
def on_after_update(mapper, connection, target):
    _restore_plaintext(target)


@event.listens_for(Chat, "load")
def on_load(target, context):
    _decrypt_fields(target)


@event.listens_for(Chat, "refresh")
def on_refresh(target, context, attrs):
    if attrs is None or "chat" in attrs or "title" in attrs:
        _decrypt_fields(target)
