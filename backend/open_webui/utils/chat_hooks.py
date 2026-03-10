"""
SQLAlchemy event hooks for transparent Chat.chat column encryption.

Encrypts chat data on INSERT/UPDATE and decrypts on load/refresh,
using the per-user DEK from the in-memory cache. The JSON column type
is preserved by wrapping ciphertext in {"__encrypted__": "<base64>"}.
"""

import json
import base64

from sqlalchemy import event

from open_webui.models.chats import Chat
from open_webui.utils.crypto_utils import encrypt_value, decrypt_value
from open_webui.utils.crypto_context import get_cached_dek


def _encrypt_chat(target: Chat) -> None:
    if target.chat is None:
        return
    if isinstance(target.chat, dict) and "__encrypted__" in target.chat:
        return
    dek = get_cached_dek(target.user_id)
    if dek is None:
        raise RuntimeError(
            f"No DEK cached for user {target.user_id}. "
            "User must be authenticated to save chat data."
        )
    plaintext = json.dumps(target.chat).encode("utf-8")
    encrypted = encrypt_value(plaintext, dek)
    target._chat_plaintext = target.chat
    target.chat = {"__encrypted__": base64.b64encode(encrypted).decode("ascii")}


def _decrypt_chat(target: Chat) -> None:
    if target.chat is None:
        return
    if not (isinstance(target.chat, dict) and "__encrypted__" in target.chat):
        return
    dek = get_cached_dek(target.user_id)
    if dek is None:
        raise RuntimeError(
            f"Encrypted chat found but no DEK cached for user {target.user_id}. "
            "User must re-login to access encrypted data."
        )
    encrypted_bytes = base64.b64decode(target.chat["__encrypted__"])
    plaintext = decrypt_value(encrypted_bytes, dek)
    target.chat = json.loads(plaintext.decode("utf-8"))


def _restore_plaintext(target: Chat) -> None:
    if hasattr(target, "_chat_plaintext"):
        target.chat = target._chat_plaintext
        del target._chat_plaintext


# -- Event listeners --------------------------------------------------------

@event.listens_for(Chat, "before_insert")
def on_before_insert(mapper, connection, target):
    _encrypt_chat(target)


@event.listens_for(Chat, "after_insert")
def on_after_insert(mapper, connection, target):
    _restore_plaintext(target)


@event.listens_for(Chat, "before_update")
def on_before_update(mapper, connection, target):
    _encrypt_chat(target)


@event.listens_for(Chat, "after_update")
def on_after_update(mapper, connection, target):
    _restore_plaintext(target)


@event.listens_for(Chat, "load")
def on_load(target, context):
    _decrypt_chat(target)


@event.listens_for(Chat, "refresh")
def on_refresh(target, context, attrs):
    if attrs is None or "chat" in attrs:
        _decrypt_chat(target)
