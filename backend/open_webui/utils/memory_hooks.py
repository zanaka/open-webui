"""
SQLAlchemy event hooks for transparent Memory column encryption.

Encrypts content on INSERT/UPDATE and decrypts on load/refresh, using the
per-user DEK from the in-memory cache.
"""

import base64

from sqlalchemy import event

from open_webui.models.memories import Memory
from open_webui.utils.crypto_utils import encrypt_value, decrypt_value
from open_webui.utils.crypto_context import get_cached_dek


def _encrypt_fields(target: Memory) -> None:
    dek = get_cached_dek(target.user_id)
    if dek is None:
        raise RuntimeError(
            f"No DEK cached for user {target.user_id}. "
            "User must be authenticated to save memory data."
        )

    target._content_plaintext = target.content
    plaintext = target.content.encode("utf-8")
    target.content = base64.b64encode(encrypt_value(plaintext, dek)).decode("ascii")


def _decrypt_fields(target: Memory) -> None:
    dek = get_cached_dek(target.user_id)
    if dek is None:
        raise RuntimeError(
            f"No DEK cached for user {target.user_id}. "
            "User must re-login to access encrypted data."
        )

    encrypted_bytes = base64.b64decode(target.content)
    target.content = decrypt_value(encrypted_bytes, dek).decode("utf-8")


def _restore_plaintext(target: Memory) -> None:
    if hasattr(target, "_content_plaintext"):
        target.content = target._content_plaintext
        del target._content_plaintext


# -- Event listeners --------------------------------------------------------

@event.listens_for(Memory, "before_insert")
def on_before_insert(mapper, connection, target):
    _encrypt_fields(target)


@event.listens_for(Memory, "after_insert")
def on_after_insert(mapper, connection, target):
    _restore_plaintext(target)


@event.listens_for(Memory, "before_update")
def on_before_update(mapper, connection, target):
    _encrypt_fields(target)


@event.listens_for(Memory, "after_update")
def on_after_update(mapper, connection, target):
    _restore_plaintext(target)


@event.listens_for(Memory, "load")
def on_load(target, context):
    _decrypt_fields(target)


@event.listens_for(Memory, "refresh")
def on_refresh(target, context, attrs):
    if attrs is None or "content" in attrs:
        _decrypt_fields(target)
