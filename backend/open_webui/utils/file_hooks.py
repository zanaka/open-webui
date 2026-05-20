"""
Encrypts filename, data, and meta on INSERT/UPDATE and decrypts on load/refresh,
using the file owner's DEK from the in-memory cache.
"""

from sqlalchemy import event

from open_webui.models.files import File
from open_webui.utils.crypto_context import require_cached_dek
from open_webui.utils.crypto_utils import (
    decrypt_json_value,
    decrypt_text,
    encrypt_json_value,
    encrypt_text,
)


def _encrypt_fields(target: File) -> None:
    dek = require_cached_dek(target.user_id)

    target._filename_plaintext = target.filename
    target._data_plaintext = target.data
    target._meta_plaintext = target.meta

    target.filename = encrypt_text(target.filename, dek)
    target.data = encrypt_json_value(target.data or {}, dek)
    target.meta = encrypt_json_value(target.meta or {}, dek)


def _decrypt_fields(target: File) -> None:
    dek = require_cached_dek(target.user_id)

    target.filename = decrypt_text(target.filename, dek)
    target.data = decrypt_json_value(target.data, dek)
    target.meta = decrypt_json_value(target.meta, dek)


def _restore_plaintext(target: File) -> None:
    if hasattr(target, "_filename_plaintext"):
        target.filename = target._filename_plaintext
        del target._filename_plaintext
    if hasattr(target, "_data_plaintext"):
        target.data = target._data_plaintext
        del target._data_plaintext
    if hasattr(target, "_meta_plaintext"):
        target.meta = target._meta_plaintext
        del target._meta_plaintext


# -- Event listeners --------------------------------------------------------


@event.listens_for(File, "before_insert")
def on_before_insert(mapper, connection, target):
    _encrypt_fields(target)


@event.listens_for(File, "after_insert")
def on_after_insert(mapper, connection, target):
    _restore_plaintext(target)


@event.listens_for(File, "before_update")
def on_before_update(mapper, connection, target):
    _encrypt_fields(target)


@event.listens_for(File, "after_update")
def on_after_update(mapper, connection, target):
    _restore_plaintext(target)


@event.listens_for(File, "load")
def on_load(target, context):
    _decrypt_fields(target)


@event.listens_for(File, "refresh")
def on_refresh(target, context, attrs):
    if attrs is None or any(attr in attrs for attr in ("filename", "data", "meta")):
        _decrypt_fields(target)
