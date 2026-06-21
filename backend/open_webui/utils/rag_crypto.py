import base64
import logging
from typing import Optional

from sqlalchemy.orm import Session

from open_webui.utils.crypto_context import get_current_user_id
from open_webui.utils.crypto_utils import decrypt_value, encrypt_value
from open_webui.utils.knowledge_crypto import resolve_kdek

log = logging.getLogger(__name__)

_ENCRYPTED_METADATA_FIELDS = ("name", "source")


def _encrypt_str(plaintext: str, kdek: bytes) -> str:
    ciphertext = encrypt_value(plaintext.encode("utf-8"), kdek)
    return base64.b64encode(ciphertext).decode("ascii")


def _decrypt_str(value, kdek: bytes):
    if not isinstance(value, str):
        return value
    ciphertext = base64.b64decode(value)
    return decrypt_value(ciphertext, kdek).decode("utf-8")


def encrypt_items(items: list[dict], kdek: bytes) -> None:
    for item in items:
        if item.get("text") is not None:
            item["text"] = _encrypt_str(item["text"], kdek)
        metadata = item.get("metadata")
        if isinstance(metadata, dict):
            for field in _ENCRYPTED_METADATA_FIELDS:
                if metadata.get(field) is not None:
                    metadata[field] = _encrypt_str(str(metadata[field]), kdek)


def decrypt_result(result, kdek: bytes):
    if result is None:
        return result
    if getattr(result, "documents", None):
        for batch in result.documents:
            for idx, document in enumerate(batch):
                batch[idx] = _decrypt_str(document, kdek)
    if getattr(result, "metadatas", None):
        for batch in result.metadatas:
            for metadata in batch:
                if not isinstance(metadata, dict):
                    continue
                for field in _ENCRYPTED_METADATA_FIELDS:
                    if field in metadata:
                        metadata[field] = _decrypt_str(metadata[field], kdek)
    return result


def encrypt_items_for_collection(
    collection_name: str,
    user_id: str,
    items: list[dict],
    db: Optional[Session] = None,
) -> None:
    kdek = resolve_kdek(collection_name, user_id, db=db)
    if kdek is None:
        return
    encrypt_items(items, kdek)


def decrypt_result_for_collection(collection_name: str, result):
    if result is None:
        return result
    user_id = get_current_user_id()
    if not user_id:
        return result
    try:
        kdek = resolve_kdek(collection_name, user_id)
    except Exception as e:
        log.debug(f"Could not resolve KDEK for collection {collection_name}: {e}")
        return result
    if kdek is None:
        return result
    return decrypt_result(result, kdek)
