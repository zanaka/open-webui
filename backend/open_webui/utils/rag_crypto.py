"""Encrypting and decrypting the text side of vector items, given a key.

Which key protects which collection is decided by the caller, not here; see
open_webui.utils.vector_keys.

A vector item is not only its chunk text. The metadata stored beside it carries
the document's title, the section headings it sits under and, for web results,
the snippet itself — all of which say what the chunk is about. Encrypting the
chunk and leaving those readable would give most of it back.

The hash is a different problem and gets a different answer. It is there so a
document can be recognised as one already held, so it has to stay the same for
the same document — which means it cannot be encrypted with a random nonce. But
a plain SHA-256 of the text can be recomputed by anyone holding a copy of the
document, turning the store into an oracle: dump it, hash a candidate file, and
learn whether it is in there without reading anything. It also matches across
collections, so the same file uploaded by two people is visibly the same file.
Keying the hash keeps recognition working and takes both of those away.
"""

import base64
import hashlib
import hmac
import logging

from open_webui.utils.crypto_utils import decrypt_value, encrypt_value

log = logging.getLogger(__name__)

#: Metadata that says something about the content, and so is protected like it.
#: `link` duplicates `source` for web results; encrypting one without the other
#: would leave the same URL readable under the other key.
_ENCRYPTED_TEXT_FIELDS = ("name", "source", "title", "snippet", "link")

#: The same, but held as a list of strings.
_ENCRYPTED_LIST_FIELDS = ("headings",)

#: Derived from the content but kept comparable, so it is keyed rather than
#: encrypted. Filters naming these fields are translated the same way, in
#: EncryptingVectorClient, so callers keep passing the plain value.
KEYED_FIELDS = ("hash",)

_HASH_INFO = b"owui-vector-hash-v1:"

_FILE_HASH_INFO = b"owui-file-hash-v1:"

_ENCRYPTED_METADATA_FIELDS = _ENCRYPTED_TEXT_FIELDS + _ENCRYPTED_LIST_FIELDS


def hash_token(value, key: bytes) -> str:
    """A content hash that only a holder of the collection's key can produce."""
    return hmac.new(
        key, _HASH_INFO + str(value).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def file_hash_token(value, dek: bytes) -> str:
    """A file's content fingerprint, keyed to its owner at the moment it is made.

    Applied right where the SHA-256 is computed, and from there carried around
    exactly as the plain hash used to be: written to the file row, handed to the
    vector store as metadata, read back and quoted in delete filters — always as
    an opaque value, never reversed. Deterministic per owner, so a re-upload is
    still recognised; useless to anyone else, so holding a copy of a document no
    longer confirms who stores it. The distinct info prefix keeps these tokens
    apart from the per-collection ones hash_token() derives from them.
    """
    return hmac.new(
        dek, _FILE_HASH_INFO + str(value).encode("utf-8"), hashlib.sha256
    ).hexdigest()


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
        if not isinstance(metadata, dict):
            continue

        for field in _ENCRYPTED_TEXT_FIELDS:
            if metadata.get(field) is not None:
                metadata[field] = _encrypt_str(str(metadata[field]), kdek)

        for field in _ENCRYPTED_LIST_FIELDS:
            values = metadata.get(field)
            if isinstance(values, list):
                metadata[field] = [_encrypt_str(str(v), kdek) for v in values]

        for field in KEYED_FIELDS:
            if metadata.get(field) is not None:
                metadata[field] = hash_token(metadata[field], kdek)


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

                for field in _ENCRYPTED_TEXT_FIELDS:
                    if field in metadata:
                        metadata[field] = _decrypt_str(metadata[field], kdek)

                for field in _ENCRYPTED_LIST_FIELDS:
                    values = metadata.get(field)
                    if isinstance(values, list):
                        metadata[field] = [_decrypt_str(v, kdek) for v in values]
    return result


def redact_metadatas_for_log(metadatas):
    if not metadatas:
        return metadatas
    redacted = []
    for batch in metadatas:
        new_batch = []
        for metadata in batch:
            if isinstance(metadata, dict):
                metadata = {
                    key: ("<redacted>" if key in _ENCRYPTED_METADATA_FIELDS else value)
                    for key, value in metadata.items()
                }
            new_batch.append(metadata)
        redacted.append(new_batch)
    return redacted
