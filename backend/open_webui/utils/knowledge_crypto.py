from typing import Optional

from sqlalchemy.orm import Session

from open_webui.models.auths import Auths
from open_webui.models.knowledge import KnowledgeKeys
from open_webui.utils.crypto_context import require_cached_dek
from open_webui.utils.crypto_utils import (
    decrypt_value,
    generate_dek,
    rsa_unwrap_key,
    rsa_wrap_key,
)


class KdekAccessError(Exception):
    pass


def create_owner_kdek(
    knowledge_id: str, owner_id: str, db: Optional[Session] = None
) -> bytes:
    public_key = Auths.get_public_key(owner_id, db=db)
    if public_key is None:
        raise RuntimeError(f"No public key for user {owner_id}; cannot create KDEK.")

    kdek = generate_dek()
    wrapped_kdek = rsa_wrap_key(kdek, public_key)
    KnowledgeKeys.insert_new_key(knowledge_id, owner_id, wrapped_kdek, db=db)
    return kdek


def resolve_kdek(
    knowledge_id: str, user_id: str, db: Optional[Session] = None
) -> Optional[bytes]:
    wrapped_kdek = KnowledgeKeys.get_wrapped_kdek(knowledge_id, user_id, db=db)
    if wrapped_kdek is None:
        return None

    dek = require_cached_dek(user_id)
    wrapped_private_key = Auths.get_wrapped_private_key(user_id, db=db)
    if wrapped_private_key is None:
        raise RuntimeError(f"No wrapped private key for user {user_id}.")

    private_der = decrypt_value(wrapped_private_key, dek)
    return rsa_unwrap_key(wrapped_kdek, private_der)


def _member_ids(access_control: Optional[dict]) -> set:
    ids: set = set()
    if not access_control:
        return ids
    for permission in ("read", "write"):
        ids.update((access_control.get(permission) or {}).get("user_ids") or [])
    return ids


def sync_shared_keys(
    knowledge_id: str,
    owner_id: str,
    access_control: Optional[dict],
    kdek: Optional[bytes],
    db: Optional[Session] = None,
) -> None:
    target = _member_ids(access_control) - {owner_id}
    existing = set(KnowledgeKeys.get_user_ids(knowledge_id, db=db)) - {owner_id}

    added = target - existing
    removed = existing - target

    if (added or removed) and kdek is None:
        raise KdekAccessError(
            "Cannot change sharing without access to the knowledge key."
        )

    for user_id in added:
        public_key = Auths.get_public_key(user_id, db=db)
        if public_key is None:
            continue
        KnowledgeKeys.insert_new_key(
            knowledge_id, user_id, rsa_wrap_key(kdek, public_key), db=db
        )

    for user_id in removed:
        KnowledgeKeys.delete_key(knowledge_id, user_id, db=db)
