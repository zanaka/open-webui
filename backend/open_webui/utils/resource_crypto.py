"""Content keys for resources that can be shared with named people.

A shared resource carries its own key. That key is stored once per person who
may open it, wrapped with their public key, so sharing is handing out a wrapped
copy and unsharing is deleting one.

Sharing with a group, or with everyone, cannot be expressed this way: there is
no fixed set of public keys to wrap for, and future members would hold none. So
those are refused here rather than in each feature that offers sharing.
"""

import logging
import time
from typing import Optional

from sqlalchemy.orm import Session

from open_webui.crypto_exceptions import CryptoPolicyError
from open_webui.internal.db import get_db_context
from open_webui.models.auths import Auth
from open_webui.models.resource_keys import ResourceKey, ResourceKeys
from open_webui.utils.crypto_context import require_cached_dek
from open_webui.utils.crypto_utils import (
    decrypt_value,
    generate_dek,
    rsa_unwrap_key,
    rsa_wrap_key,
)

log = logging.getLogger(__name__)


class SharingNotSupportedError(CryptoPolicyError):
    """The requested audience cannot be given keys."""


class ResourceKeyAccessError(CryptoPolicyError):
    """The actor holds no key for this resource, so cannot pass one on."""


def validate_shareable_access_control(access_control: Optional[dict]) -> None:
    """Named recipients only.

    `None` means public in Open WebUI, and a group is a moving set of people;
    neither can be enumerated as public keys at the time of sharing.
    """
    if access_control is None:
        raise SharingNotSupportedError(
            "Sharing with everyone is not available: encrypted content is shared "
            "by handing a key to each named person."
        )

    for permission in ("read", "write"):
        if (access_control.get(permission) or {}).get("group_ids"):
            raise SharingNotSupportedError(
                "Sharing with a group is not available: encrypted content is "
                "shared by handing a key to each named person."
            )


def named_recipients(access_control: Optional[dict]) -> set:
    ids: set = set()
    if not access_control:
        return ids
    for permission in ("read", "write"):
        ids.update((access_control.get(permission) or {}).get("user_ids") or [])
    return ids


def _add_key(
    session: Session, resource_type: str, resource_id: str, user_id: str, key: bytes
) -> None:
    """Add a wrapped copy to the session; the caller's flush writes it."""
    # Queried on the caller's own sync session: this runs inside ORM event
    # hooks, where the async table APIs must not be entered.
    auth = session.query(Auth).filter_by(id=user_id).first()
    public_key = auth.public_key if auth else None
    if public_key is None:
        raise SharingNotSupportedError(
            f"User {user_id} has no public key to hand a copy of the key to."
        )

    session.add(
        ResourceKey(
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            wrapped_key=rsa_wrap_key(key, public_key),
            created_at=int(time.time()),
        )
    )


def create_owner_key(
    resource_type: str, resource_id: str, owner_id: str, session: Session
) -> bytes:
    key = generate_dek()
    _add_key(session, resource_type, resource_id, owner_id, key)
    return key


def resolve_key(
    resource_type: str, resource_id: str, user_id: str, db: Optional[Session] = None
) -> Optional[bytes]:
    wrapped_key = ResourceKeys.get_wrapped_key(
        resource_type, resource_id, user_id, db=db
    )
    if wrapped_key is None:
        return None

    dek = require_cached_dek(user_id)
    with get_db_context(db) as session:
        auth = session.query(Auth).filter_by(id=user_id).first()
        wrapped_private_key = auth.wrapped_private_key if auth else None
    if wrapped_private_key is None:
        raise RuntimeError(f"No wrapped private key for user {user_id}.")

    private_der = decrypt_value(wrapped_private_key, dek)
    return rsa_unwrap_key(wrapped_key, private_der)


