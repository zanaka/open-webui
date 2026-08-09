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

from open_webui.models.auths import Auths
from open_webui.models.resource_keys import ResourceKey, ResourceKeys
from open_webui.utils.crypto_context import require_cached_dek
from open_webui.utils.crypto_utils import (
    decrypt_value,
    generate_dek,
    rsa_unwrap_key,
    rsa_wrap_key,
)

log = logging.getLogger(__name__)


class SharingNotSupportedError(Exception):
    """The requested audience cannot be given keys."""


class ResourceKeyAccessError(Exception):
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
    public_key = Auths.get_public_key(user_id, db=session)
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
    wrapped_private_key = Auths.get_wrapped_private_key(user_id, db=db)
    if wrapped_private_key is None:
        raise RuntimeError(f"No wrapped private key for user {user_id}.")

    private_der = decrypt_value(wrapped_private_key, dek)
    return rsa_unwrap_key(wrapped_key, private_der)


def sync_shared_keys(
    resource_type: str,
    resource_id: str,
    owner_id: str,
    access_control: Optional[dict],
    key: Optional[bytes],
    session: Session,
) -> None:
    """Bring the stored key copies in line with who the resource is shared with."""
    wanted = named_recipients(access_control) - {owner_id}
    existing = {
        row.user_id
        for row in session.query(ResourceKey).filter_by(
            resource_type=resource_type, resource_id=resource_id
        )
    } - {owner_id}
    # Copies added earlier in this same flush are not in the table yet.
    existing |= {
        obj.user_id
        for obj in session.new
        if isinstance(obj, ResourceKey)
        and obj.resource_type == resource_type
        and obj.resource_id == resource_id
    } - {owner_id}

    added = wanted - existing
    removed = existing - wanted

    if (added or removed) and key is None:
        raise ResourceKeyAccessError(
            "Cannot change who this is shared with without holding its key."
        )

    for user_id in added:
        _add_key(session, resource_type, resource_id, user_id, key)

    for user_id in removed:
        session.query(ResourceKey).filter_by(
            resource_type=resource_type, resource_id=resource_id, user_id=user_id
        ).delete(synchronize_session=False)
