"""Keys for vector collections.

The vector store never works out which key protects a collection; every caller
hands one in. These are the only two ways to get one, and both raise instead of
returning None, so a caller cannot end up storing or reading vector data with no
key in hand.
"""

import logging
from typing import Optional

from sqlalchemy.orm import Session

from open_webui.utils.crypto_context import get_cached_dek
from open_webui.utils.resource_crypto import resolve_key

log = logging.getLogger(__name__)


class VectorKeyError(Exception):
    """No usable key, so the vector data must not be written or read."""


def owner_key(user_id: Optional[str]) -> bytes:
    """Key for a collection that holds one user's own data."""
    if not user_id:
        raise VectorKeyError("No user to key vector data with.")

    dek = get_cached_dek(user_id)
    if dek is None:
        raise VectorKeyError(f"No DEK cached for user {user_id}. User must re-login.")
    return dek


def knowledge_key(
    knowledge_id: str, user_id: Optional[str], db: Optional[Session] = None
) -> bytes:
    """Key for a knowledge base, held by everyone it is shared with.

    The same content key that protects the knowledge row's own columns, so a
    knowledge base and its vectors are opened by one key, not two.
    """
    if not knowledge_id:
        raise VectorKeyError("No knowledge base to key vector data with.")
    if not user_id:
        raise VectorKeyError(
            f"No user to unwrap the key of knowledge base {knowledge_id} with."
        )

    key = resolve_key("Knowledge", knowledge_id, user_id, db=db)
    if key is None:
        raise VectorKeyError(
            f"User {user_id} holds no key for knowledge base {knowledge_id}."
        )
    return key
