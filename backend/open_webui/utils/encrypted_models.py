"""Which model columns are encrypted at rest, and the hooks that do it.

One declarative table rather than a hand-written hook module per model. Adding a
model is a line in ENCRYPTED_MODELS; leaving one out is caught at startup by
assert_models_are_covered(), so a model carrying user content cannot quietly
join the schema in the clear.

Every model is keyed by its owner's DEK and access is refused unless the owner
is the user making the request.
"""

import logging
from dataclasses import dataclass

from sqlalchemy import event

from open_webui.internal.db import Base
from open_webui.models.chats import Chat
from open_webui.models.files import File
from open_webui.models.folders import Folder
from open_webui.models.memories import Memory
from open_webui.utils.crypto_context import require_current_user_dek
from open_webui.utils.crypto_utils import (
    decrypt_json_value,
    decrypt_text,
    encrypt_json_value,
    encrypt_text,
)

log = logging.getLogger(__name__)

_PLAINTEXT_STASH = "_plaintext_before_encrypt"


@dataclass(frozen=True)
class EncryptionPolicy:
    """Whose key opens a row, and which of its columns are encrypted."""

    owner: str
    text: tuple[str, ...] = ()
    json: tuple[str, ...] = ()

    @property
    def columns(self) -> tuple[str, ...]:
        return self.text + self.json


ENCRYPTED_MODELS: dict[type, EncryptionPolicy] = {
    Chat: EncryptionPolicy(owner="user_id", text=("title",), json=("chat",)),
    File: EncryptionPolicy(owner="user_id", text=("filename",), json=("data", "meta")),
    Memory: EncryptionPolicy(owner="user_id", text=("content",)),
    Folder: EncryptionPolicy(
        owner="user_id", text=("name",), json=("items", "meta", "data")
    ),
}


def _encrypt(target, policy: EncryptionPolicy) -> None:
    dek = require_current_user_dek(getattr(target, policy.owner))

    # Kept so the caller's own object still reads as plaintext after the flush.
    stash = {column: getattr(target, column) for column in policy.columns}
    setattr(target, _PLAINTEXT_STASH, stash)

    for column in policy.text:
        setattr(target, column, encrypt_text(stash[column], dek))
    for column in policy.json:
        setattr(target, column, encrypt_json_value(stash[column], dek))


def _decrypt(target, policy: EncryptionPolicy) -> None:
    dek = require_current_user_dek(getattr(target, policy.owner))

    for column in policy.text:
        setattr(target, column, decrypt_text(getattr(target, column), dek))
    for column in policy.json:
        setattr(target, column, decrypt_json_value(getattr(target, column), dek))


def _restore_plaintext(target) -> None:
    stash = getattr(target, _PLAINTEXT_STASH, None)
    if stash is None:
        return
    for column, value in stash.items():
        setattr(target, column, value)
    delattr(target, _PLAINTEXT_STASH)


def _register(model: type, policy: EncryptionPolicy) -> None:
    @event.listens_for(model, "before_insert")
    def _before_insert(mapper, connection, target):
        _encrypt(target, policy)

    @event.listens_for(model, "after_insert")
    def _after_insert(mapper, connection, target):
        _restore_plaintext(target)

    @event.listens_for(model, "before_update")
    def _before_update(mapper, connection, target):
        _encrypt(target, policy)

    @event.listens_for(model, "after_update")
    def _after_update(mapper, connection, target):
        _restore_plaintext(target)

    @event.listens_for(model, "load")
    def _on_load(target, context):
        _decrypt(target, policy)

    @event.listens_for(model, "refresh")
    def _on_refresh(target, context, attrs):
        if attrs is None or any(column in attrs for column in policy.columns):
            _decrypt(target, policy)


# Every mapped model must appear either in ENCRYPTED_MODELS above or here, with
# the reason it is not encrypted. A model in neither list stops the app at
# startup, so a new table carrying user content cannot slip in unnoticed.
#
# Keyed by class name rather than the class itself: this module is imported
# before most model modules are, and a name that no longer matches leaves the
# model unclassified, which is the safe direction.
NOT_ENCRYPTED: dict[str, str] = {
    # Key material and credentials. Encrypting these is circular or breaks the
    # lookup that authentication itself depends on.
    "Auth": "holds the KDF salt and wrapped DEK that everything else is unlocked with",
    "KnowledgeKey": "holds KDEKs already wrapped with the member's public key",
    "ApiKey": "the key is looked up by value to authenticate the request",
    "OAuthSession": "the token column is already encrypted with the server key",
    "User": "email and name are looked up at sign-in and shown to admins",
    # Rows of identifiers only; no user content to protect.
    "ChatFile": "join table of ids",
    "ChannelFile": "join table of ids",
    "KnowledgeFile": "join table of ids",
    "GroupMember": "join table of ids",
    # Instance-wide configuration, not owned by any user.
    "Config": "instance configuration, not user content",
    # Administrator-authored workspace objects. Visible to their audience by
    # design, and their content is code or configuration rather than user data.
    "Group": "administrator-managed membership, queried across users",
    "Function": "administrator-authored code, loaded at startup before any login",
    "Tool": "administrator-authored code, loaded without a user context",
    "Model": "workspace model definitions, resolved before a user is known",
    # Known gaps: user content that is still stored in the clear. Each needs its
    # query paths rewritten before it can be encrypted, so they are listed here
    # deliberately rather than left to be discovered.
    "Note": "TODO: user content; search filters on the data JSON in SQL",
    "Feedback": "TODO: user content; snapshot embeds the conversation",
    "Prompt": "TODO: user content; looked up by command",
    "Tag": "TODO: user content; tags are matched in SQL during chat search",
    "Knowledge": "TODO: name and description; searched in SQL and shared across users",
    "Channel": "TODO: user content; channels are disabled in this deployment",
    "ChannelMember": "TODO: user content; channels are disabled in this deployment",
    "ChannelWebhook": "TODO: holds a bearer token; channels are disabled here",
    "Message": "TODO: user content; channels are disabled in this deployment",
    "MessageReaction": "TODO: emoji names; channels are disabled in this deployment",
}


class UnclassifiedModelError(RuntimeError):
    """A mapped model is neither encrypted nor listed as deliberately not."""


def assert_models_are_covered() -> None:
    """Refuse to start if any model has escaped classification.

    Call once every model module has been imported.
    """
    unclassified = sorted(
        mapper.class_.__name__
        for mapper in Base.registry.mappers
        if mapper.class_ not in ENCRYPTED_MODELS
        and mapper.class_.__name__ not in NOT_ENCRYPTED
    )
    if unclassified:
        raise UnclassifiedModelError(
            "These models are neither encrypted nor listed in NOT_ENCRYPTED: "
            f"{', '.join(unclassified)}. Add them to one of the two in "
            "open_webui/utils/encrypted_models.py."
        )

    log.info(
        "Model encryption coverage checked: %d encrypted, %d deliberately not.",
        len(ENCRYPTED_MODELS),
        len(NOT_ENCRYPTED),
    )


_installed = False


def install() -> None:
    """Attach the hooks. Safe to call more than once; listeners register once."""
    global _installed
    if _installed:
        return
    _installed = True

    for model, policy in ENCRYPTED_MODELS.items():
        _register(model, policy)
    log.info(
        "Column encryption installed for: %s",
        ", ".join(model.__name__ for model in ENCRYPTED_MODELS),
    )
