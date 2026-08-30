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
from typing import Optional

from sqlalchemy import event, inspect, select
from sqlalchemy import delete as sql_delete
from sqlalchemy.orm import Session, object_session

from open_webui.internal.db import Base
from open_webui.models.access_grants import (
    PRINCIPAL_TYPE_USER,
    WILDCARD_PRINCIPAL_ID,
    AccessGrant,
)
from open_webui.models.chat_messages import ChatMessage
from open_webui.models.chats import Chat
from open_webui.models.files import File
from open_webui.models.folders import Folder
from open_webui.models.knowledge import Knowledge
from open_webui.models.memories import Memory
from open_webui.models.notes import Note
from open_webui.models.prompt_history import PromptHistory
from open_webui.models.prompts import Prompt
from open_webui.models.resource_keys import ResourceKey
from open_webui.models.skills import Skill
from open_webui.models.tags import Tag
from open_webui.crypto_exceptions import EncryptedDataAccessDeniedError
from open_webui.utils.crypto_context import (
    get_current_user_id,
    require_current_user_dek,
)
from open_webui.utils.resource_crypto import (
    ResourceKeyAccessError,
    SharingNotSupportedError,
    _add_key,
    create_owner_key,
    resolve_key,
)
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
    """Whose key opens a row, and which of its columns are encrypted.

    `shared=True` means the row is opened by a key belonging to the resource
    itself rather than to its owner, so it can be handed to named people. Those
    rows are provisioned and re-shared automatically from their access_control;
    a feature offering sharing does not have to do anything, and cannot forget.
    """

    owner: str
    text: tuple[str, ...] = ()
    json: tuple[str, ...] = ()
    shared: bool = False
    # The column that names a row. Not every table calls it "id"; a prompt is
    # identified by the command a person types to reach it.
    identity: str = "id"

    @property
    def columns(self) -> tuple[str, ...]:
        return self.text + self.json


ENCRYPTED_MODELS: dict[type, EncryptionPolicy] = {
    # `tasks` and `summary` are upstream's chat auto-summary/task columns —
    # conversation content, so they travel with the chat body.
    Chat: EncryptionPolicy(
        owner="user_id", text=("title", "summary"), json=("chat", "tasks")
    ),
    # The normalized message store upstream reads chat content from. `usage`,
    # `role`, `model_id` and the tree columns stay clear: the admin usage
    # dashboard aggregates them across users, and branch queries walk them in
    # SQL — the same reasoning as File.hash. `context_summary` carries the
    # compaction checkpoint, i.e. a distillation of the conversation.
    ChatMessage: EncryptionPolicy(
        owner="user_id",
        text=("context_summary",),
        json=(
            "content",
            "output",
            "files",
            "sources",
            "embeds",
            "meta",
            "status_history",
            "error",
        ),
    ),
    # `hash` is deliberately absent: it never holds a plain SHA-256. The
    # fingerprint is keyed to its owner where it is computed (file_hash_token in
    # rag_crypto), because it must stay readable to people without the owner's
    # key — a member removing a file from a shared knowledge base, an
    # administrator deleting without reading — who pass it around opaquely.
    File: EncryptionPolicy(owner="user_id", text=("filename",), json=("data", "meta")),
    Memory: EncryptionPolicy(owner="user_id", text=("content",)),
    Folder: EncryptionPolicy(
        owner="user_id", text=("name",), json=("items", "meta", "data")
    ),
    Tag: EncryptionPolicy(owner="user_id", text=("name",), json=("meta",)),
    Knowledge: EncryptionPolicy(
        owner="user_id",
        text=("name", "description"),
        json=("meta",),
        shared=True,
    ),
    Note: EncryptionPolicy(
        owner="user_id",
        text=("title",),
        json=("data", "meta"),
        shared=True,
    ),
    # `command` stays in the clear: it is what a person types to find the row,
    # so it has to be matchable before the row — and therefore its key — is
    # known. Tag ids can be keyed tokens because a tag is opened with its
    # owner's key, which is in hand before the lookup; a shared prompt is not.
    Prompt: EncryptionPolicy(
        owner="user_id",
        text=("name", "content"),
        shared=True,
        identity="command",
    ),
    # A skill is instructions a person wrote, loaded only inside requests where
    # a signed-in user picked it — so unlike Tools and Functions it always has
    # a key in hand. The grants-scoped listing keeps rows the requester cannot
    # open out of every query, so a skill someone else attached to a model is
    # simply unavailable rather than an error, exactly like encrypted
    # knowledge attached to a model.
    Skill: EncryptionPolicy(
        owner="user_id",
        text=("name", "description", "content"),
        json=("meta",),
        shared=True,
    ),
    # A history entry duplicates its prompt's content, so it is opened with the
    # prompt's own key (see BORROWED_KEYS below): readable by exactly whoever
    # can read the prompt, and sharing follows the prompt's grants with nothing
    # extra stored or revoked.
    PromptHistory: EncryptionPolicy(
        owner="user_id",
        json=("snapshot",),
        shared=True,
    ),
}


def _prompt_history_key_of(session, target) -> tuple[str, Optional[str]]:
    row = (
        session.query(Prompt.command).filter(Prompt.id == target.prompt_id).first()
    )
    return ("Prompt", row[0] if row else None)


# Rows that duplicate another row's content are opened with that row's key
# rather than one of their own. Provisioning skips them: they never own key
# copies, so nothing is created on insert or cleaned up on delete.
BORROWED_KEYS: dict[type, "object"] = {
    PromptHistory: _prompt_history_key_of,
}


_RESOURCE_KEY_STASH = "_resource_key"


def _key_for(target, policy: EncryptionPolicy) -> bytes:
    """The key that opens this row."""
    borrowed = BORROWED_KEYS.get(type(target))
    if borrowed is not None:
        actor = get_current_user_id()
        if actor is None:
            raise RuntimeError("No current user context. Cannot access encrypted data.")
        session = object_session(target)
        resource_type, resource_id = borrowed(session, target)
        key = (
            resolve_key(resource_type, resource_id, actor, db=session)
            if resource_id is not None
            else None
        )
        if key is None:
            raise EncryptedDataAccessDeniedError(
                f"{actor} holds no key for the {resource_type} behind "
                f"{type(target).__name__} {getattr(target, policy.identity)}."
            )
        return key

    if not policy.shared:
        return require_current_user_dek(getattr(target, policy.owner))

    # Provisioned during before_flush for rows being written, so the key does not
    # have to be read back from a table that has not been written yet.
    stashed = getattr(target, _RESOURCE_KEY_STASH, None)
    if stashed is not None:
        return stashed

    actor = get_current_user_id()
    if actor is None:
        raise RuntimeError("No current user context. Cannot access encrypted data.")

    resource_id = getattr(target, policy.identity)
    # The row's own session is reused: this runs inside ORM events, where
    # opening a second connection would stall the async engine's event loop.
    key = resolve_key(
        type(target).__name__, resource_id, actor, db=object_session(target)
    )
    if key is None:
        raise EncryptedDataAccessDeniedError(
            f"{actor} holds no key for {type(target).__name__} {resource_id}."
        )
    return key


# Grant rows name resources by their lowercase API type and primary key; the
# key store names them by model class and policy identity. This table carries
# a grant to the shared encrypted model it concerns; grant types not listed
# (models, tools, ...) hold no encrypted content and pass through untouched.
GRANTED_SHARED_MODELS: dict[str, type] = {
    "knowledge": Knowledge,
    "note": Note,
    "prompt": Prompt,
    "skill": Skill,
}


def _grant_key_identity(session, model: type, resource_id: str) -> Optional[str]:
    """The key-store id for a granted resource.

    Grants carry the row's primary key, but a prompt's key is stored against
    its command (see the Prompt policy). Read as a column query so the row
    itself is not loaded — and therefore not decrypted — along the way.
    """
    policy = ENCRYPTED_MODELS[model]
    if policy.identity == "id":
        return resource_id
    row = (
        session.query(getattr(model, policy.identity))
        .filter(model.id == resource_id)
        .first()
    )
    return row[0] if row else None


def _validate_grant(grant) -> None:
    """Named people only; a group, everyone, or a wildcard cannot be keyed."""
    if grant.principal_type != PRINCIPAL_TYPE_USER or (
        grant.principal_id == WILDCARD_PRINCIPAL_ID
    ):
        raise SharingNotSupportedError(
            "Sharing with a group or with everyone is not available: encrypted "
            "content is shared by handing a key to each named person."
        )


def _sync_granted_keys(session) -> None:
    """Bring the stored key copies in line with the access grants being written.

    set_access_grants replaces a resource's grants wholesale — it deletes the
    old rows and adds the full new set through the ORM — so the flush shows
    every change here: the wanted audience is the surviving grant rows plus
    the pending ones.
    """
    touched: dict[tuple[str, str], type] = {}
    for grant in list(session.new) + list(session.deleted):
        if isinstance(grant, AccessGrant):
            model = GRANTED_SHARED_MODELS.get(grant.resource_type)
            if model is not None:
                touched[(grant.resource_type, grant.resource_id)] = model

    for (grant_type, grant_resource_id), model in touched.items():
        new_grants = [
            g
            for g in session.new
            if isinstance(g, AccessGrant)
            and g.resource_type == grant_type
            and g.resource_id == grant_resource_id
        ]
        for grant in new_grants:
            _validate_grant(grant)

        deleted_ids = {
            g.id
            for g in session.deleted
            if isinstance(g, AccessGrant)
            and g.resource_type == grant_type
            and g.resource_id == grant_resource_id
        }
        surviving = [
            g
            for g in session.query(AccessGrant).filter_by(
                resource_type=grant_type, resource_id=grant_resource_id
            )
            if g.id not in deleted_ids
        ]

        wanted = {g.principal_id for g in surviving + new_grants}

        resource_type = model.__name__
        resource_id = _grant_key_identity(session, model, grant_resource_id)
        if resource_id is None:
            # The resource is gone; its keys go with it below, or are already gone.
            continue

        key_rows = {
            row.user_id: row
            for row in session.query(ResourceKey).filter_by(
                resource_type=resource_type, resource_id=resource_id
            )
        }
        owner_row = (
            session.query(getattr(model, ENCRYPTED_MODELS[model].owner))
            .filter(model.id == grant_resource_id)
            .first()
        )
        owner_id = owner_row[0] if owner_row else None

        added = wanted - set(key_rows) - {owner_id}
        removed = set(key_rows) - wanted - {owner_id}

        if added:
            actor = get_current_user_id()
            key = (
                resolve_key(resource_type, resource_id, actor, db=session)
                if actor
                else None
            )
            if key is None:
                raise ResourceKeyAccessError(
                    "Cannot change who this is shared with without holding its key."
                )
            for user_id in added:
                _add_key(session, resource_type, resource_id, user_id, key)

        for user_id in removed:
            session.delete(key_rows[user_id])


def _provision_resource_keys(session, flush_context, instances) -> None:
    """Give shared rows a key, and keep the shared copies in step.

    Runs before the flush, which is the only point where new rows may be added
    to it. A feature that writes access grants gets the key handling for free —
    or a refusal, if it asks for an audience that cannot be keyed.
    """
    written = list(session.new) + [
        obj for obj in session.dirty if session.is_modified(obj)
    ]

    for target in written:
        policy = ENCRYPTED_MODELS.get(type(target))
        if policy is None or not policy.shared or type(target) in BORROWED_KEYS:
            continue

        resource_type = type(target).__name__
        resource_id = getattr(target, policy.identity)
        owner_id = getattr(target, policy.owner)

        if target in session.new:
            key = create_owner_key(resource_type, resource_id, owner_id, session)
        else:
            # A renamed identity (a prompt's command can be edited) must carry
            # the stored key copies along, or the row becomes undecryptable.
            history = inspect(target).attrs[policy.identity].history
            if history.has_changes() and history.deleted:
                session.query(ResourceKey).filter_by(
                    resource_type=resource_type, resource_id=history.deleted[0]
                ).update(
                    {ResourceKey.resource_id: resource_id},
                    synchronize_session=False,
                )

            actor = get_current_user_id()
            key = (
                resolve_key(resource_type, resource_id, actor, db=session)
                if actor
                else None
            )

        setattr(target, _RESOURCE_KEY_STASH, key)

    _sync_granted_keys(session)

    # A deleted resource takes its key copies with it, or the wrapped keys of
    # content that no longer exists would be left behind.
    for target in session.deleted:
        policy = ENCRYPTED_MODELS.get(type(target))
        if policy is None or not policy.shared or type(target) in BORROWED_KEYS:
            continue
        session.query(ResourceKey).filter_by(
            resource_type=type(target).__name__,
            resource_id=getattr(target, policy.identity),
        ).delete(synchronize_session=False)


def named_recipient_resources() -> list[str]:
    """The resources that can only be shared with people named one by one.

    Handed to the interface so it can offer the audiences that will actually
    work. Read off the registry rather than written out again, so encrypting a
    new model changes what is offered without anyone remembering to.
    """
    return sorted(
        model.__name__ for model, policy in ENCRYPTED_MODELS.items() if policy.shared
    )


def _identity_column(model: type):
    policy = ENCRYPTED_MODELS.get(model)
    return getattr(model, policy.identity if policy else "id")


def read_without_decrypting(session, model: type, id: str, *columns: str):
    """Read columns that carry no user content, leaving the row encrypted.

    Ownership and access_control say who a row belongs to and who may reach it,
    never what it says, so they can be read by someone holding no key. Asking
    for an encrypted column here is refused rather than quietly handed back as
    ciphertext.
    """
    policy = ENCRYPTED_MODELS.get(model)
    if policy is not None:
        encrypted = set(columns) & set(policy.columns)
        if encrypted:
            raise ValueError(
                f"{', '.join(sorted(encrypted))} on {model.__name__} is encrypted. "
                "Load the row itself, with the key, to read it."
            )

    return (
        session.query(*[getattr(model, column) for column in columns])
        .filter(_identity_column(model) == id)
        .first()
    )


def delete_without_reading(session, model: type, ids: list[str]) -> None:
    """Remove rows without loading them, and take their key copies with them.

    Deleting does not need to know what a row says, so it must not need the key
    either — an administrator can clear out someone's data without being able
    to open it. Loading the row would decrypt it, so this deletes by statement
    and cleans up the wrapped keys itself instead of relying on the flush hook.
    """
    if not ids:
        return

    policy = ENCRYPTED_MODELS.get(model)
    if policy is not None and policy.shared:
        session.query(ResourceKey).filter(
            ResourceKey.resource_type == model.__name__,
            ResourceKey.resource_id.in_(ids),
        ).delete(synchronize_session=False)

    session.query(model).filter(_identity_column(model).in_(ids)).delete(
        synchronize_session=False
    )


async def read_without_decrypting_async(session, model: type, id: str, *columns: str):
    """read_without_decrypting for the async table APIs."""
    policy = ENCRYPTED_MODELS.get(model)
    if policy is not None:
        encrypted = set(columns) & set(policy.columns)
        if encrypted:
            raise ValueError(
                f"{', '.join(sorted(encrypted))} on {model.__name__} is encrypted. "
                "Load the row itself, with the key, to read it."
            )

    result = await session.execute(
        select(*[getattr(model, column) for column in columns]).where(
            _identity_column(model) == id
        )
    )
    return result.first()


async def delete_without_reading_async(session, model: type, ids: list[str]) -> None:
    """delete_without_reading for the async table APIs."""
    if not ids:
        return

    policy = ENCRYPTED_MODELS.get(model)
    if policy is not None and policy.shared:
        await session.execute(
            sql_delete(ResourceKey).where(
                ResourceKey.resource_type == model.__name__,
                ResourceKey.resource_id.in_(ids),
            )
        )

    await session.execute(
        sql_delete(model).where(_identity_column(model).in_(ids))
    )


def _encrypt(target, policy: EncryptionPolicy) -> None:
    dek = _key_for(target, policy)

    # Kept so the caller's own object still reads as plaintext after the flush.
    stash = {column: getattr(target, column) for column in policy.columns}
    setattr(target, _PLAINTEXT_STASH, stash)

    for column in policy.text:
        setattr(target, column, encrypt_text(stash[column], dek))
    for column in policy.json:
        setattr(target, column, encrypt_json_value(stash[column], dek))


def _decrypt(target, policy: EncryptionPolicy) -> None:
    dek = _key_for(target, policy)

    for column in policy.text:
        setattr(target, column, decrypt_text(getattr(target, column), dek))
    for column in policy.json:
        setattr(target, column, decrypt_json_value(getattr(target, column), dek))


def _restore_plaintext(target) -> None:
    # The key was only stashed to carry it from before_flush to the encrypt
    # step; keeping it would let whoever loads this object next borrow it.
    if hasattr(target, _RESOURCE_KEY_STASH):
        delattr(target, _RESOURCE_KEY_STASH)

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
    "ResourceKey": "holds content keys already wrapped with each member's public key",
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
    # Response rating is closed here rather than encrypted: the leaderboard has
    # to read every user's rating to score a model, which no per-user key can
    # open, while the same row's snapshot holds the conversation itself and so
    # cannot be left readable. Every endpoint returns 501 (see
    # routers/evaluations.py), so this table stays empty. Reopening it means
    # deciding which parts of a feedback row may be read across users.
    "Feedback": "response rating is closed; the leaderboard reads every user's ratings",
    # The channel feature is closed here rather than encrypted: a channel has
    # many readers, a public one has no bounded member set, and its inbound
    # webhook writes messages with no user at all, so no per-user key can cover
    # it. Every endpoint returns 501 (see routers/channels.py), so these tables
    # stay empty. Reopening channels means building a per-channel key first.
    "Channel": "channels are closed; a channel key would be needed, not a user key",
    "ChannelMember": "channels are closed; membership rows only",
    "ChannelWebhook": "channels are closed; the token is compared by value anyway",
    "Message": "channels are closed; messages have many readers and no single owner",
    "MessageReaction": "channels are closed; emoji names",
    # Models new in upstream v0.11.1, provisionally exempted so the merged app
    # can boot. TODO(phase3): each gets its final decision — encrypt what holds
    # user content (ChatMessage, Skill, PromptHistory, Calendar*), close what
    # cannot be keyed (Automation runs headless with no DEK; SharedChat stores
    # a plaintext snapshot of a chat).
    "AccessGrant": "TODO(phase3): rows of ids and permissions only",
    "Automation": "TODO(phase3): to be closed; scheduled runs execute with no DEK in cache",
    "AutomationRun": "TODO(phase3): to be closed with Automation",
    "Calendar": "TODO(phase3): to be encrypted with the owner's key",
    "CalendarEvent": "TODO(phase3): to be encrypted with the owner's key",
    "CalendarEventAttendee": "TODO(phase3): decide with Calendar; attendee rows",
    "KnowledgeDirectory": "TODO(phase3): inspect columns, then encrypt or exempt",
    "PinnedNote": "TODO(phase3): join table of ids",
    "SharedChat": "TODO(phase3): to be closed; plaintext chat snapshots for sharing",
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

    event.listen(Session, "before_flush", _provision_resource_keys)
    for model, policy in ENCRYPTED_MODELS.items():
        _register(model, policy)
    log.info(
        "Column encryption installed for: %s",
        ", ".join(model.__name__ for model in ENCRYPTED_MODELS),
    )
