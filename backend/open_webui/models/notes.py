import json
import time
import uuid
from typing import Optional
from functools import lru_cache

from sqlalchemy.orm import Session
from open_webui.internal.db import Base, get_db, get_db_context
from open_webui.models.groups import Groups
from open_webui.utils.access_control import has_access
from open_webui.utils.db.access_control import has_permission
from open_webui.models.users import User, UserModel, Users, UserResponse


from pydantic import BaseModel, ConfigDict
from sqlalchemy import BigInteger, Boolean, Column, String, Text, JSON
from sqlalchemy.dialects.postgresql import JSONB


from sqlalchemy import or_, func, select, and_, text, cast, or_, and_, func
from sqlalchemy.sql import exists

####################
# Note DB Schema
####################


class Note(Base):
    __tablename__ = "note"

    id = Column(Text, primary_key=True, unique=True)
    user_id = Column(Text)

    title = Column(Text)
    data = Column(JSON, nullable=True)
    meta = Column(JSON, nullable=True)

    access_control = Column(JSON, nullable=True)

    created_at = Column(BigInteger)
    updated_at = Column(BigInteger)


class NoteModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str

    title: str
    data: Optional[dict] = None
    meta: Optional[dict] = None

    access_control: Optional[dict] = None

    created_at: int  # timestamp in epoch
    updated_at: int  # timestamp in epoch


####################
# Forms
####################


class NoteForm(BaseModel):
    title: str
    data: Optional[dict] = None
    meta: Optional[dict] = None
    access_control: Optional[dict] = None


class NoteUpdateForm(BaseModel):
    title: Optional[str] = None
    data: Optional[dict] = None
    meta: Optional[dict] = None
    access_control: Optional[dict] = None


class NoteUserResponse(NoteModel):
    user: Optional[UserResponse] = None


class NoteItemResponse(BaseModel):
    id: str
    title: str
    data: Optional[dict]
    updated_at: int
    created_at: int
    user: Optional[UserResponse] = None


class NoteListResponse(BaseModel):
    items: list[NoteUserResponse]
    total: int


class NoteTable:
    def insert_new_note(
        self, user_id: str, form_data: NoteForm, db: Optional[Session] = None
    ) -> Optional[NoteModel]:
        with get_db_context(db) as db:
            note = NoteModel(
                **{
                    "id": str(uuid.uuid4()),
                    "user_id": user_id,
                    **form_data.model_dump(),
                    "created_at": int(time.time_ns()),
                    "updated_at": int(time.time_ns()),
                }
            )

            new_note = Note(**note.model_dump())

            db.add(new_note)
            db.commit()
            return note

    @staticmethod
    def _normalize(value: Optional[str]) -> str:
        """Hyphens and spaces removed, so "todo" matches "to-do" and "to do"."""
        return (value or "").replace("-", "").replace(" ", "").lower()

    def search_notes(
        self,
        user_id: str,
        filter: dict = {},
        skip: int = 0,
        limit: int = 30,
        db: Optional[Session] = None,
    ) -> NoteListResponse:
        with get_db_context(db) as db:
            query = db.query(Note, User).outerjoin(User, User.id == Note.user_id)

            query_key = None
            order_by = None
            direction = None

            if filter:
                query_key = filter.get("query")

                view_option = filter.get("view_option")
                if view_option == "created":
                    query = query.filter(Note.user_id == user_id)
                elif view_option == "shared":
                    query = query.filter(Note.user_id != user_id)

                query = has_permission(
                    db, Note, query, filter, filter.get("permission", "write")
                )

                order_by = filter.get("order_by")
                direction = filter.get("direction")

            if order_by == "created_at":
                query = query.order_by(
                    Note.created_at.asc() if direction == "asc" else Note.created_at.desc()
                )
            elif order_by == "updated_at":
                query = query.order_by(
                    Note.updated_at.asc() if direction == "asc" else Note.updated_at.desc()
                )
            else:
                query = query.order_by(Note.updated_at.desc())

            items = query.all()

            if query_key:
                # The title and the note body are matched after they are read,
                # because they are encrypted at rest.
                needle = self._normalize(query_key)
                items = [
                    (note, user)
                    for note, user in items
                    if needle in self._normalize(note.title)
                    or needle
                    in self._normalize(
                        ((note.data or {}).get("content") or {}).get("md")
                    )
                ]

            if order_by == "name":
                items = sorted(
                    items,
                    key=lambda item: (item[0].title or "").lower(),
                    reverse=direction != "asc",
                )

            # Counted after filtering, so the total matches what is returned.
            total = len(items)

            if skip:
                items = items[skip:]
            if limit:
                items = items[:limit]

            notes = []
            for note, user in items:
                notes.append(
                    NoteUserResponse(
                        **NoteModel.model_validate(note).model_dump(),
                        user=(
                            UserResponse(**UserModel.model_validate(user).model_dump())
                            if user
                            else None
                        ),
                    )
                )

            return NoteListResponse(items=notes, total=total)

    def get_notes_by_user_id(
        self,
        user_id: str,
        permission: str = "read",
        skip: int = 0,
        limit: int = 50,
        db: Optional[Session] = None,
    ) -> list[NoteModel]:
        with get_db_context(db) as db:
            user_group_ids = [
                group.id for group in Groups.get_groups_by_member_id(user_id, db=db)
            ]

            query = db.query(Note).order_by(Note.updated_at.desc())
            query = has_permission(
                db,
                Note,
                query,
                {"user_id": user_id, "group_ids": user_group_ids},
                permission,
            )

            if skip is not None:
                query = query.offset(skip)
            if limit is not None:
                query = query.limit(limit)

            notes = query.all()
            return [NoteModel.model_validate(note) for note in notes]

    def get_note_by_id(
        self, id: str, db: Optional[Session] = None
    ) -> Optional[NoteModel]:
        with get_db_context(db) as db:
            note = db.query(Note).filter(Note.id == id).first()
            return NoteModel.model_validate(note) if note else None

    def update_note_by_id(
        self, id: str, form_data: NoteUpdateForm, db: Optional[Session] = None
    ) -> Optional[NoteModel]:
        with get_db_context(db) as db:
            note = db.query(Note).filter(Note.id == id).first()
            if not note:
                return None

            form_data = form_data.model_dump(exclude_unset=True)

            if "title" in form_data:
                note.title = form_data["title"]
            if "data" in form_data:
                note.data = {**note.data, **form_data["data"]}
            if "meta" in form_data:
                note.meta = {**note.meta, **form_data["meta"]}

            if "access_control" in form_data:
                note.access_control = form_data["access_control"]

            note.updated_at = int(time.time_ns())

            db.commit()
            return NoteModel.model_validate(note) if note else None

    def delete_note_by_id(self, id: str, db: Optional[Session] = None) -> bool:
        # Deleting does not need the contents, so it must not need the key. See
        # Knowledges.delete_knowledge_by_id for why the import is not at the top.
        from open_webui.utils.encrypted_models import delete_without_reading

        try:
            with get_db_context(db) as db:
                delete_without_reading(db, Note, [id])
                db.commit()
                return True
        except Exception:
            return False


Notes = NoteTable()
