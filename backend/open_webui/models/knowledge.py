import json
import logging
import time
from typing import Optional
import uuid

from sqlalchemy.orm import Session
from open_webui.internal.db import Base, JSONField, get_db, get_db_context

from open_webui.models.files import (
    File,
    FileModel,
    FileMetadataResponse,
    FileModelResponse,
)
from open_webui.models.groups import Groups
from open_webui.models.users import User, UserModel, Users, UserResponse


from pydantic import BaseModel, ConfigDict
from sqlalchemy import (
    BigInteger,
    Column,
    ForeignKey,
    String,
    Text,
    JSON,
    UniqueConstraint,
    or_,
)

from open_webui.crypto_exceptions import CryptoPolicyError
from open_webui.utils.access_control import has_access
from open_webui.utils.db.access_control import has_permission


log = logging.getLogger(__name__)

####################
# Knowledge DB Schema
####################


class Knowledge(Base):
    __tablename__ = "knowledge"

    id = Column(Text, unique=True, primary_key=True)
    user_id = Column(Text)

    name = Column(Text)
    description = Column(Text)

    meta = Column(JSON, nullable=True)
    access_control = Column(JSON, nullable=True)  # Controls data access levels.
    # Defines access control rules for this entry.
    # - `None`: Public access, available to all users with the "user" role.
    # - `{}`: Private access, restricted exclusively to the owner.
    # - Custom permissions: Specific access control for reading and writing;
    #   Can specify group or user-level restrictions:
    #   {
    #      "read": {
    #          "group_ids": ["group_id1", "group_id2"],
    #          "user_ids":  ["user_id1", "user_id2"]
    #      },
    #      "write": {
    #          "group_ids": ["group_id1", "group_id2"],
    #          "user_ids":  ["user_id1", "user_id2"]
    #      }
    #   }

    created_at = Column(BigInteger)
    updated_at = Column(BigInteger)


class KnowledgeModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str

    name: str
    description: str

    meta: Optional[dict] = None

    access_control: Optional[dict] = None

    created_at: int  # timestamp in epoch
    updated_at: int  # timestamp in epoch


class KnowledgeFile(Base):
    __tablename__ = "knowledge_file"

    id = Column(Text, unique=True, primary_key=True)

    knowledge_id = Column(
        Text, ForeignKey("knowledge.id", ondelete="CASCADE"), nullable=False
    )
    file_id = Column(Text, ForeignKey("file.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Text, nullable=False)

    created_at = Column(BigInteger, nullable=False)
    updated_at = Column(BigInteger, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "knowledge_id", "file_id", name="uq_knowledge_file_knowledge_file"
        ),
    )


class KnowledgeFileModel(BaseModel):
    id: str
    knowledge_id: str
    file_id: str
    user_id: str

    created_at: int  # timestamp in epoch
    updated_at: int  # timestamp in epoch

    model_config = ConfigDict(from_attributes=True)


####################
# Forms
####################
class KnowledgeUserModel(KnowledgeModel):
    user: Optional[UserResponse] = None


class KnowledgeResponse(KnowledgeModel):
    files: Optional[list[FileMetadataResponse | dict]] = None


class KnowledgeUserResponse(KnowledgeUserModel):
    pass


class KnowledgeForm(BaseModel):
    name: str
    description: str
    access_control: Optional[dict] = None


class FileUserResponse(FileModelResponse):
    user: Optional[UserResponse] = None


class KnowledgeListResponse(BaseModel):
    items: list[KnowledgeUserModel]
    total: int


class KnowledgeFileListResponse(BaseModel):
    items: list[FileUserResponse]
    total: int


class KnowledgeTable:
    def insert_new_knowledge(
        self, user_id: str, form_data: KnowledgeForm, db: Optional[Session] = None
    ) -> Optional[KnowledgeModel]:
        with get_db_context(db) as db:
            knowledge = KnowledgeModel(
                **{
                    **form_data.model_dump(),
                    "id": str(uuid.uuid4()),
                    "user_id": user_id,
                    "created_at": int(time.time()),
                    "updated_at": int(time.time()),
                }
            )

            try:
                result = Knowledge(**knowledge.model_dump())
                db.add(result)
                db.commit()
                db.refresh(result)
                if result:
                    return KnowledgeModel.model_validate(result)
                else:
                    return None
            except CryptoPolicyError:
                # A refused audience is an answer for the caller, not a failure
                # to write, so it must not be flattened into None here.
                raise
            except Exception:
                return None

    def search_knowledge_bases(
        self,
        user_id: str,
        filter: dict,
        skip: int = 0,
        limit: int = 30,
        db: Optional[Session] = None,
    ) -> KnowledgeListResponse:
        try:
            with get_db_context(db) as db:
                query = db.query(Knowledge, User).outerjoin(
                    User, User.id == Knowledge.user_id
                )

                query_key = None
                if filter:
                    query_key = filter.get("query")

                    view_option = filter.get("view_option")
                    if view_option == "created":
                        query = query.filter(Knowledge.user_id == user_id)
                    elif view_option == "shared":
                        query = query.filter(Knowledge.user_id != user_id)

                    query = has_permission(db, Knowledge, query, filter)

                query = query.order_by(Knowledge.updated_at.desc())

                items = query.all()

                if query_key:
                    # name and description are matched after they are read, so
                    # that this keeps working once they are encrypted at rest.
                    needle = query_key.lower()
                    items = [
                        (knowledge_base, user)
                        for knowledge_base, user in items
                        if needle in (knowledge_base.name or "").lower()
                        or needle in (knowledge_base.description or "").lower()
                    ]

                total = len(items)
                if skip:
                    items = items[skip:]
                if limit:
                    items = items[:limit]

                knowledge_bases = []
                for knowledge_base, user in items:
                    knowledge_bases.append(
                        KnowledgeUserModel.model_validate(
                            {
                                **KnowledgeModel.model_validate(
                                    knowledge_base
                                ).model_dump(),
                                "user": (
                                    UserModel.model_validate(user).model_dump()
                                    if user
                                    else None
                                ),
                            }
                        )
                    )

                return KnowledgeListResponse(items=knowledge_bases, total=total)
        except Exception as e:
            print(e)
            return KnowledgeListResponse(items=[], total=0)

    def search_knowledge_files(
        self, filter: dict, skip: int = 0, limit: int = 30, db: Optional[Session] = None
    ) -> KnowledgeFileListResponse:
        """
        Scalable version: search files across all knowledge bases the user has
        READ access to, without loading all KBs or using large IN() lists.
        """
        try:
            with get_db_context(db) as db:
                # Base query: join Knowledge → KnowledgeFile → File
                query = (
                    db.query(File, User, Knowledge)
                    .join(KnowledgeFile, File.id == KnowledgeFile.file_id)
                    .join(Knowledge, KnowledgeFile.knowledge_id == Knowledge.id)
                    .outerjoin(User, User.id == KnowledgeFile.user_id)
                )

                # Apply access-control directly to the joined query
                # This makes the database handle filtering, even with 10k+ KBs
                query = has_permission(db, Knowledge, query, filter)

                # Order by file changes
                query = query.order_by(File.updated_at.desc())

                rows = query.all()
                if filter:
                    q = filter.get("query")
                    if q:
                        query_key = q.lower()
                        filtered_rows = []
                        for file, user, knowledge in rows:
                            filename = (file.filename or "").lower()
                            if query_key in filename:
                                filtered_rows.append((file, user, knowledge))
                        rows = filtered_rows

                # Count before pagination
                total = len(rows)

                if skip:
                    rows = rows[skip:]
                if limit:
                    rows = rows[:limit]

                items = []
                for file, user, knowledge in rows:
                    items.append(
                        FileUserResponse(
                            **FileModel.model_validate(file).model_dump(),
                            user=(
                                UserResponse(
                                    **UserModel.model_validate(user).model_dump()
                                )
                                if user
                                else None
                            ),
                            collection=KnowledgeModel.model_validate(
                                knowledge
                            ).model_dump(),
                        )
                    )

                return KnowledgeFileListResponse(items=items, total=total)

        except Exception as e:
            print("search_knowledge_files error:", e)
            return KnowledgeFileListResponse(items=[], total=0)

    def check_access_by_user_id(
        self, id, user_id, permission="write", db: Optional[Session] = None
    ) -> bool:
        knowledge = self.get_knowledge_by_id(id, db=db)
        if not knowledge:
            return False
        if knowledge.user_id == user_id:
            return True
        user_group_ids = {
            group.id for group in Groups.get_groups_by_member_id(user_id, db=db)
        }
        return has_access(user_id, permission, knowledge.access_control, user_group_ids)

    def get_knowledge_bases_by_user_id(
        self, user_id: str, permission: str = "write", db: Optional[Session] = None
    ) -> list[KnowledgeUserModel]:
        """Every knowledge base this person may open, at this permission.

        Narrowed in SQL rather than after loading: a knowledge base is decrypted
        as it is read, so loading one whose key this person does not hold would
        raise rather than simply be filtered out.
        """
        with get_db_context(db) as db:
            filter = {"user_id": user_id}
            groups = Groups.get_groups_by_member_id(user_id, db=db)
            if groups:
                filter["group_ids"] = [group.id for group in groups]

            query = has_permission(
                db, Knowledge, db.query(Knowledge), filter, permission
            )

            rows = query.order_by(Knowledge.updated_at.desc()).all()
            user_ids = list({row.user_id for row in rows})
            users = {
                user.id: user
                for user in (
                    Users.get_users_by_user_ids(user_ids, db=db) if user_ids else []
                )
            }
            return [
                KnowledgeUserModel.model_validate(
                    {
                        **KnowledgeModel.model_validate(row).model_dump(),
                        "user": (
                            users[row.user_id].model_dump()
                            if row.user_id in users
                            else None
                        ),
                    }
                )
                for row in rows
            ]

    def get_knowledge_by_id(
        self, id: str, db: Optional[Session] = None
    ) -> Optional[KnowledgeModel]:
        try:
            with get_db_context(db) as db:
                knowledge = db.query(Knowledge).filter_by(id=id).first()
                return KnowledgeModel.model_validate(knowledge) if knowledge else None
        except Exception:
            return None

    def get_knowledge_access_by_id(self, id: str, db: Optional[Session] = None):
        """Who owns this knowledge base and who may reach it, without reading it.

        For callers that only have to decide whether an action is allowed —
        deleting, above all. Deleting does not need the contents, so it must not
        need the key: an administrator can remove someone's knowledge base
        without being able to open it.
        """
        # See delete_knowledge_by_id for why this import is not at the top.
        from open_webui.utils.encrypted_models import read_without_decrypting

        with get_db_context(db) as db:
            return read_without_decrypting(
                db, Knowledge, id, "id", "user_id", "access_control"
            )

    def get_knowledge_by_id_and_user_id(
        self, id: str, user_id: str, db: Optional[Session] = None
    ) -> Optional[KnowledgeModel]:
        knowledge = self.get_knowledge_by_id(id, db=db)
        if not knowledge:
            return None

        if knowledge.user_id == user_id:
            return knowledge

        user_group_ids = {
            group.id for group in Groups.get_groups_by_member_id(user_id, db=db)
        }
        if has_access(user_id, "write", knowledge.access_control, user_group_ids):
            return knowledge
        return None

    def get_knowledges_by_file_id(
        self, file_id: str, user_id: str, db: Optional[Session] = None
    ) -> list[KnowledgeModel]:
        """The knowledge bases holding this file that this person may open.

        Scoped to one person for the same reason as
        get_knowledge_bases_by_user_id: reading a knowledge base decrypts it.
        """
        try:
            with get_db_context(db) as db:
                filter = {"user_id": user_id}
                groups = Groups.get_groups_by_member_id(user_id, db=db)
                if groups:
                    filter["group_ids"] = [group.id for group in groups]

                query = (
                    db.query(Knowledge)
                    .join(KnowledgeFile, Knowledge.id == KnowledgeFile.knowledge_id)
                    .filter(KnowledgeFile.file_id == file_id)
                )
                query = has_permission(db, Knowledge, query, filter, "read")

                return [
                    KnowledgeModel.model_validate(knowledge)
                    for knowledge in query.all()
                ]
        except Exception:
            return []

    def search_files_by_id(
        self,
        knowledge_id: str,
        user_id: str,
        filter: dict,
        skip: int = 0,
        limit: int = 30,
        db: Optional[Session] = None,
    ) -> KnowledgeFileListResponse:
        try:
            with get_db_context(db) as db:
                query = (
                    db.query(File, User)
                    .join(KnowledgeFile, File.id == KnowledgeFile.file_id)
                    .outerjoin(User, User.id == KnowledgeFile.user_id)
                    .filter(KnowledgeFile.knowledge_id == knowledge_id)
                )

                query_key = None
                order_by = None
                direction = None

                if filter:
                    query_key = filter.get("query")
                    view_option = filter.get("view_option")
                    if view_option == "created":
                        query = query.filter(KnowledgeFile.user_id == user_id)
                    elif view_option == "shared":
                        query = query.filter(KnowledgeFile.user_id != user_id)

                    order_by = filter.get("order_by")
                    direction = filter.get("direction")

                    if order_by == "created_at":
                        if direction == "asc":
                            query = query.order_by(File.created_at.asc())
                        else:
                            query = query.order_by(File.created_at.desc())
                    elif order_by == "updated_at":
                        if direction == "asc":
                            query = query.order_by(File.updated_at.asc())
                        else:
                            query = query.order_by(File.updated_at.desc())
                    else:
                        query = query.order_by(File.updated_at.desc())

                else:
                    query = query.order_by(File.updated_at.desc())

                items = query.all()
                if query_key:
                    normalized_query = query_key.lower()
                    filtered_items = []
                    for file, user in items:
                        filename = (file.filename or "").lower()
                        if normalized_query in filename:
                            filtered_items.append((file, user))
                    items = filtered_items

                if order_by == "name":
                    items = sorted(
                        items,
                        key=lambda item: (item[0].filename or "").lower(),
                        reverse=direction != "asc",
                    )

                total = len(items)
                if skip:
                    items = items[skip:]
                if limit:
                    items = items[:limit]

                files = []
                for file, user in items:
                    files.append(
                        FileUserResponse(
                            **FileModel.model_validate(file).model_dump(),
                            user=(
                                UserResponse(
                                    **UserModel.model_validate(user).model_dump()
                                )
                                if user
                                else None
                            ),
                        )
                    )

                return KnowledgeFileListResponse(items=files, total=total)
        except Exception as e:
            print(e)
            return KnowledgeFileListResponse(items=[], total=0)

    def get_files_by_id(
        self, knowledge_id: str, db: Optional[Session] = None
    ) -> list[FileModel]:
        try:
            with get_db_context(db) as db:
                files = (
                    db.query(File)
                    .join(KnowledgeFile, File.id == KnowledgeFile.file_id)
                    .filter(KnowledgeFile.knowledge_id == knowledge_id)
                    .all()
                )
                return [FileModel.model_validate(file) for file in files]
        except Exception:
            return []

    def get_file_metadatas_by_id(
        self, knowledge_id: str, db: Optional[Session] = None
    ) -> list[FileMetadataResponse]:
        try:
            with get_db_context(db) as db:
                files = self.get_files_by_id(knowledge_id, db=db)
                return [FileMetadataResponse(**file.model_dump()) for file in files]
        except Exception:
            return []

    def add_file_to_knowledge_by_id(
        self,
        knowledge_id: str,
        file_id: str,
        user_id: str,
        db: Optional[Session] = None,
    ) -> Optional[KnowledgeFileModel]:
        with get_db_context(db) as db:
            knowledge_file = KnowledgeFileModel(
                **{
                    "id": str(uuid.uuid4()),
                    "knowledge_id": knowledge_id,
                    "file_id": file_id,
                    "user_id": user_id,
                    "created_at": int(time.time()),
                    "updated_at": int(time.time()),
                }
            )

            try:
                result = KnowledgeFile(**knowledge_file.model_dump())
                db.add(result)
                db.commit()
                db.refresh(result)
                if result:
                    return KnowledgeFileModel.model_validate(result)
                else:
                    return None
            except Exception:
                return None

    def remove_file_from_knowledge_by_id(
        self, knowledge_id: str, file_id: str, db: Optional[Session] = None
    ) -> bool:
        try:
            with get_db_context(db) as db:
                db.query(KnowledgeFile).filter_by(
                    knowledge_id=knowledge_id, file_id=file_id
                ).delete()
                db.commit()
                return True
        except Exception:
            return False

    def reset_knowledge_by_id(
        self, id: str, db: Optional[Session] = None
    ) -> Optional[KnowledgeModel]:
        try:
            with get_db_context(db) as db:
                # Delete all knowledge_file entries for this knowledge_id
                db.query(KnowledgeFile).filter_by(knowledge_id=id).delete()
                db.commit()

                # Update the knowledge entry's updated_at timestamp
                db.query(Knowledge).filter_by(id=id).update(
                    {
                        "updated_at": int(time.time()),
                    }
                )
                db.commit()

                return self.get_knowledge_by_id(id=id, db=db)
        except Exception as e:
            log.exception(e)
            return None

    def update_knowledge_by_id(
        self,
        id: str,
        form_data: KnowledgeForm,
        overwrite: bool = False,
        db: Optional[Session] = None,
    ) -> Optional[KnowledgeModel]:
        # Written through the loaded row rather than as a bulk UPDATE: a bulk
        # UPDATE skips the mapper events, so the name and description would be
        # stored in the clear and the shared key copies would never be brought
        # in line with the new access_control.
        with get_db_context(db) as db:
            knowledge = db.query(Knowledge).filter_by(id=id).first()
            if not knowledge:
                return None

            knowledge.name = form_data.name
            knowledge.description = form_data.description
            knowledge.access_control = form_data.access_control
            knowledge.updated_at = int(time.time())

            db.commit()
            db.refresh(knowledge)
            return KnowledgeModel.model_validate(knowledge)

    def update_knowledge_data_by_id(
        self, id: str, data: dict, db: Optional[Session] = None
    ) -> Optional[KnowledgeModel]:
        try:
            with get_db_context(db) as db:
                knowledge = self.get_knowledge_by_id(id=id, db=db)
                db.query(Knowledge).filter_by(id=id).update(
                    {
                        "data": data,
                        "updated_at": int(time.time()),
                    }
                )
                db.commit()
                return self.get_knowledge_by_id(id=id, db=db)
        except Exception as e:
            log.exception(e)
            return None

    def delete_knowledge_by_id(self, id: str, db: Optional[Session] = None) -> bool:
        # Imported here because the registry imports every model, this one
        # included, so importing it at the top would close a cycle.
        from open_webui.utils.encrypted_models import delete_without_reading

        try:
            with get_db_context(db) as db:
                delete_without_reading(db, Knowledge, [id])
                db.commit()
                return True
        except Exception:
            return False

    def delete_all_knowledge(self, db: Optional[Session] = None) -> bool:
        # See delete_knowledge_by_id for why this import is not at the top.
        from open_webui.utils.encrypted_models import delete_without_reading

        with get_db_context(db) as db:
            try:
                ids = [row.id for row in db.query(Knowledge.id).all()]
                delete_without_reading(db, Knowledge, ids)
                db.commit()

                return True
            except Exception:
                return False


Knowledges = KnowledgeTable()
