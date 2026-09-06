import logging
import time
import uuid
from typing import Optional

from open_webui.config import RAG_FILE_CONTENT_SEARCH_MAX_CHARS
from open_webui.crypto_exceptions import CryptoPolicyError
from open_webui.internal.db import Base, JSONField, get_async_db_context
from open_webui.models.access_grants import AccessGrantModel, AccessGrants
from open_webui.models.files import (
    File,
    FileMetadataResponse,
    FileModel,
    FileModelResponse,
)
from open_webui.models.groups import Groups
from open_webui.models.users import User, UserModel, UserResponse, Users
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    delete,
    func,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

# Columns the knowledge base list may be ordered by; anything else falls back to the default.
KNOWLEDGE_SORTABLE_FIELDS = {'name', 'created_at', 'updated_at'}

####################
# Knowledge DB Schema
# Let what was gathered here outlast the one who gathered it,
# and still teach when the builder is gone.
####################


class Knowledge(Base):
    __tablename__ = 'knowledge'

    id = Column(Text, unique=True, primary_key=True)
    user_id = Column(Text)

    name = Column(Text)
    description = Column(Text)

    meta = Column(JSON, nullable=True)

    created_at = Column(BigInteger)
    updated_at = Column(BigInteger)


class KnowledgeDirectory(Base):
    __tablename__ = 'knowledge_directory'

    id = Column(Text, unique=True, primary_key=True)
    knowledge_id = Column(Text, ForeignKey('knowledge.id', ondelete='CASCADE'), nullable=False)
    parent_id = Column(Text, ForeignKey('knowledge_directory.id', ondelete='CASCADE'), nullable=True)
    name = Column(Text, nullable=False)
    user_id = Column(Text, nullable=False)

    created_at = Column(BigInteger, nullable=False)
    updated_at = Column(BigInteger, nullable=False)

    __table_args__ = (
        UniqueConstraint('knowledge_id', 'parent_id', 'name', name='uq_knowledge_directory_knowledge_parent_name'),
        Index('ix_knowledge_directory_knowledge_id', 'knowledge_id'),
        Index('ix_knowledge_directory_parent_id', 'parent_id'),
    )


class KnowledgeModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str

    name: str
    description: str

    meta: Optional[dict] = None

    access_grants: list[AccessGrantModel] = Field(default_factory=list)

    created_at: int  # timestamp in epoch
    updated_at: int  # timestamp in epoch


class KnowledgeFile(Base):
    __tablename__ = 'knowledge_file'

    id = Column(Text, unique=True, primary_key=True)

    knowledge_id = Column(Text, ForeignKey('knowledge.id', ondelete='CASCADE'), nullable=False)
    file_id = Column(Text, ForeignKey('file.id', ondelete='CASCADE'), nullable=False)
    directory_id = Column(Text, ForeignKey('knowledge_directory.id', ondelete='SET NULL'), nullable=True)
    user_id = Column(Text, nullable=False)

    created_at = Column(BigInteger, nullable=False)
    updated_at = Column(BigInteger, nullable=False)

    __table_args__ = (
        UniqueConstraint('knowledge_id', 'file_id', name='uq_knowledge_file_knowledge_file'),
        Index('ix_knowledge_file_directory_id', 'directory_id'),
    )


class KnowledgeFileModel(BaseModel):
    id: str
    knowledge_id: str
    file_id: str
    directory_id: Optional[str] = None
    user_id: str

    created_at: int  # timestamp in epoch
    updated_at: int  # timestamp in epoch

    model_config = ConfigDict(from_attributes=True)


class KnowledgeDirectoryModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    knowledge_id: str
    parent_id: Optional[str] = None
    name: str
    user_id: str

    created_at: int  # timestamp in epoch
    updated_at: int  # timestamp in epoch


class KnowledgeDirectoryForm(BaseModel):
    name: str
    parent_id: Optional[str] = None


####################
# Forms
####################
class KnowledgeUserModel(KnowledgeModel):
    user: Optional[UserResponse] = None
    file_count: int | None = None


class KnowledgeResponse(KnowledgeModel):
    files: Optional[list[FileMetadataResponse | dict]] = None


class KnowledgeUserResponse(KnowledgeUserModel):
    pass


class KnowledgeForm(BaseModel):
    name: str
    description: str
    access_grants: Optional[list[dict]] = None


class FileUserResponse(FileModelResponse):
    user: Optional[UserResponse] = None


class KnowledgeListResponse(BaseModel):
    items: list[KnowledgeUserModel]
    total: int


class KnowledgeFileListResponse(BaseModel):
    items: list[FileUserResponse]
    directories: list[KnowledgeDirectoryModel] = Field(default_factory=list)
    breadcrumbs: list[KnowledgeDirectoryModel] = Field(default_factory=list)
    total: int


class KnowledgeTable:
    async def _get_access_grants(self, knowledge_id: str, db: Optional[AsyncSession] = None) -> list[AccessGrantModel]:
        return await AccessGrants.get_grants_by_resource('knowledge', knowledge_id, db=db)

    async def _to_knowledge_model(
        self,
        knowledge: Knowledge,
        access_grants: Optional[list[AccessGrantModel]] = None,
        db: Optional[AsyncSession] = None,
    ) -> KnowledgeModel:
        knowledge_model = KnowledgeModel.model_validate(knowledge)
        knowledge_model.access_grants = (
            access_grants if access_grants is not None else await self._get_access_grants(knowledge_model.id, db=db)
        )
        return knowledge_model

    async def insert_new_knowledge(
        self, user_id: str, form_data: KnowledgeForm, db: Optional[AsyncSession] = None
    ) -> Optional[KnowledgeModel]:
        async with get_async_db_context(db) as db:
            knowledge = KnowledgeModel(
                **{
                    **form_data.model_dump(exclude={'access_grants'}),
                    'id': str(uuid.uuid4()),
                    'user_id': user_id,
                    'created_at': int(time.time()),
                    'updated_at': int(time.time()),
                    'access_grants': [],
                }
            )

            try:
                result = Knowledge(**knowledge.model_dump(exclude={'access_grants'}))
                db.add(result)
                await db.commit()
                await db.refresh(result)
                await AccessGrants.set_access_grants('knowledge', result.id, form_data.access_grants, db=db)
                if result:
                    return await self._to_knowledge_model(result, db=db)
                else:
                    return None
            except CryptoPolicyError:
                # A refused audience is an answer for the caller, not a failure
                # to write, so it must not be flattened into None here.
                raise
            except Exception:
                return None

    async def get_knowledge_bases(
        self, skip: int = 0, limit: int = 30, db: Optional[AsyncSession] = None
    ) -> list[KnowledgeUserModel]:
        async with get_async_db_context(db) as db:
            result = await db.execute(select(Knowledge).order_by(Knowledge.updated_at.desc()))
            all_knowledge = result.scalars().all()
            user_ids = list(set(knowledge.user_id for knowledge in all_knowledge))
            knowledge_ids = [knowledge.id for knowledge in all_knowledge]

            users = await Users.get_users_by_user_ids(user_ids, db=db) if user_ids else []
            users_dict = {user.id: user for user in users}
            grants_map = await AccessGrants.get_grants_by_resources('knowledge', knowledge_ids, db=db)

            knowledge_bases = []
            for knowledge in all_knowledge:
                user = users_dict.get(knowledge.user_id)
                knowledge_bases.append(
                    KnowledgeUserModel.model_validate(
                        {
                            **(
                                await self._to_knowledge_model(
                                    knowledge,
                                    access_grants=grants_map.get(knowledge.id, []),
                                    db=db,
                                )
                            ).model_dump(),
                            'user': user.model_dump() if user else None,
                        }
                    )
                )
            return knowledge_bases

    async def search_knowledge_bases(
        self,
        user_id: str,
        filter: dict,
        skip: int = 0,
        limit: int = 30,
        db: Optional[AsyncSession] = None,
    ) -> KnowledgeListResponse:
        try:
            async with get_async_db_context(db) as db:
                stmt = select(Knowledge, User).outerjoin(User, User.id == Knowledge.user_id)

                query_key = None
                source = None
                if filter:
                    query_key = filter.get('query')
                    source = filter.get('source')

                    view_option = filter.get('view_option')
                    if view_option == 'created':
                        stmt = stmt.filter(Knowledge.user_id == user_id)
                    elif view_option == 'shared':
                        stmt = stmt.filter(Knowledge.user_id != user_id)

                    stmt = AccessGrants.has_permission_filter(
                        db=db,
                        query=stmt,
                        DocumentModel=Knowledge,
                        filter=filter,
                        resource_type='knowledge',
                        permission='read',
                    )

                order_by = (filter or {}).get('order_by')
                direction = (filter or {}).get('direction')

                if order_by in KNOWLEDGE_SORTABLE_FIELDS and order_by != 'name':
                    column = getattr(Knowledge, order_by)
                    if (direction or 'desc').lower() == 'asc':
                        stmt = stmt.order_by(column.asc(), Knowledge.id.asc())
                    else:
                        stmt = stmt.order_by(column.desc(), Knowledge.id.asc())
                else:
                    stmt = stmt.order_by(Knowledge.updated_at.desc(), Knowledge.id.asc())

                result = await db.execute(stmt)
                items = result.all()

                # The name, the description and the meta are matched after they
                # are read, because they are encrypted at rest and SQL only
                # ever sees ciphertext.
                if source == 'external':
                    items = [(kb, user) for kb, user in items if (kb.meta or {}).get('source') == 'external']
                elif source == 'local':
                    items = [(kb, user) for kb, user in items if (kb.meta or {}).get('source') != 'external']

                if query_key:
                    needle = query_key.lower()
                    items = [
                        (kb, user)
                        for kb, user in items
                        if needle in (kb.name or '').lower()
                        or needle in (kb.description or '').lower()
                        or (user is not None and needle in (user.name or '').lower())
                        or (user is not None and needle in (user.email or '').lower())
                        or (user is not None and needle in (user.username or '').lower())
                    ]

                if order_by == 'name':
                    # Sorted on the decrypted name, which SQL never sees.
                    items = sorted(
                        items,
                        key=lambda item: (item[0].name or '').lower(),
                        reverse=(direction or 'desc').lower() != 'asc',
                    )

                # Counted after filtering, so the total matches what is returned.
                total = len(items)
                if skip:
                    items = items[skip:]
                if limit:
                    items = items[:limit]

                knowledge_ids = [kb.id for kb, _ in items]
                grants_map = await AccessGrants.get_grants_by_resources('knowledge', knowledge_ids, db=db)
                file_counts = {}
                if knowledge_ids:
                    file_count_result = await db.execute(
                        select(KnowledgeFile.knowledge_id, func.count(KnowledgeFile.id))
                        .where(KnowledgeFile.knowledge_id.in_(knowledge_ids))
                        .group_by(KnowledgeFile.knowledge_id)
                    )
                    file_counts = dict(file_count_result.all())

                knowledge_bases = []
                for knowledge_base, user in items:
                    knowledge_bases.append(
                        KnowledgeUserModel.model_validate(
                            {
                                **(
                                    await self._to_knowledge_model(
                                        knowledge_base,
                                        access_grants=grants_map.get(knowledge_base.id, []),
                                        db=db,
                                    )
                                ).model_dump(),
                                'user': (UserModel.model_validate(user).model_dump() if user else None),
                                'file_count': file_counts.get(knowledge_base.id, 0),
                            }
                        )
                    )

                return KnowledgeListResponse(items=knowledge_bases, total=total)
        except Exception as e:
            print(e)
            return KnowledgeListResponse(items=[], total=0)

    async def search_knowledge_files(
        self, filter: dict, skip: int = 0, limit: int = 30, db: Optional[AsyncSession] = None
    ) -> KnowledgeFileListResponse:
        """
        Scalable version: search files across all knowledge bases the user has
        READ access to, without loading all KBs or using large IN() lists.
        """
        try:
            async with get_async_db_context(db) as db:
                # Base query: join Knowledge → KnowledgeFile → File
                stmt = (
                    select(File, User, Knowledge)
                    .join(KnowledgeFile, File.id == KnowledgeFile.file_id)
                    .join(Knowledge, KnowledgeFile.knowledge_id == Knowledge.id)
                    .outerjoin(User, User.id == KnowledgeFile.user_id)
                )

                # Apply access-control directly to the joined query
                stmt = AccessGrants.has_permission_filter(
                    db=db,
                    query=stmt,
                    DocumentModel=Knowledge,
                    filter=filter,
                    resource_type='knowledge',
                    permission='read',
                )

                # Order by file changes
                stmt = stmt.order_by(File.updated_at.desc(), File.id.asc())

                result = await db.execute(stmt)
                rows = result.all()

                # The filename and the content are matched after they are read,
                # because they are encrypted at rest and SQL only ever sees
                # ciphertext.
                if filter:
                    q = filter.get('query')
                    if q:
                        needle = q.lower()
                        include_content = bool(filter.get('include_content'))
                        filtered_rows = []
                        for file, user, knowledge in rows:
                            if needle in (file.filename or '').lower():
                                filtered_rows.append((file, user, knowledge))
                                continue
                            if include_content:
                                content = ((file.data or {}).get('content') or '')
                                if not isinstance(content, str):
                                    content = str(content)
                                if needle in content[:RAG_FILE_CONTENT_SEARCH_MAX_CHARS].lower():
                                    filtered_rows.append((file, user, knowledge))
                        rows = filtered_rows

                # Counted after filtering, so the total matches what is returned.
                total = len(rows)

                if skip:
                    rows = rows[skip:]
                if limit:
                    rows = rows[:limit]

                items = []
                for file, user, knowledge in rows:
                    items.append(
                        FileUserResponse(
                            id=file.id,
                            user_id=file.user_id,
                            hash=file.hash,
                            filename=file.filename,
                            meta=file.meta,
                            created_at=file.created_at,
                            updated_at=file.updated_at,
                            user=(UserResponse(**UserModel.model_validate(user).model_dump()) if user else None),
                            collection=(await self._to_knowledge_model(knowledge, db=db)).model_dump(),
                        )
                    )

                return KnowledgeFileListResponse(items=items, total=total)

        except Exception as e:
            print('search_knowledge_files error:', e)
            return KnowledgeFileListResponse(items=[], total=0)

    async def check_access_by_user_id(
        self,
        id,
        user_id,
        permission='write',
        db: Optional[AsyncSession] = None,
        user_group_ids: set[str] | None = None,
    ) -> bool:
        # Deciding whether an action is allowed needs ownership and grants,
        # never the contents — so it must not need the key. Loading the row
        # here would decrypt it and refuse for anyone who holds no key, and
        # the refusal would read as "no access" for people (an administrator,
        # a write-checked member) the answer should be yes for.
        knowledge = await self.get_knowledge_access_by_id(id, db=db)
        if not knowledge:
            return False
        if knowledge.user_id == user_id:
            return True
        if user_group_ids is None:
            user_groups = await Groups.get_groups_by_member_id(user_id, db=db)
            user_group_ids = {group.id for group in user_groups}
        return await AccessGrants.has_access(
            user_id=user_id,
            resource_type='knowledge',
            resource_id=knowledge.id,
            permission=permission,
            user_group_ids=user_group_ids,
            db=db,
        )

    async def get_knowledge_by_id(self, id: str, db: Optional[AsyncSession] = None) -> Optional[KnowledgeModel]:
        try:
            async with get_async_db_context(db) as db:
                result = await db.execute(select(Knowledge).filter_by(id=id))
                knowledge = result.scalars().first()
                return await self._to_knowledge_model(knowledge, db=db) if knowledge else None
        except Exception:
            return None

    async def get_knowledge_access_by_id(self, id: str, db: Optional[AsyncSession] = None):
        """Who owns this knowledge base, without reading it.

        For callers that only have to decide whether an action is allowed —
        deleting, above all. Deleting does not need the contents, so it must
        not need the key: an administrator can remove someone's knowledge base
        without being able to open it. Who may reach it lives in the
        access_grant table, keyless as well.
        """
        # See delete_knowledge_by_id for why this import is not at the top.
        from open_webui.utils.encrypted_models import read_without_decrypting_async

        async with get_async_db_context(db) as db:
            return await read_without_decrypting_async(db, Knowledge, id, 'id', 'user_id')

    async def get_knowledges_by_file_id(
        self, file_id: str, user_id: str, db: Optional[AsyncSession] = None
    ) -> list[KnowledgeModel]:
        """The knowledge bases holding this file that this person may open.

        Scoped to one person because a knowledge base is decrypted as it is
        read, so loading one whose key this person does not hold would raise
        rather than simply be filtered out.
        """
        try:
            async with get_async_db_context(db) as db:
                filter = {'user_id': user_id}
                groups = await Groups.get_groups_by_member_id(user_id, db=db)
                if groups:
                    filter['group_ids'] = [group.id for group in groups]

                stmt = (
                    select(Knowledge)
                    .join(KnowledgeFile, Knowledge.id == KnowledgeFile.knowledge_id)
                    .filter(KnowledgeFile.file_id == file_id)
                )
                stmt = AccessGrants.has_permission_filter(
                    db=db,
                    query=stmt,
                    DocumentModel=Knowledge,
                    filter=filter,
                    resource_type='knowledge',
                    permission='read',
                )

                result = await db.execute(stmt)
                knowledges = result.scalars().all()
                knowledge_ids = [k.id for k in knowledges]
                grants_map = await AccessGrants.get_grants_by_resources('knowledge', knowledge_ids, db=db)
                return [
                    await self._to_knowledge_model(
                        knowledge,
                        access_grants=grants_map.get(knowledge.id, []),
                        db=db,
                    )
                    for knowledge in knowledges
                ]
        except Exception:
            return []

    async def search_files_by_id(
        self,
        knowledge_id: str,
        user_id: str,
        filter: dict,
        skip: int = 0,
        limit: int = 30,
        db: Optional[AsyncSession] = None,
    ) -> KnowledgeFileListResponse:
        try:
            async with get_async_db_context(db) as db:
                stmt = (
                    select(File, User)
                    .join(KnowledgeFile, File.id == KnowledgeFile.file_id)
                    .outerjoin(User, User.id == KnowledgeFile.user_id)
                    .filter(KnowledgeFile.knowledge_id == knowledge_id)
                )

                # Filter by directory_id (None = root level)
                directory_id = filter.get('directory_id') if filter else None
                if directory_id:
                    stmt = stmt.filter(KnowledgeFile.directory_id == directory_id)
                elif filter and 'directory_id' in filter:
                    # Explicit None = root level only
                    stmt = stmt.filter(KnowledgeFile.directory_id.is_(None))

                # Default sort: updated_at descending
                primary_sort = File.updated_at.desc()

                query_key = None
                order_by = None
                direction = None

                if filter:
                    query_key = filter.get('query')

                    view_option = filter.get('view_option')
                    if view_option == 'created':
                        stmt = stmt.filter(KnowledgeFile.user_id == user_id)
                    elif view_option == 'shared':
                        stmt = stmt.filter(KnowledgeFile.user_id != user_id)

                    order_by = filter.get('order_by')
                    direction = filter.get('direction')
                    is_asc = direction == 'asc'

                    if order_by == 'created_at':
                        primary_sort = File.created_at.asc() if is_asc else File.created_at.desc()
                    elif order_by == 'updated_at':
                        primary_sort = File.updated_at.asc() if is_asc else File.updated_at.desc()

                # Apply sort with secondary key for deterministic pagination
                stmt = stmt.order_by(primary_sort, File.id.asc())

                result = await db.execute(stmt)
                items = result.all()

                # The filename and the content are matched after they are
                # read, because they are encrypted at rest and SQL only ever
                # sees ciphertext.
                if query_key:
                    needle = query_key.lower()
                    include_content = bool(filter.get('include_content'))
                    filtered_items = []
                    for file, user in items:
                        if needle in (file.filename or '').lower():
                            filtered_items.append((file, user))
                            continue
                        if include_content:
                            content = ((file.data or {}).get('content') or '')
                            if not isinstance(content, str):
                                content = str(content)
                            if needle in content[:RAG_FILE_CONTENT_SEARCH_MAX_CHARS].lower():
                                filtered_items.append((file, user))
                    items = filtered_items

                if order_by == 'name':
                    # Sorted on the decrypted filename, which SQL never sees.
                    items = sorted(
                        items,
                        key=lambda item: (item[0].filename or '').lower(),
                        reverse=direction != 'asc',
                    )

                # Counted after filtering, so the total matches what is returned.
                total = len(items)

                if skip:
                    items = items[skip:]
                if limit:
                    items = items[:limit]

                files = [
                    FileUserResponse(
                        id=file.id,
                        user_id=file.user_id,
                        hash=file.hash,
                        filename=file.filename,
                        meta=file.meta,
                        created_at=file.created_at,
                        updated_at=file.updated_at,
                        user=(UserResponse(**UserModel.model_validate(user).model_dump()) if user else None),
                    )
                    for file, user in items
                ]

                return KnowledgeFileListResponse(
                    items=files,
                    directories=await self.get_directories(
                        knowledge_id,
                        parent_id=filter.get('directory_id') if filter else None,
                        db=db,
                    ),
                    breadcrumbs=await self.get_directory_breadcrumbs(
                        filter.get('directory_id') if filter else None,
                        db=db,
                    ),
                    total=total,
                )
        except Exception as e:
            print(e)
            return KnowledgeFileListResponse(items=[], total=0)

    async def get_files_by_id(self, knowledge_id: str, db: Optional[AsyncSession] = None) -> list[FileModel]:
        try:
            async with get_async_db_context(db) as db:
                result = await db.execute(
                    select(File)
                    .join(KnowledgeFile, File.id == KnowledgeFile.file_id)
                    .filter(KnowledgeFile.knowledge_id == knowledge_id)
                )
                files = result.scalars().all()
                return [FileModel.model_validate(file) for file in files]
        except Exception:
            return []

    async def get_file_metadatas_by_id(
        self, knowledge_id: str, db: Optional[AsyncSession] = None
    ) -> list[FileMetadataResponse]:
        """Column-only listing: File.data holds each file's full extracted
        text, which metadata views must never load."""
        try:
            async with get_async_db_context(db) as db:
                result = await db.execute(
                    select(File.id, File.hash, File.meta, File.created_at, File.updated_at)
                    .join(KnowledgeFile, File.id == KnowledgeFile.file_id)
                    .filter(KnowledgeFile.knowledge_id == knowledge_id)
                )
                return [
                    FileMetadataResponse(
                        id=row.id,
                        hash=row.hash,
                        meta=row.meta,
                        created_at=row.created_at,
                        updated_at=row.updated_at,
                    )
                    for row in result.all()
                ]
        except Exception:
            return []

    async def add_file_to_knowledge_by_id(
        self,
        knowledge_id: str,
        file_id: str,
        user_id: str,
        directory_id: Optional[str] = None,
        db: Optional[AsyncSession] = None,
    ) -> Optional[KnowledgeFileModel]:
        async with get_async_db_context(db) as db:
            knowledge_file = KnowledgeFileModel(
                **{
                    'id': str(uuid.uuid4()),
                    'knowledge_id': knowledge_id,
                    'file_id': file_id,
                    'directory_id': directory_id,
                    'user_id': user_id,
                    'created_at': int(time.time()),
                    'updated_at': int(time.time()),
                }
            )

            try:
                result = KnowledgeFile(**knowledge_file.model_dump())
                db.add(result)
                await db.commit()
                await db.refresh(result)
                if result:
                    return KnowledgeFileModel.model_validate(result)
                else:
                    return None
            except Exception:
                return None

    async def has_file(self, knowledge_id: str, file_id: str, db: Optional[AsyncSession] = None) -> bool:
        """Check whether a file belongs to a knowledge base."""
        try:
            async with get_async_db_context(db) as db:
                result = await db.execute(
                    select(KnowledgeFile).filter_by(knowledge_id=knowledge_id, file_id=file_id).limit(1)
                )
                return result.scalars().first() is not None
        except Exception:
            return False

    async def remove_file_from_knowledge_by_id(
        self, knowledge_id: str, file_id: str, db: Optional[AsyncSession] = None
    ) -> bool:
        try:
            async with get_async_db_context(db) as db:
                await db.execute(delete(KnowledgeFile).filter_by(knowledge_id=knowledge_id, file_id=file_id))
                await db.commit()
                return True
        except Exception:
            return False

    async def reset_knowledge_by_id(
        self, id: str, include_directories: bool = True, db: Optional[AsyncSession] = None
    ) -> Optional[KnowledgeModel]:
        try:
            async with get_async_db_context(db) as db:
                # Delete all knowledge_file entries for this knowledge_id
                await db.execute(delete(KnowledgeFile).filter_by(knowledge_id=id))

                # Delete all directories if requested
                if include_directories:
                    await db.execute(delete(KnowledgeDirectory).filter_by(knowledge_id=id))

                await db.commit()

                # Update the knowledge entry's updated_at timestamp
                await db.execute(update(Knowledge).filter_by(id=id).values(updated_at=int(time.time())))
                await db.commit()

                return await self.get_knowledge_by_id(id=id, db=db)
        except Exception as e:
            log.exception(e)
            return None

    async def update_knowledge_by_id(
        self,
        id: str,
        form_data: KnowledgeForm,
        overwrite: bool = False,
        db: Optional[AsyncSession] = None,
    ) -> Optional[KnowledgeModel]:
        # Written through the loaded row rather than as a bulk UPDATE: a bulk
        # UPDATE skips the mapper events, so the name and description would be
        # stored in the clear. Setting the grants flushes the dirty row in the
        # same session, so a refused audience rolls the whole change back.
        try:
            async with get_async_db_context(db) as db:
                result = await db.execute(select(Knowledge).filter_by(id=id))
                knowledge = result.scalars().first()
                if not knowledge:
                    return None

                knowledge.name = form_data.name
                knowledge.description = form_data.description
                knowledge.updated_at = int(time.time())

                if form_data.access_grants is not None:
                    await AccessGrants.set_access_grants('knowledge', id, form_data.access_grants, db=db)

                await db.commit()
                return await self._to_knowledge_model(knowledge, db=db)
        except CryptoPolicyError:
            # A refused audience is an answer for the caller, not a failure
            # to write, so it must not be flattened into None here.
            raise
        except Exception as e:
            log.exception(e)
            return None

    async def update_knowledge_meta_by_id(
        self, id: str, meta: dict, db: Optional[AsyncSession] = None
    ) -> Optional[KnowledgeModel]:
        # Written through the loaded row: meta is encrypted at rest, and a
        # bulk UPDATE would skip the mapper events and store it in the clear.
        try:
            async with get_async_db_context(db) as db:
                result = await db.execute(select(Knowledge).filter_by(id=id))
                knowledge = result.scalars().first()
                if not knowledge:
                    return None

                knowledge.meta = meta
                knowledge.updated_at = int(time.time())

                await db.commit()
                return await self._to_knowledge_model(knowledge, db=db)
        except CryptoPolicyError:
            raise
        except Exception as e:
            log.exception(e)
            return None

    async def delete_knowledge_by_id(self, id: str, db: Optional[AsyncSession] = None) -> bool:
        # Deleting does not need the contents, so it must not need the key: the
        # helper removes the row by statement — never loading, and therefore
        # never decrypting, it — and takes the wrapped key copies with it.
        # Imported here because the registry imports every model, this one
        # included, so importing it at the top would close a cycle.
        from open_webui.utils.encrypted_models import delete_without_reading_async

        try:
            async with get_async_db_context(db) as db:
                await AccessGrants.revoke_all_access('knowledge', id, db=db)
                await delete_without_reading_async(db, Knowledge, [id])
                await db.commit()
                return True
        except Exception:
            return False

    async def delete_all_knowledge(self, db: Optional[AsyncSession] = None) -> bool:
        # See delete_knowledge_by_id for why this import is not at the top.
        from open_webui.utils.encrypted_models import delete_without_reading_async

        async with get_async_db_context(db) as db:
            try:
                result = await db.execute(select(Knowledge.id))
                knowledge_ids = [row[0] for row in result.all()]
                for knowledge_id in knowledge_ids:
                    await AccessGrants.revoke_all_access('knowledge', knowledge_id, db=db)
                await delete_without_reading_async(db, Knowledge, knowledge_ids)
                await db.commit()

                return True
            except Exception:
                return False

    # ── Directory CRUD ────────────────────────────────────────────────

    async def create_directory(
        self,
        knowledge_id: str,
        name: str,
        user_id: str,
        parent_id: Optional[str] = None,
        db: Optional[AsyncSession] = None,
    ) -> Optional[KnowledgeDirectoryModel]:
        async with get_async_db_context(db) as db:
            try:
                now = int(time.time())
                directory = KnowledgeDirectory(
                    id=str(uuid.uuid4()),
                    knowledge_id=knowledge_id,
                    parent_id=parent_id,
                    name=name,
                    user_id=user_id,
                    created_at=now,
                    updated_at=now,
                )
                db.add(directory)
                await db.commit()
                await db.refresh(directory)
                return KnowledgeDirectoryModel.model_validate(directory)
            except Exception as e:
                log.exception(e)
                return None

    async def get_directories(
        self,
        knowledge_id: str,
        parent_id: Optional[str] = None,
        db: Optional[AsyncSession] = None,
    ) -> list[KnowledgeDirectoryModel]:
        """List directories at a given level (parent_id=None for root)."""
        async with get_async_db_context(db) as db:
            stmt = select(KnowledgeDirectory).filter(KnowledgeDirectory.knowledge_id == knowledge_id)
            if parent_id:
                stmt = stmt.filter(KnowledgeDirectory.parent_id == parent_id)
            else:
                stmt = stmt.filter(KnowledgeDirectory.parent_id.is_(None))

            stmt = stmt.order_by(KnowledgeDirectory.name.asc())
            result = await db.execute(stmt)
            return [KnowledgeDirectoryModel.model_validate(d) for d in result.scalars().all()]

    async def get_all_directories(
        self,
        knowledge_id: str,
        db: Optional[AsyncSession] = None,
    ) -> list[KnowledgeDirectoryModel]:
        """Get ALL directories for a KB (no parent filter). Used for tree building."""
        async with get_async_db_context(db) as db:
            stmt = (
                select(KnowledgeDirectory)
                .filter(KnowledgeDirectory.knowledge_id == knowledge_id)
                .order_by(KnowledgeDirectory.name.asc())
            )
            result = await db.execute(stmt)
            return [KnowledgeDirectoryModel.model_validate(d) for d in result.scalars().all()]

    async def get_files_with_directory_ids(
        self,
        knowledge_id: str,
        db: Optional[AsyncSession] = None,
    ) -> list[tuple[FileModel, Optional[str]]]:
        """Get all files in a KB with their directory_id from KnowledgeFile."""
        try:
            async with get_async_db_context(db) as db:
                result = await db.execute(
                    select(File, KnowledgeFile.directory_id)
                    .join(KnowledgeFile, File.id == KnowledgeFile.file_id)
                    .filter(KnowledgeFile.knowledge_id == knowledge_id)
                )
                return [(FileModel.model_validate(file), dir_id) for file, dir_id in result.all()]
        except Exception:
            return []

    async def get_directory_by_id(
        self, directory_id: str, db: Optional[AsyncSession] = None
    ) -> Optional[KnowledgeDirectoryModel]:
        async with get_async_db_context(db) as db:
            result = await db.execute(select(KnowledgeDirectory).filter_by(id=directory_id))
            directory = result.scalars().first()
            return KnowledgeDirectoryModel.model_validate(directory) if directory else None

    async def get_directory_breadcrumbs(
        self,
        directory_id: Optional[str],
        db: Optional[AsyncSession] = None,
    ) -> list[KnowledgeDirectoryModel]:
        """Walk up the parent chain to build breadcrumbs (root first)."""
        if not directory_id:
            return []

        async with get_async_db_context(db) as db:
            breadcrumbs = []
            current_id = directory_id
            seen = set()

            while current_id and current_id not in seen:
                seen.add(current_id)
                result = await db.execute(select(KnowledgeDirectory).filter_by(id=current_id))
                directory = result.scalars().first()
                if not directory:
                    break
                breadcrumbs.append(KnowledgeDirectoryModel.model_validate(directory))
                current_id = directory.parent_id

            breadcrumbs.reverse()  # root first
            return breadcrumbs

    async def rename_directory(
        self,
        directory_id: str,
        name: str,
        db: Optional[AsyncSession] = None,
    ) -> Optional[KnowledgeDirectoryModel]:
        async with get_async_db_context(db) as db:
            try:
                await db.execute(
                    update(KnowledgeDirectory).filter_by(id=directory_id).values(name=name, updated_at=int(time.time()))
                )
                await db.commit()
                return await self.get_directory_by_id(directory_id, db=db)
            except Exception as e:
                log.exception(e)
                return None

    async def move_directory(
        self,
        directory_id: str,
        new_parent_id: Optional[str],
        db: Optional[AsyncSession] = None,
    ) -> Optional[KnowledgeDirectoryModel]:
        """Move a directory to a new parent, with cycle detection."""
        async with get_async_db_context(db) as db:
            try:
                # Cycle detection: walk up from new_parent_id to ensure
                # we don't encounter directory_id
                if new_parent_id:
                    current = new_parent_id
                    seen = set()
                    while current and current not in seen:
                        if current == directory_id:
                            return None  # Would create a cycle
                        seen.add(current)
                        result = await db.execute(select(KnowledgeDirectory.parent_id).filter_by(id=current))
                        row = result.first()
                        current = row[0] if row else None

                await db.execute(
                    update(KnowledgeDirectory)
                    .filter_by(id=directory_id)
                    .values(parent_id=new_parent_id, updated_at=int(time.time()))
                )
                await db.commit()
                return await self.get_directory_by_id(directory_id, db=db)
            except Exception as e:
                log.exception(e)
                return None

    async def update_directory(
        self,
        directory_id: str,
        name: Optional[str] = None,
        parent_id: Optional[str] = '__unset__',
        db: Optional[AsyncSession] = None,
    ) -> Optional[KnowledgeDirectoryModel]:
        """Update directory name and/or parent. Pass parent_id=None to move to root."""
        # Handle move if parent_id is being changed
        if parent_id != '__unset__':
            result = await self.move_directory(directory_id, parent_id, db=db)
            if result is None:
                return None  # Cycle detected or error

        if name is not None:
            return await self.rename_directory(directory_id, name, db=db)

        return await self.get_directory_by_id(directory_id, db=db)

    async def delete_directory(
        self,
        directory_id: str,
        move_files_to_parent: bool = True,
        db: Optional[AsyncSession] = None,
    ) -> bool:
        """
        Delete a directory.
        - If move_files_to_parent=True: files move to parent dir (or root)
        - If move_files_to_parent=False: files are also deleted
        """
        async with get_async_db_context(db) as db:
            try:
                # Get the directory to find its parent
                result = await db.execute(select(KnowledgeDirectory).filter_by(id=directory_id))
                directory = result.scalars().first()
                if not directory:
                    return False

                parent_id = directory.parent_id

                if move_files_to_parent:
                    # Move files in this directory to its parent (or root)
                    await db.execute(
                        update(KnowledgeFile).filter_by(directory_id=directory_id).values(directory_id=parent_id)
                    )
                    # Recursively move files from all subdirectories too
                    await self._move_files_from_subtree(directory_id, parent_id, db=db)
                else:
                    # Delete files in this directory and all subdirectories
                    await self._delete_files_in_subtree(directory_id, db=db)

                # CASCADE on parent_id will handle deleting subdirectories
                await db.execute(delete(KnowledgeDirectory).filter_by(id=directory_id))
                await db.commit()
                return True
            except Exception as e:
                log.exception(e)
                return False

    async def _move_files_from_subtree(
        self,
        directory_id: str,
        target_directory_id: Optional[str],
        db: AsyncSession,
    ) -> None:
        """Recursively move all files from a directory subtree to the target."""
        result = await db.execute(select(KnowledgeDirectory.id).filter_by(parent_id=directory_id))
        child_ids = [row[0] for row in result.all()]

        for child_id in child_ids:
            await db.execute(
                update(KnowledgeFile).filter_by(directory_id=child_id).values(directory_id=target_directory_id)
            )
            await self._move_files_from_subtree(child_id, target_directory_id, db=db)

    async def _delete_files_in_subtree(
        self,
        directory_id: str,
        db: AsyncSession,
    ) -> None:
        """Recursively delete all files from a directory subtree."""
        await db.execute(delete(KnowledgeFile).filter_by(directory_id=directory_id))
        result = await db.execute(select(KnowledgeDirectory.id).filter_by(parent_id=directory_id))
        child_ids = [row[0] for row in result.all()]
        for child_id in child_ids:
            await self._delete_files_in_subtree(child_id, db=db)

    async def move_file_to_directory(
        self,
        knowledge_id: str,
        file_id: str,
        directory_id: Optional[str] = None,
        db: Optional[AsyncSession] = None,
    ) -> bool:
        """Move a file to a different directory within the same KB."""
        async with get_async_db_context(db) as db:
            try:
                await db.execute(
                    update(KnowledgeFile)
                    .filter_by(knowledge_id=knowledge_id, file_id=file_id)
                    .values(directory_id=directory_id, updated_at=int(time.time()))
                )
                await db.commit()
                return True
            except Exception as e:
                log.exception(e)
                return False


Knowledges = KnowledgeTable()
