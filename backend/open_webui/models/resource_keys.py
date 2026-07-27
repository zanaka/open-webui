import time
from typing import Optional

from sqlalchemy import BigInteger, Column, LargeBinary, Text
from sqlalchemy.orm import Session

from open_webui.internal.db import Base, get_db_context

####################
# Resource key DB Schema
#
# One content key per shared resource, stored once per person who may open it,
# wrapped with that person's public key. Not tied to any one feature: the
# resource_type column says which model the row belongs to.
####################


class ResourceKey(Base):
    __tablename__ = "resource_key"

    resource_type = Column(Text, primary_key=True)
    resource_id = Column(Text, primary_key=True)
    user_id = Column(Text, primary_key=True)
    wrapped_key = Column(LargeBinary, nullable=False)
    created_at = Column(BigInteger)


class ResourceKeysTable:
    def insert_new_key(
        self,
        resource_type: str,
        resource_id: str,
        user_id: str,
        wrapped_key: bytes,
        db: Optional[Session] = None,
    ) -> bool:
        with get_db_context(db) as db:
            db.merge(
                ResourceKey(
                    resource_type=resource_type,
                    resource_id=resource_id,
                    user_id=user_id,
                    wrapped_key=wrapped_key,
                    created_at=int(time.time()),
                )
            )
            db.commit()
            return True

    def get_wrapped_key(
        self,
        resource_type: str,
        resource_id: str,
        user_id: str,
        db: Optional[Session] = None,
    ) -> Optional[bytes]:
        with get_db_context(db) as db:
            row = (
                db.query(ResourceKey)
                .filter_by(
                    resource_type=resource_type,
                    resource_id=resource_id,
                    user_id=user_id,
                )
                .first()
            )
            return row.wrapped_key if row else None

    def get_user_ids(
        self, resource_type: str, resource_id: str, db: Optional[Session] = None
    ) -> list[str]:
        with get_db_context(db) as db:
            rows = (
                db.query(ResourceKey.user_id)
                .filter_by(resource_type=resource_type, resource_id=resource_id)
                .all()
            )
            return [row[0] for row in rows]

    def delete_key(
        self,
        resource_type: str,
        resource_id: str,
        user_id: str,
        db: Optional[Session] = None,
    ) -> bool:
        with get_db_context(db) as db:
            db.query(ResourceKey).filter_by(
                resource_type=resource_type,
                resource_id=resource_id,
                user_id=user_id,
            ).delete(synchronize_session=False)
            db.commit()
            return True

    def delete_resource(
        self, resource_type: str, resource_id: str, db: Optional[Session] = None
    ) -> bool:
        with get_db_context(db) as db:
            db.query(ResourceKey).filter_by(
                resource_type=resource_type, resource_id=resource_id
            ).delete(synchronize_session=False)
            db.commit()
            return True


ResourceKeys = ResourceKeysTable()
