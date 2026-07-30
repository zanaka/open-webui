import time
from typing import Optional

from sqlalchemy.orm import Session
from open_webui.internal.db import Base, JSONField, get_db, get_db_context
from open_webui.models.groups import Groups
from open_webui.models.users import Users, UserResponse

from pydantic import BaseModel, ConfigDict
from sqlalchemy import BigInteger, Column, String, Text, JSON

from open_webui.crypto_exceptions import CryptoPolicyError
from open_webui.utils.access_control import has_access
from open_webui.utils.db.access_control import has_permission

####################
# Prompts DB Schema
####################


class Prompt(Base):
    __tablename__ = "prompt"

    command = Column(String, primary_key=True)
    user_id = Column(String)
    title = Column(Text)
    content = Column(Text)
    timestamp = Column(BigInteger)

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


class PromptModel(BaseModel):
    command: str
    user_id: str
    title: str
    content: str
    timestamp: int  # timestamp in epoch

    access_control: Optional[dict] = None
    model_config = ConfigDict(from_attributes=True)


####################
# Forms
####################


class PromptUserResponse(PromptModel):
    user: Optional[UserResponse] = None


class PromptAccessResponse(PromptUserResponse):
    write_access: Optional[bool] = False


class PromptForm(BaseModel):
    command: str
    title: str
    content: str
    access_control: Optional[dict] = None


class PromptsTable:
    def insert_new_prompt(
        self, user_id: str, form_data: PromptForm, db: Optional[Session] = None
    ) -> Optional[PromptModel]:
        prompt = PromptModel(
            **{
                "user_id": user_id,
                **form_data.model_dump(),
                "timestamp": int(time.time()),
            }
        )

        try:
            with get_db_context(db) as db:
                result = Prompt(**prompt.model_dump())
                db.add(result)
                db.commit()
                db.refresh(result)
                if result:
                    return PromptModel.model_validate(result)
                else:
                    return None
        except CryptoPolicyError:
            # A refused audience is an answer for the caller, not a failure to
            # write, so it must not be flattened into None here.
            raise
        except Exception:
            return None

    def get_prompt_by_command(
        self, command: str, db: Optional[Session] = None
    ) -> Optional[PromptModel]:
        try:
            with get_db_context(db) as db:
                prompt = db.query(Prompt).filter_by(command=command).first()
                return PromptModel.model_validate(prompt)
        except Exception:
            return None

    def get_prompts_by_user_id(
        self, user_id: str, permission: str = "write", db: Optional[Session] = None
    ) -> list[PromptUserResponse]:
        """Every prompt this person may open, at this permission.

        Narrowed in SQL rather than after loading: a prompt is decrypted as it
        is read, so loading one whose key this person does not hold would raise
        rather than simply be filtered out.
        """
        with get_db_context(db) as db:
            filter = {"user_id": user_id}
            groups = Groups.get_groups_by_member_id(user_id, db=db)
            if groups:
                filter["group_ids"] = [group.id for group in groups]

            query = has_permission(
                db, Prompt, db.query(Prompt), filter, permission
            ).order_by(Prompt.timestamp.desc())

            rows = query.all()
            user_ids = list({row.user_id for row in rows})
            users = {
                user.id: user
                for user in (
                    Users.get_users_by_user_ids(user_ids, db=db) if user_ids else []
                )
            }

            return [
                PromptUserResponse.model_validate(
                    {
                        **PromptModel.model_validate(row).model_dump(),
                        "user": (
                            users[row.user_id].model_dump()
                            if row.user_id in users
                            else None
                        ),
                    }
                )
                for row in rows
            ]

    def update_prompt_by_command(
        self, command: str, form_data: PromptForm, db: Optional[Session] = None
    ) -> Optional[PromptModel]:
        try:
            with get_db_context(db) as db:
                prompt = db.query(Prompt).filter_by(command=command).first()
                prompt.title = form_data.title
                prompt.content = form_data.content
                prompt.access_control = form_data.access_control
                prompt.timestamp = int(time.time())
                db.commit()
                return PromptModel.model_validate(prompt)
        except CryptoPolicyError:
            raise
        except Exception:
            return None

    def delete_prompt_by_command(
        self, command: str, db: Optional[Session] = None
    ) -> bool:
        # Deleting does not need the contents, so it must not need the key. See
        # Knowledges.delete_knowledge_by_id for why the import is not at the top.
        from open_webui.utils.encrypted_models import delete_without_reading

        try:
            with get_db_context(db) as db:
                delete_without_reading(db, Prompt, [command])
                db.commit()

                return True
        except Exception:
            return False


Prompts = PromptsTable()
