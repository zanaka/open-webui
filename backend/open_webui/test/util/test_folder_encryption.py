import time

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from open_webui.internal import db as internal_db
from open_webui.internal.db import Base
from open_webui.models.folders import Folder, FolderForm, FolderUpdateForm, Folders
from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek, set_current_user_id
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.encrypted_models import install

install()

USER_ID = "folder-user"


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(internal_db, "DATABASE_ENABLE_SESSION_SHARING", True)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[Folder.__table__])
    session = sessionmaker(bind=engine)()

    cache_dek(USER_ID, generate_dek(), jti="jti-1", expires_at=time.time() + 3600)
    set_current_user_id(USER_ID)

    yield session

    set_current_user_id(None)
    session.close()
    engine.dispose()
    crypto_context._dek_cache.clear()


def _add(db, name):
    return Folders.insert_new_folder(USER_ID, FolderForm(name=name), db=db)


def _raw_names(db):
    return [row[0] for row in db.execute(text("SELECT name FROM folder")).all()]


class TestAtRest:
    def test_name_is_ciphertext(self, db):
        _add(db, "Project Falcon")

        assert "Falcon" not in " ".join(_raw_names(db))

    def test_round_trips(self, db):
        created = _add(db, "Project Falcon")

        assert created.name == "Project Falcon"
        assert Folders.get_folder_by_id_and_user_id(created.id, USER_ID, db=db).name == (
            "Project Falcon"
        )


class TestLookupByName:
    """The name column can no longer be matched in SQL, so this compares
    decrypted names instead."""

    def test_finds_the_folder(self, db):
        created = _add(db, "Project Falcon")
        _add(db, "Something Else")

        found = Folders.get_folder_by_parent_id_and_user_id_and_name(
            None, USER_ID, "Project Falcon", db=db
        )

        assert found.id == created.id

    def test_is_case_insensitive(self, db):
        created = _add(db, "Project Falcon")

        found = Folders.get_folder_by_parent_id_and_user_id_and_name(
            None, USER_ID, "project falcon", db=db
        )

        assert found.id == created.id

    def test_returns_nothing_for_an_unknown_name(self, db):
        _add(db, "Project Falcon")

        assert (
            Folders.get_folder_by_parent_id_and_user_id_and_name(
                None, USER_ID, "No Such Folder", db=db
            )
            is None
        )


class TestRenameCollision:
    def test_rename_onto_a_sibling_is_refused(self, db):
        _add(db, "Project Falcon")
        other = _add(db, "Something Else")

        result = Folders.update_folder_by_id_and_user_id(
            other.id, USER_ID, FolderUpdateForm(name="Project Falcon"), db=db
        )

        assert result is None

    def test_renaming_to_a_free_name_works(self, db):
        folder = _add(db, "Project Falcon")

        result = Folders.update_folder_by_id_and_user_id(
            folder.id, USER_ID, FolderUpdateForm(name="Project Condor"), db=db
        )

        assert result.name == "Project Condor"
        assert "Condor" not in " ".join(_raw_names(db))

    def test_keeping_its_own_name_is_allowed(self, db):
        folder = _add(db, "Project Falcon")

        result = Folders.update_folder_by_id_and_user_id(
            folder.id, USER_ID, FolderUpdateForm(name="Project Falcon"), db=db
        )

        assert result is not None

    def test_updating_only_data_leaves_the_name_alone(self, db):
        folder = _add(db, "Project Falcon")

        result = Folders.update_folder_by_id_and_user_id(
            folder.id, USER_ID, FolderUpdateForm(data={"colour": "red"}), db=db
        )

        assert result.name == "Project Falcon"
        assert result.data == {"colour": "red"}


class TestSearch:
    def test_exact_name_search_matches_decrypted_names(self, db):
        created = _add(db, "Project Falcon")
        _add(db, "Something Else")

        found = Folders.search_folders_by_names(USER_ID, ["project falcon"], db=db)

        assert [folder.id for folder in found] == [created.id]

    def test_partial_name_search_matches_decrypted_names(self, db):
        created = _add(db, "Project Falcon")
        _add(db, "Something Else")

        found = Folders.search_folders_by_name_contains(USER_ID, "falcon", db=db)

        assert [folder.id for folder in found] == [created.id]
