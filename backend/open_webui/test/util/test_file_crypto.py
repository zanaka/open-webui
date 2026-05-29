import io
import time

import pytest

from open_webui.utils import crypto_context
from open_webui.utils.crypto_context import cache_dek
from open_webui.utils.crypto_utils import FILE_MAGIC, generate_dek
from open_webui.utils.file_crypto import (
    decrypted_file_path,
    read_decrypted_file,
    store_encrypted_upload,
)


USER_ID = "test-user"
FILE_ID = "file-1"


class _File:
    id = FILE_ID
    user_id = USER_ID
    filename = "report.txt"
    meta = {"content_type": "text/plain"}

    def __init__(self, path):
        self.path = path


@pytest.fixture(autouse=True)
def _isolate_dek_cache():
    crypto_context._dek_cache.clear()
    yield
    crypto_context._dek_cache.clear()


@pytest.fixture
def dek():
    key = generate_dek()
    cache_dek(USER_ID, key, jti="jti-1", expires_at=time.time() + 3600)
    return key


def test_store_encrypted_upload_writes_opaque_encrypted_file(tmp_path, monkeypatch, dek):
    monkeypatch.setattr("open_webui.utils.file_crypto.STORAGE_PROVIDER", "local")
    monkeypatch.setattr("open_webui.utils.file_crypto.UPLOAD_DIR", tmp_path)

    size, path = store_encrypted_upload(
        io.BytesIO(b"plain report"),
        user_id=USER_ID,
        file_id=FILE_ID,
    )

    assert size == len(b"plain report")
    assert path == str(tmp_path / FILE_ID)
    raw = (tmp_path / FILE_ID).read_bytes()
    assert raw.startswith(FILE_MAGIC)
    assert b"plain report" not in raw

    assert read_decrypted_file(_File(path)) == b"plain report"


def test_decrypted_file_path_creates_temporary_plaintext_file(tmp_path, monkeypatch, dek):
    monkeypatch.setattr("open_webui.utils.file_crypto.STORAGE_PROVIDER", "local")
    monkeypatch.setattr("open_webui.utils.file_crypto.UPLOAD_DIR", tmp_path)

    _, path = store_encrypted_upload(
        io.BytesIO(b"temporary plaintext"),
        user_id=USER_ID,
        file_id=FILE_ID,
    )

    with decrypted_file_path(_File(path)) as plaintext_path:
        with open(plaintext_path, "rb") as f:
            assert f.read() == b"temporary plaintext"


def test_empty_upload_is_rejected_and_removed(tmp_path, monkeypatch, dek):
    monkeypatch.setattr("open_webui.utils.file_crypto.STORAGE_PROVIDER", "local")
    monkeypatch.setattr("open_webui.utils.file_crypto.UPLOAD_DIR", tmp_path)

    with pytest.raises(ValueError):
        store_encrypted_upload(
            io.BytesIO(b""),
            user_id=USER_ID,
            file_id=FILE_ID,
        )

    assert not (tmp_path / FILE_ID).exists()
