import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from fastapi.responses import StreamingResponse

from open_webui.config import STORAGE_PROVIDER, UPLOAD_DIR
from open_webui.constants import ERROR_MESSAGES
from open_webui.storage.provider import Storage
from open_webui.utils.crypto_context import require_cached_dek
from open_webui.utils.crypto_utils import (
    iter_decrypt_file,
    stream_decrypt_file_to_path,
    stream_encrypt_file,
)


def store_encrypted_upload(source, *, user_id: str, file_id: str) -> tuple[int, str]:
    if STORAGE_PROVIDER != "local":
        raise RuntimeError("Encrypted file upload currently supports local storage only")

    dek = require_cached_dek(user_id)
    destination_path = Path(UPLOAD_DIR) / file_id
    size = stream_encrypt_file(
        source,
        destination_path,
        dek,
        user_id=user_id,
        file_id=file_id,
    )
    if size == 0:
        destination_path.unlink(missing_ok=True)
        raise ValueError(ERROR_MESSAGES.EMPTY_CONTENT)

    return size, str(destination_path)


def get_encrypted_file_path(file) -> Path:
    file_path = Path(Storage.get_file(file.path))
    if not file_path.is_file():
        raise FileNotFoundError(file_path)
    return file_path


def iter_decrypted_file(file) -> Iterator[bytes]:
    dek = require_cached_dek(file.user_id)
    yield from iter_decrypt_file(
        get_encrypted_file_path(file),
        dek,
        user_id=file.user_id,
        file_id=file.id,
    )


def read_decrypted_file(file) -> bytes:
    return b"".join(iter_decrypted_file(file))


def decrypt_file_to_path(file, destination_path: str | Path) -> int:
    dek = require_cached_dek(file.user_id)
    return stream_decrypt_file_to_path(
        get_encrypted_file_path(file),
        destination_path,
        dek,
        user_id=file.user_id,
        file_id=file.id,
    )


@contextmanager
def decrypted_file_path(file) -> Iterator[str]:
    suffix = Path(file.filename or "").suffix
    temp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    temp_path = temp.name
    temp.close()

    try:
        decrypt_file_to_path(file, temp_path)
        yield temp_path
    finally:
        Path(temp_path).unlink(missing_ok=True)


class DecryptedFileResponse(StreamingResponse):
    def __init__(self, file, *, headers=None, media_type=None):
        # Check the encrypted path before the response starts so missing files
        # become normal HTTP errors in the route handler.
        get_encrypted_file_path(file)
        require_cached_dek(file.user_id)
        super().__init__(
            iter_decrypted_file(file),
            headers=headers,
            media_type=media_type,
        )
