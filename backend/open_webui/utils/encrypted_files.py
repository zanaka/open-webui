import os
import tempfile
from pathlib import Path

from open_webui.storage.provider import Storage
from open_webui.utils.crypto_context import require_cached_dek
from open_webui.utils.crypto_utils import (
    iter_decrypt_file,
    stream_decrypt_file_to_path,
)


def _get_file_attr(file, name: str):
    if isinstance(file, dict):
        return file.get(name)
    return getattr(file, name)


def _get_file_dek(file) -> bytes:
    user_id = _get_file_attr(file, "user_id")
    return require_cached_dek(user_id)


def get_encrypted_file_path(file) -> Path:
    encrypted_path = Path(Storage.get_file(_get_file_attr(file, "path")))
    if not encrypted_path.is_file():
        raise FileNotFoundError(encrypted_path)
    return encrypted_path


def decrypt_file_to_temp(file) -> str:
    encrypted_path = get_encrypted_file_path(file)
    user_id = _get_file_attr(file, "user_id")
    file_id = _get_file_attr(file, "id")
    dek = _get_file_dek(file)

    fd, temp_path = tempfile.mkstemp(prefix=f"{file_id}_", suffix=".dec")
    os.close(fd)

    stream_decrypt_file_to_path(
        encrypted_path,
        temp_path,
        dek,
        user_id=user_id,
        file_id=file_id,
    )
    return temp_path


def iter_decrypted_file(file, encrypted_path: str | Path | None = None):
    encrypted_path = (
        Path(encrypted_path) if encrypted_path else get_encrypted_file_path(file)
    )
    user_id = _get_file_attr(file, "user_id")
    file_id = _get_file_attr(file, "id")
    dek = _get_file_dek(file)
    return iter_decrypt_file(
        encrypted_path,
        dek,
        user_id=user_id,
        file_id=file_id,
    )


def remove_temp_file(path: str | None) -> None:
    if not path:
        return
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
