import os
import base64
import json
import logging
import struct
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

log = logging.getLogger(__name__)

NONCE_SIZE = 12     # 96 bits for AES-GCM
DEK_SIZE = 32       # 256 bits
KDF_SALT_SIZE = 16  # 128 bits (RFC 9106)

# Argon2id parameters (RFC 9106 first recommendation: time=1, memory=2GiB, parallelism=4)
ARGON2_TIME_COST = 1
ARGON2_MEMORY_COST = 2097152  # 2 GiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32  # 256 bits

# Chunked file encryption format
FILE_MAGIC = b"OWUIFILEENC1\n"
FILE_CHUNK_SIZE = 64 * 1024  # 64 KiB plaintext per chunk
_CHUNK_LEN_HEADER = struct.Struct(">I")  # 4-byte big-endian ciphertext length


def generate_dek() -> bytes:
    return os.urandom(DEK_SIZE)


def generate_kdf_salt() -> bytes:
    return os.urandom(KDF_SALT_SIZE)


def derive_kek(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def wrap_dek(dek: bytes, kek: bytes) -> bytes:
    aesgcm = AESGCM(kek)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, dek, None)
    return nonce + ciphertext


def unwrap_dek(wrapped_dek: bytes, kek: bytes) -> bytes:
    aesgcm = AESGCM(kek)
    nonce = wrapped_dek[:NONCE_SIZE]
    ciphertext = wrapped_dek[NONCE_SIZE:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_value(plaintext_bytes: bytes, dek: bytes) -> bytes:
    aesgcm = AESGCM(dek)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce + ciphertext


def decrypt_value(encrypted_bytes: bytes, dek: bytes) -> bytes:
    nonce = encrypted_bytes[:NONCE_SIZE]
    ciphertext = encrypted_bytes[NONCE_SIZE:]
    aesgcm = AESGCM(dek)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_text(value: Optional[str], dek: bytes) -> Optional[str]:
    if value is None:
        return None
    encrypted = encrypt_value(value.encode("utf-8"), dek)
    return base64.b64encode(encrypted).decode("ascii")


def decrypt_text(value: Optional[str], dek: bytes) -> Optional[str]:
    if value is None:
        return None
    encrypted = base64.b64decode(value)
    return decrypt_value(encrypted, dek).decode("utf-8")


def encrypt_json_value(value: Any, dek: bytes) -> Optional[str]:
    if value is None:
        return None
    plaintext = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    encrypted = encrypt_value(plaintext, dek)
    return base64.b64encode(encrypted).decode("ascii")


def decrypt_json_value(value: Optional[str], dek: bytes) -> Any:
    if value is None:
        return None
    encrypted = base64.b64decode(value)
    plaintext = decrypt_value(encrypted, dek)
    return json.loads(plaintext.decode("utf-8"))


# ---------------------------------------------------------------------------
# Chunked file encryption
#
# File layout:
#   [FILE_MAGIC]
#   <chunk>+
#
# Per chunk:
#   [4-byte BE ciphertext length][1-byte final flag][12-byte nonce][ciphertext]
#
# AAD per chunk binds user_id, file_id, chunk_index, and the final flag, so
# truncation, reordering, and cross-file/user swap all fail at the GCM tag
# check. An empty input still produces one final chunk with 0-byte plaintext.
# ---------------------------------------------------------------------------


def _file_aad(user_id: str, file_id: str, chunk_index: int, final: bool) -> bytes:
    return f"owui-file-v1:{user_id}:{file_id}:{chunk_index}:{int(final)}".encode(
        "utf-8"
    )


def stream_encrypt_file(
    source: BinaryIO,
    destination_path: str | Path,
    dek: bytes,
    *,
    user_id: str,
    file_id: str,
    chunk_size: int = FILE_CHUNK_SIZE,
) -> int:
    """Encrypt `source` into `destination_path` in chunks. Returns plaintext byte count."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than 0")

    destination_path = Path(destination_path)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    aesgcm = AESGCM(dek)
    total_size = 0
    chunk_index = 0

    try:
        with destination_path.open("wb") as output:
            output.write(FILE_MAGIC)
            current = source.read(chunk_size)
            while True:
                next_chunk = source.read(chunk_size)
                final = next_chunk == b""
                nonce = os.urandom(NONCE_SIZE)
                ciphertext = aesgcm.encrypt(
                    nonce,
                    current,
                    _file_aad(user_id, file_id, chunk_index, final),
                )
                output.write(_CHUNK_LEN_HEADER.pack(len(ciphertext)))
                output.write(bytes([1 if final else 0]))
                output.write(nonce)
                output.write(ciphertext)
                total_size += len(current)
                if final:
                    break
                current = next_chunk
                chunk_index += 1
    except Exception:
        try:
            destination_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise

    return total_size


def _read_exact(source: BinaryIO, n: int) -> bytes:
    data = source.read(n)
    if len(data) != n:
        raise ValueError("Invalid encrypted file: unexpected EOF")
    return data


def _iter_chunks(
    source: BinaryIO, dek: bytes, *, user_id: str, file_id: str
) -> Iterator[bytes]:
    if source.read(len(FILE_MAGIC)) != FILE_MAGIC:
        raise ValueError("Invalid encrypted file: bad magic header")

    aesgcm = AESGCM(dek)
    chunk_index = 0
    saw_final = False

    while True:
        length_bytes = source.read(_CHUNK_LEN_HEADER.size)
        if length_bytes == b"":
            break
        if len(length_bytes) != _CHUNK_LEN_HEADER.size:
            raise ValueError("Invalid encrypted file: truncated chunk header")

        ciphertext_len = _CHUNK_LEN_HEADER.unpack(length_bytes)[0]
        final_flag = _read_exact(source, 1)
        if final_flag not in (b"\x00", b"\x01"):
            raise ValueError("Invalid encrypted file: bad final flag")
        nonce = _read_exact(source, NONCE_SIZE)
        ciphertext = _read_exact(source, ciphertext_len)

        final = final_flag == b"\x01"
        plaintext = aesgcm.decrypt(
            nonce,
            ciphertext,
            _file_aad(user_id, file_id, chunk_index, final),
        )
        yield plaintext

        if final:
            if source.read(1) != b"":
                raise ValueError("Unexpected data after final encrypted chunk")
            saw_final = True
            break
        chunk_index += 1

    if not saw_final:
        raise ValueError("Encrypted file is missing final chunk")


def stream_decrypt_file_to_path(
    source_path: str | Path,
    destination_path: str | Path,
    dek: bytes,
    *,
    user_id: str,
    file_id: str,
) -> int:
    """Decrypt `source_path` into `destination_path`. Returns plaintext byte count."""
    source_path = Path(source_path)
    destination_path = Path(destination_path)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    total_size = 0

    try:
        with source_path.open("rb") as source, destination_path.open("wb") as output:
            for plaintext in _iter_chunks(
                source, dek, user_id=user_id, file_id=file_id
            ):
                output.write(plaintext)
                total_size += len(plaintext)
    except Exception:
        try:
            destination_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise

    return total_size


def iter_decrypt_file(
    source_path: str | Path,
    dek: bytes,
    *,
    user_id: str,
    file_id: str,
) -> Iterator[bytes]:
    """Yield decrypted plaintext chunks from `source_path`."""
    source_path = Path(source_path)
    with source_path.open("rb") as source:
        yield from _iter_chunks(source, dek, user_id=user_id, file_id=file_id)
