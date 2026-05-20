import os
import base64
import json
import struct
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

NONCE_SIZE = 12     # 96 bits for AES-GCM
DEK_SIZE = 32       # 256 bits
KDF_SALT_SIZE = 16  # 128 bits (RFC 9106)

# Argon2id parameters (RFC 9106 first recommendation: time=1, memory=2GiB, parallelism=4)
ARGON2_TIME_COST = 1
ARGON2_MEMORY_COST = 2097152  # 2 GiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32  # 256 bits
ENCRYPTED_VALUE_PREFIX = "owenc:v1:"
FILE_MAGIC = b"OWUIFILEENC1\n"
FILE_CHUNK_SIZE = 64 * 1024


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


def is_encrypted_value(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(ENCRYPTED_VALUE_PREFIX)


def encrypt_text(value: str | None, dek: bytes) -> str | None:
    if value is None or is_encrypted_value(value):
        return value
    encrypted = encrypt_value(value.encode("utf-8"), dek)
    return ENCRYPTED_VALUE_PREFIX + base64.b64encode(encrypted).decode("ascii")


def decrypt_text(value: str | None, dek: bytes) -> str | None:
    if value is None or not is_encrypted_value(value):
        return value
    payload = base64.b64decode(value[len(ENCRYPTED_VALUE_PREFIX) :])
    return decrypt_value(payload, dek).decode("utf-8")


def encrypt_json_value(value: Any, dek: bytes) -> str:
    if is_encrypted_value(value):
        return value
    plaintext = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    encrypted = encrypt_value(plaintext, dek)
    return ENCRYPTED_VALUE_PREFIX + base64.b64encode(encrypted).decode("ascii")


def decrypt_json_value(value: Any, dek: bytes) -> Any:
    if not is_encrypted_value(value):
        return value
    payload = base64.b64decode(value[len(ENCRYPTED_VALUE_PREFIX) :])
    plaintext = decrypt_value(payload, dek)
    return json.loads(plaintext.decode("utf-8"))


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
    destination_path = Path(destination_path)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    total_size = 0
    chunk_index = 0

    try:
        with destination_path.open("wb") as output:
            output.write(FILE_MAGIC)
            current = source.read(chunk_size)
            if current == b"":
                raise ValueError("Empty file")

            while current:
                next_chunk = source.read(chunk_size)
                final = next_chunk == b""
                nonce = os.urandom(NONCE_SIZE)
                ciphertext = AESGCM(dek).encrypt(
                    nonce,
                    current,
                    _file_aad(user_id, file_id, chunk_index, final),
                )
                output.write(struct.pack(">I", len(ciphertext)))
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


def stream_decrypt_file_to_path(
    source_path: str | Path,
    destination_path: str | Path,
    dek: bytes,
    *,
    user_id: str,
    file_id: str,
) -> int:
    source_path = Path(source_path)
    destination_path = Path(destination_path)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    total_size = 0
    chunk_index = 0
    saw_final = False

    try:
        with source_path.open("rb") as source, destination_path.open("wb") as output:
            if source.read(len(FILE_MAGIC)) != FILE_MAGIC:
                raise ValueError("Invalid encrypted file")

            while True:
                length_bytes = source.read(4)
                if length_bytes == b"":
                    break
                if len(length_bytes) != 4:
                    raise ValueError("Invalid encrypted file chunk header")

                ciphertext_len = struct.unpack(">I", length_bytes)[0]
                final_flag = source.read(1)
                nonce = source.read(NONCE_SIZE)
                ciphertext = source.read(ciphertext_len)

                if (
                    len(final_flag) != 1
                    or len(nonce) != NONCE_SIZE
                    or len(ciphertext) != ciphertext_len
                ):
                    raise ValueError("Invalid encrypted file chunk")

                final = final_flag == b"\x01"
                plaintext = AESGCM(dek).decrypt(
                    nonce,
                    ciphertext,
                    _file_aad(user_id, file_id, chunk_index, final),
                )
                output.write(plaintext)
                total_size += len(plaintext)

                if final:
                    if source.read(1) != b"":
                        raise ValueError(
                            "Unexpected data after final encrypted file chunk"
                        )
                    saw_final = True
                    break

                chunk_index += 1

            if not saw_final:
                raise ValueError("Encrypted file is missing final chunk")
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
    source_path = Path(source_path)
    chunk_index = 0
    saw_final = False

    with source_path.open("rb") as source:
        if source.read(len(FILE_MAGIC)) != FILE_MAGIC:
            raise ValueError("Invalid encrypted file")

        while True:
            length_bytes = source.read(4)
            if length_bytes == b"":
                break
            if len(length_bytes) != 4:
                raise ValueError("Invalid encrypted file chunk header")

            ciphertext_len = struct.unpack(">I", length_bytes)[0]
            final_flag = source.read(1)
            nonce = source.read(NONCE_SIZE)
            ciphertext = source.read(ciphertext_len)

            if (
                len(final_flag) != 1
                or len(nonce) != NONCE_SIZE
                or len(ciphertext) != ciphertext_len
            ):
                raise ValueError("Invalid encrypted file chunk")

            final = final_flag == b"\x01"
            plaintext = AESGCM(dek).decrypt(
                nonce,
                ciphertext,
                _file_aad(user_id, file_id, chunk_index, final),
            )
            yield plaintext

            if final:
                if source.read(1) != b"":
                    raise ValueError(
                        "Unexpected data after final encrypted file chunk"
                    )
                saw_final = True
                break

            chunk_index += 1

        if not saw_final:
            raise ValueError("Encrypted file is missing final chunk")
