import os
import base64
import json
import logging
from typing import Any, Optional

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
