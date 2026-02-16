import os
import base64
import json
import logging
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

log = logging.getLogger(__name__)

NONCE_SIZE = 12   # 96 bits for AES-GCM
DEK_SIZE = 32     # 256 bits
KDF_SALT_SIZE = 16  # 128 bits (RFC 9106)

# Argon2id parameters (RFC 9106 first recommendation: time=1, memory=2GiB, parallelism=4)
ARGON2_TIME_COST = 1
ARGON2_MEMORY_COST = 2097152  # 2 GiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32  # 256 bits

# Magic prefix to distinguish encrypted data from plaintext JSON
ENCRYPTED_PREFIX = b"$ENC$"


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
    return ENCRYPTED_PREFIX + nonce + ciphertext


def decrypt_value(encrypted_bytes: bytes, dek: bytes) -> bytes:
    if not encrypted_bytes.startswith(ENCRYPTED_PREFIX):
        raise ValueError("Data is not encrypted (missing prefix)")
    data = encrypted_bytes[len(ENCRYPTED_PREFIX):]
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    aesgcm = AESGCM(dek)
    return aesgcm.decrypt(nonce, ciphertext, None)


def is_encrypted(value: str) -> bool:
    try:
        raw = base64.b64decode(value)
        return raw.startswith(ENCRYPTED_PREFIX)
    except Exception:
        return False
