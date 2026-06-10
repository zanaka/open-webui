import pytest
from cryptography.exceptions import InvalidTag

from argon2.low_level import Type, hash_secret_raw

from open_webui.utils import crypto_utils
from open_webui.utils.crypto_utils import (
    DEK_SIZE,
    KDF_SALT_SIZE,
    NONCE_SIZE,
    decrypt_value,
    derive_kek,
    encrypt_value,
    generate_dek,
    generate_kdf_salt,
    unwrap_dek,
    wrap_dek,
)


# ---------------------------------------------------------------------------
# CSPRNG key / salt generation
# ---------------------------------------------------------------------------


class TestGenerateDek:
    def test_length_is_256_bits(self):
        assert len(generate_dek()) == DEK_SIZE == 32

    def test_returns_bytes(self):
        assert isinstance(generate_dek(), bytes)

    def test_unique_across_calls(self):
        keys = {generate_dek() for _ in range(100)}
        assert len(keys) == 100


class TestGenerateKdfSalt:
    def test_length_is_128_bits(self):
        assert len(generate_kdf_salt()) == KDF_SALT_SIZE == 16

    def test_returns_bytes(self):
        assert isinstance(generate_kdf_salt(), bytes)

    def test_unique_across_calls(self):
        salts = {generate_kdf_salt() for _ in range(100)}
        assert len(salts) == 100


# ---------------------------------------------------------------------------
# Argon2id key derivation (KEK)
# ---------------------------------------------------------------------------

_PASSWORD = "correct horse battery staple"
_SALT = b"0123456789abcdef"  # fixed 16-byte salt for deterministic checks


@pytest.fixture(scope="module")
def baseline_kek() -> bytes:
    return derive_kek(_PASSWORD, _SALT)


class TestDeriveKek:
    def test_output_length_is_256_bits(self, baseline_kek):
        assert len(baseline_kek) == 32

    def test_returns_bytes(self, baseline_kek):
        assert isinstance(baseline_kek, bytes)

    def test_deterministic_for_same_password_and_salt(self, baseline_kek):
        # Same inputs must reproduce the same KEK, otherwise login (DEK unwrap)
        # would break after the wrapping derivation.
        assert derive_kek(_PASSWORD, _SALT) == baseline_kek

    def test_different_salt_yields_different_kek(self, baseline_kek):
        other = derive_kek(_PASSWORD, b"fedcba9876543210")
        assert other != baseline_kek

    def test_different_password_yields_different_kek(self, baseline_kek):
        other = derive_kek("a different password", _SALT)
        assert other != baseline_kek

    def test_matches_argon2id_with_module_parameters(self, baseline_kek):
        # Pin the algorithm + parameters: derive_kek must equal a direct
        # Argon2id call using the module's published constants. This guards
        # against silent parameter drift (which would invalidate stored DEKs).
        expected = hash_secret_raw(
            secret=_PASSWORD.encode("utf-8"),
            salt=_SALT,
            time_cost=crypto_utils.ARGON2_TIME_COST,
            memory_cost=crypto_utils.ARGON2_MEMORY_COST,
            parallelism=crypto_utils.ARGON2_PARALLELISM,
            hash_len=crypto_utils.ARGON2_HASH_LEN,
            type=Type.ID,
        )
        assert baseline_kek == expected

    def test_parameters_match_rfc9106_first_recommendation(self):
        # Cheap assertion (no derivation): RFC 9106 §4 first recommendation.
        assert crypto_utils.ARGON2_TIME_COST == 1
        assert crypto_utils.ARGON2_MEMORY_COST == 2097152  # 2 GiB in KiB
        assert crypto_utils.ARGON2_PARALLELISM == 4
        assert crypto_utils.ARGON2_HASH_LEN == 32


# ---------------------------------------------------------------------------
# DEK wrapping (AES-GCM, KEK as key)
# ---------------------------------------------------------------------------


@pytest.fixture
def kek() -> bytes:
    return generate_dek()


class TestWrapDek:
    def test_roundtrip(self, kek):
        dek = generate_dek()
        assert unwrap_dek(wrap_dek(dek, kek), kek) == dek

    def test_output_is_nonce_prefixed(self, kek):
        dek = generate_dek()
        wrapped = wrap_dek(dek, kek)
        # nonce + ciphertext + 16-byte GCM tag
        assert len(wrapped) == NONCE_SIZE + DEK_SIZE + 16

    def test_fresh_nonce_per_call(self, kek):
        dek = generate_dek()
        a = wrap_dek(dek, kek)
        b = wrap_dek(dek, kek)
        # Different nonce → different ciphertext, and nonces must not repeat.
        assert a != b
        assert a[:NONCE_SIZE] != b[:NONCE_SIZE]

    def test_wrong_kek_raises(self, kek):
        wrapped = wrap_dek(generate_dek(), kek)
        with pytest.raises(InvalidTag):
            unwrap_dek(wrapped, generate_dek())

    def test_tampered_ciphertext_raises(self, kek):
        wrapped = bytearray(wrap_dek(generate_dek(), kek))
        wrapped[-1] ^= 0x01  # flip a tag bit
        with pytest.raises(InvalidTag):
            unwrap_dek(bytes(wrapped), kek)

    def test_tampered_nonce_raises(self, kek):
        wrapped = bytearray(wrap_dek(generate_dek(), kek))
        wrapped[0] ^= 0x01  # corrupt the nonce
        with pytest.raises(InvalidTag):
            unwrap_dek(bytes(wrapped), kek)


# ---------------------------------------------------------------------------
# Low-level AES-GCM value encryption
# ---------------------------------------------------------------------------


class TestEncryptValue:
    def test_roundtrip(self, kek):
        plaintext = b"some raw secret bytes \x00\x01\xff"
        assert decrypt_value(encrypt_value(plaintext, kek), kek) == plaintext

    def test_roundtrip_empty_bytes(self, kek):
        assert decrypt_value(encrypt_value(b"", kek), kek) == b""

    def test_output_is_nonce_prefixed(self, kek):
        ciphertext = encrypt_value(b"abc", kek)
        # nonce + ciphertext(len 3) + 16-byte tag
        assert len(ciphertext) == NONCE_SIZE + 3 + 16
        assert len(ciphertext[:NONCE_SIZE]) == NONCE_SIZE

    def test_fresh_nonce_per_call(self, kek):
        a = encrypt_value(b"abc", kek)
        b = encrypt_value(b"abc", kek)
        assert a != b
        assert a[:NONCE_SIZE] != b[:NONCE_SIZE]

    def test_wrong_dek_raises(self, kek):
        encrypted = encrypt_value(b"abc", kek)
        with pytest.raises(InvalidTag):
            decrypt_value(encrypted, generate_dek())

    def test_tampered_ciphertext_raises(self, kek):
        encrypted = bytearray(encrypt_value(b"abc", kek))
        encrypted[-1] ^= 0x01
        with pytest.raises(InvalidTag):
            decrypt_value(bytes(encrypted), kek)
