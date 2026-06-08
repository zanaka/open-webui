import io
import os

import pytest
from cryptography.exceptions import InvalidTag

from open_webui.utils.crypto_utils import (
    FILE_CHUNK_SIZE,
    FILE_MAGIC,
    NONCE_SIZE,
    generate_dek,
    iter_decrypt_file,
    stream_decrypt_file_to_path,
    stream_encrypt_file,
)


@pytest.fixture
def dek() -> bytes:
    return generate_dek()


def _encrypt(plaintext: bytes, dek: bytes, dst, *, user_id="u1", file_id="f1", chunk_size=16) -> int:
    return stream_encrypt_file(
        io.BytesIO(plaintext),
        dst,
        dek,
        user_id=user_id,
        file_id=file_id,
        chunk_size=chunk_size,
    )


def _decrypt_to_bytes(src, dek: bytes, *, user_id="u1", file_id="f1") -> bytes:
    return b"".join(iter_decrypt_file(src, dek, user_id=user_id, file_id=file_id))


class TestRoundtrip:
    @pytest.mark.parametrize(
        "size",
        [
            0,           # empty
            1,           # tiny
            15,          # less than chunk_size (=16 in tests)
            16,          # exactly chunk_size
            17,          # chunk_size + 1
            32,          # exactly 2*chunk_size
            33,          # 2*chunk_size + 1
            1024,        # many chunks
        ],
    )
    def test_roundtrip_to_path(self, dek, tmp_path, size):
        plaintext = os.urandom(size)
        encrypted = tmp_path / "enc.bin"
        decrypted = tmp_path / "dec.bin"

        written = _encrypt(plaintext, dek, encrypted)
        assert written == size

        read = stream_decrypt_file_to_path(
            encrypted, decrypted, dek, user_id="u1", file_id="f1"
        )
        assert read == size
        assert decrypted.read_bytes() == plaintext

    def test_iter_decrypt_yields_full_plaintext(self, dek, tmp_path):
        plaintext = os.urandom(40)
        encrypted = tmp_path / "enc.bin"
        _encrypt(plaintext, dek, encrypted)

        assert _decrypt_to_bytes(encrypted, dek) == plaintext

    def test_default_chunk_size_used_when_not_specified(self, dek, tmp_path):
        # Use the production chunk size (64 KiB) so one chunk holds the whole payload.
        plaintext = b"x" * (FILE_CHUNK_SIZE - 1)
        encrypted = tmp_path / "enc.bin"
        stream_encrypt_file(
            io.BytesIO(plaintext), encrypted, dek, user_id="u1", file_id="f1"
        )
        assert _decrypt_to_bytes(encrypted, dek) == plaintext

    def test_file_starts_with_magic(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"
        _encrypt(b"abc", dek, encrypted)
        assert encrypted.read_bytes().startswith(FILE_MAGIC)

    def test_nonce_is_fresh_per_chunk(self, dek, tmp_path):
        # Encrypt the same byte pattern twice; the on-disk bytes must differ.
        plaintext = b"a" * 100
        f1 = tmp_path / "1.bin"
        f2 = tmp_path / "2.bin"
        _encrypt(plaintext, dek, f1)
        _encrypt(plaintext, dek, f2)
        assert f1.read_bytes() != f2.read_bytes()


class TestTamperDetection:
    def test_wrong_dek_raises(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"
        _encrypt(b"hello world", dek, encrypted)

        with pytest.raises(InvalidTag):
            _decrypt_to_bytes(encrypted, generate_dek())

    def test_wrong_user_id_raises(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"
        _encrypt(b"hello world", dek, encrypted, user_id="alice")

        with pytest.raises(InvalidTag):
            _decrypt_to_bytes(encrypted, dek, user_id="bob")

    def test_wrong_file_id_raises(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"
        _encrypt(b"hello world", dek, encrypted, file_id="f1")

        with pytest.raises(InvalidTag):
            _decrypt_to_bytes(encrypted, dek, file_id="f2")

    def test_bad_magic_raises(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"
        _encrypt(b"hello world", dek, encrypted)
        raw = bytearray(encrypted.read_bytes())
        raw[0] ^= 0x01
        encrypted.write_bytes(bytes(raw))

        with pytest.raises(ValueError, match="bad magic"):
            _decrypt_to_bytes(encrypted, dek)

    def test_single_bit_flip_in_ciphertext_raises(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"
        _encrypt(b"hello world", dek, encrypted)
        raw = bytearray(encrypted.read_bytes())
        # Flip the last byte (part of the GCM tag).
        raw[-1] ^= 0x01
        encrypted.write_bytes(bytes(raw))

        with pytest.raises(InvalidTag):
            _decrypt_to_bytes(encrypted, dek)

    def test_bad_non_final_flag_raises(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"
        _encrypt(b"A" * 32, dek, encrypted, chunk_size=16)
        raw = bytearray(encrypted.read_bytes())
        first_flag_offset = len(FILE_MAGIC) + 4
        raw[first_flag_offset] = 2
        encrypted.write_bytes(bytes(raw))

        with pytest.raises(ValueError, match="bad final flag"):
            _decrypt_to_bytes(encrypted, dek)

    def test_truncated_after_non_final_chunk_raises(self, dek, tmp_path):
        # Three chunks of 16 bytes → write only the first.
        plaintext = b"A" * 16 + b"B" * 16 + b"C" * 16
        encrypted = tmp_path / "enc.bin"
        _encrypt(plaintext, dek, encrypted, chunk_size=16)

        raw = encrypted.read_bytes()
        # Locate the second chunk header and truncate the file there.
        first_chunk_size = (
            len(FILE_MAGIC) + 4 + 1 + NONCE_SIZE + (16 + 16)  # 16 plaintext + 16 GCM tag
        )
        encrypted.write_bytes(raw[:first_chunk_size])

        with pytest.raises(ValueError, match="missing final chunk"):
            _decrypt_to_bytes(encrypted, dek)

    def test_truncated_mid_chunk_raises(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"
        _encrypt(b"ABCDEFGHIJ" * 10, dek, encrypted, chunk_size=16)
        raw = encrypted.read_bytes()
        # Drop the last 4 bytes (truncates the tail of the final chunk).
        encrypted.write_bytes(raw[:-4])

        with pytest.raises(ValueError):
            _decrypt_to_bytes(encrypted, dek)

    def test_trailing_garbage_after_final_chunk_raises(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"
        _encrypt(b"hello", dek, encrypted)
        raw = encrypted.read_bytes()
        encrypted.write_bytes(raw + b"junk")

        with pytest.raises(ValueError, match="after final"):
            _decrypt_to_bytes(encrypted, dek)


class TestErrorCleanup:
    def test_rejects_non_positive_chunk_size(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"

        with pytest.raises(ValueError, match="chunk_size"):
            stream_encrypt_file(
                io.BytesIO(b"hello"),
                encrypted,
                dek,
                user_id="u1",
                file_id="f1",
                chunk_size=0,
            )

        assert not encrypted.exists()

    def test_destination_removed_on_encrypt_failure(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"

        class _Boom(io.BytesIO):
            def read(self, *_args, **_kwargs):
                raise IOError("source unreadable")

        with pytest.raises(IOError):
            stream_encrypt_file(
                _Boom(), encrypted, dek, user_id="u1", file_id="f1", chunk_size=16
            )

        assert not encrypted.exists()

    def test_destination_removed_on_decrypt_failure(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"
        _encrypt(b"hello", dek, encrypted)
        # Corrupt the tag so decryption fails after the file is opened.
        raw = bytearray(encrypted.read_bytes())
        raw[-1] ^= 0x01
        encrypted.write_bytes(bytes(raw))

        decrypted = tmp_path / "out" / "dec.bin"
        with pytest.raises(InvalidTag):
            stream_decrypt_file_to_path(
                encrypted, decrypted, dek, user_id="u1", file_id="f1"
            )

        assert not decrypted.exists()


class TestPathHandling:
    def test_encrypt_creates_parent_directory(self, dek, tmp_path):
        target = tmp_path / "a" / "b" / "c" / "enc.bin"
        _encrypt(b"hello", dek, target)
        assert target.exists()

    def test_decrypt_creates_parent_directory(self, dek, tmp_path):
        encrypted = tmp_path / "enc.bin"
        _encrypt(b"hello", dek, encrypted)
        target = tmp_path / "x" / "y" / "dec.bin"
        stream_decrypt_file_to_path(
            encrypted, target, dek, user_id="u1", file_id="f1"
        )
        assert target.read_bytes() == b"hello"

    def test_accepts_str_paths(self, dek, tmp_path):
        encrypted = str(tmp_path / "enc.bin")
        decrypted = str(tmp_path / "dec.bin")
        _encrypt(b"hello", dek, encrypted)
        stream_decrypt_file_to_path(
            encrypted, decrypted, dek, user_id="u1", file_id="f1"
        )
        assert open(decrypted, "rb").read() == b"hello"
