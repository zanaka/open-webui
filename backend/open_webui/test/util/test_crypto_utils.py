import base64

import pytest
from cryptography.exceptions import InvalidTag

from open_webui.utils.crypto_utils import (
    decrypt_json_value,
    decrypt_text,
    encrypt_json_value,
    encrypt_text,
    generate_dek,
)


@pytest.fixture
def dek() -> bytes:
    return generate_dek()


class TestEncryptText:
    def test_roundtrip_ascii(self, dek):
        assert decrypt_text(encrypt_text("hello", dek), dek) == "hello"

    def test_roundtrip_empty_string(self, dek):
        assert decrypt_text(encrypt_text("", dek), dek) == ""

    def test_roundtrip_unicode(self, dek):
        value = "こんにちは🌸 — emoji and 漢字"
        assert decrypt_text(encrypt_text(value, dek), dek) == value

    def test_roundtrip_long_string(self, dek):
        value = "a" * 100_000
        assert decrypt_text(encrypt_text(value, dek), dek) == value

    def test_roundtrip_marker_like_string(self, dek):
        value = "owenc:v1:my-file.png"
        assert decrypt_text(encrypt_text(value, dek), dek) == value

    def test_none_passes_through_on_encrypt(self, dek):
        assert encrypt_text(None, dek) is None

    def test_none_passes_through_on_decrypt(self, dek):
        assert decrypt_text(None, dek) is None

    def test_output_is_ascii_base64(self, dek):
        encrypted = encrypt_text("hello", dek)
        # Must be ASCII-safe (no Python bytes, no non-ASCII)
        assert isinstance(encrypted, str)
        encrypted.encode("ascii")
        # Must be valid base64
        base64.b64decode(encrypted)

    def test_two_encryptions_produce_different_ciphertext(self, dek):
        # Fresh nonce per call → ciphertexts differ
        a = encrypt_text("hello", dek)
        b = encrypt_text("hello", dek)
        assert a != b

    def test_wrong_dek_raises(self, dek):
        encrypted = encrypt_text("hello", dek)
        with pytest.raises(InvalidTag):
            decrypt_text(encrypted, generate_dek())

    def test_tampered_ciphertext_raises(self, dek):
        encrypted = encrypt_text("hello", dek)
        raw = bytearray(base64.b64decode(encrypted))
        raw[-1] ^= 0x01  # flip a tag bit
        tampered = base64.b64encode(bytes(raw)).decode("ascii")
        with pytest.raises(InvalidTag):
            decrypt_text(tampered, dek)

    def test_invalid_base64_raises(self, dek):
        with pytest.raises(Exception):
            decrypt_text("not_base64!!!", dek)


class TestEncryptJsonValue:
    def test_roundtrip_dict(self, dek):
        value = {"a": 1, "b": "two", "c": None}
        assert decrypt_json_value(encrypt_json_value(value, dek), dek) == value

    def test_roundtrip_list(self, dek):
        value = [1, "two", {"three": 3}, None, True, False]
        assert decrypt_json_value(encrypt_json_value(value, dek), dek) == value

    def test_roundtrip_nested(self, dek):
        value = {"outer": {"inner": {"deep": [1, 2, {"x": "y"}]}}}
        assert decrypt_json_value(encrypt_json_value(value, dek), dek) == value

    def test_roundtrip_empty_dict(self, dek):
        assert decrypt_json_value(encrypt_json_value({}, dek), dek) == {}

    def test_roundtrip_empty_list(self, dek):
        assert decrypt_json_value(encrypt_json_value([], dek), dek) == []

    def test_roundtrip_unicode_keys_and_values(self, dek):
        value = {"日本語キー": "🌸value", "emoji": "🎉"}
        assert decrypt_json_value(encrypt_json_value(value, dek), dek) == value

    def test_roundtrip_json_containing_marker_like_string(self, dek):
        value = {"name": "owenc:v1:my-file.png"}
        assert decrypt_json_value(encrypt_json_value(value, dek), dek) == value

    def test_top_level_none_passes_through_on_encrypt(self, dek):
        assert encrypt_json_value(None, dek) is None

    def test_top_level_none_passes_through_on_decrypt(self, dek):
        assert decrypt_json_value(None, dek) is None

    def test_scalar_values_roundtrip(self, dek):
        for value in (True, False, 0, 1, -1, 3.14, "scalar string"):
            assert decrypt_json_value(encrypt_json_value(value, dek), dek) == value

    def test_wrong_dek_raises(self, dek):
        encrypted = encrypt_json_value({"a": 1}, dek)
        with pytest.raises(InvalidTag):
            decrypt_json_value(encrypted, generate_dek())

    def test_tampered_ciphertext_raises(self, dek):
        encrypted = encrypt_json_value({"a": 1}, dek)
        raw = bytearray(base64.b64decode(encrypted))
        raw[-1] ^= 0x01
        tampered = base64.b64encode(bytes(raw)).decode("ascii")
        with pytest.raises(InvalidTag):
            decrypt_json_value(tampered, dek)

    def test_non_json_serializable_raises(self, dek):
        with pytest.raises(TypeError):
            encrypt_json_value({"bytes": b"raw"}, dek)
