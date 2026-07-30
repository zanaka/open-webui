"""Nothing a person wrote reaches a log line — unless everyone can see it might.

The rule is deliberately blunt: every string is replaced by its length. A list
of fields to hide would have to be revisited every time a payload grows one,
and whatever the list forgot would be what leaked. Here a field nobody thought
about is hidden because that is the default, not because someone remembered.

The one exception is an announced debug session: the same flag that lets
content through to the logs also puts a notice on every screen, so the two
cannot be separated.
"""

from pydantic import BaseModel

from open_webui.utils import log_redaction
from open_webui.utils.log_redaction import MAX_ITEMS, describe

SECRET = "the quarterly figures are down"


def _flatten(value):
    """Every string that would end up in the log line."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [
            piece
            for key, item in value.items()
            for piece in [key, *_flatten(item)]
        ]
    if isinstance(value, (list, tuple)):
        return [piece for item in value for piece in _flatten(item)]
    return []


class TestStrings:
    def test_a_string_becomes_its_length(self):
        assert describe(SECRET) == f"<str {len(SECRET)}>"

    def test_even_a_short_string_is_hidden(self):
        """"gpt-4" and "my salary" are both strings; this cannot tell them apart."""
        assert describe("hi") == "<str 2>"

    def test_an_empty_string_is_still_described(self):
        assert describe("") == "<str 0>"

    def test_bytes_are_hidden_too(self):
        assert describe(b"secret bytes") == "<bytes 12>"


class TestShapeSurvives:
    def test_numbers_and_booleans_pass_through(self):
        """They are shapes, not sentences, and they are what makes a log useful."""
        assert describe({"count": 3, "ok": True, "score": 0.5, "missing": None}) == {
            "count": 3,
            "ok": True,
            "score": 0.5,
            "missing": None,
        }

    def test_keys_are_kept(self):
        described = describe({"model": "x", "messages": []})

        assert set(described) == {"model", "messages"}

    def test_nesting_is_kept(self):
        described = describe({"messages": [{"role": "user", "content": SECRET}]})

        assert described == {
            "messages": [{"role": "<str 4>", "content": f"<str {len(SECRET)}>"}]
        }


class TestNothingEscapes:
    def test_a_chat_payload_leaks_nothing(self):
        form_data = {
            "model": "llama3",
            "messages": [
                {"role": "user", "content": SECRET},
                {"role": "assistant", "content": "and here is why"},
            ],
            "metadata": {"chat_id": "c1", "files": [{"name": "budget.xlsx"}]},
        }

        assert SECRET not in str(describe(form_data))
        assert "budget.xlsx" not in str(describe(form_data))

    def test_rag_sources_leak_nothing(self):
        sources = [
            {
                "document": [SECRET],
                "metadata": [{"hash": "abc", "title": "Q3 plan"}],
                "source": {"name": "confidential.pdf"},
            }
        ]

        assert not any(SECRET in piece for piece in _flatten(describe(sources)))
        assert not any("confidential" in piece for piece in _flatten(describe(sources)))

    def test_an_unknown_object_is_summarised_by_type(self):
        """str() on it could print the very thing this is here to keep out."""

        class Response:
            def __str__(self):
                return SECRET

        assert describe(Response()) == "<Response>"

    def test_a_pydantic_model_is_described_field_by_field(self):
        class Payload(BaseModel):
            model: str
            temperature: float

        described = describe(Payload(model=SECRET, temperature=0.7))

        assert described == {"model": f"<str {len(SECRET)}>", "temperature": 0.7}

    def test_deep_nesting_stops_without_printing_anything(self):
        value = SECRET
        for _ in range(20):
            value = {"next": value}

        assert SECRET not in str(describe(value))

    def test_long_lists_are_truncated_with_a_count(self):
        described = describe(["x"] * (MAX_ITEMS + 5))

        assert len(described) == MAX_ITEMS + 1
        assert described[-1] == "<5 more>"


class TestAnnouncedDebugSession:
    """Content may reach the logs only while every screen says it might."""

    def test_debug_mode_passes_the_value_through(self, monkeypatch):
        monkeypatch.setattr(log_redaction, "DEBUG_MODE", True)
        payload = {"messages": [{"content": SECRET}]}

        assert describe(payload) == payload

    def test_outside_a_debug_session_nothing_changes(self):
        assert log_redaction.DEBUG_MODE is False
        assert SECRET not in str(describe({"content": SECRET}))

    def test_the_banner_and_the_logs_share_one_flag(self):
        """main.py exposes this same value as features.debug_mode, so the
        notice and the plaintext cannot be enabled separately."""
        from open_webui.env import GLOBAL_LOG_LEVEL

        assert log_redaction.DEBUG_MODE == (GLOBAL_LOG_LEVEL == "DEBUG")
