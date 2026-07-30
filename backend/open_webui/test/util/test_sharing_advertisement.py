"""What the interface is told it may offer.

Offering an audience the save path will refuse is worse than not offering it,
so the list comes off the encryption registry rather than being written out a
second time in the frontend.
"""

from open_webui.utils.encrypted_models import (
    ENCRYPTED_MODELS,
    named_recipient_resources,
)


def test_shared_models_are_advertised_as_named_only():
    assert "Knowledge" in named_recipient_resources()


def test_it_matches_the_registry_exactly():
    """The point of reading it off the registry is that it cannot drift."""
    assert named_recipient_resources() == sorted(
        model.__name__ for model, policy in ENCRYPTED_MODELS.items() if policy.shared
    )


def test_models_keyed_by_their_owner_are_not_advertised():
    """A chat has no key of its own, so there is nobody to hand a copy to."""
    assert "Chat" not in named_recipient_resources()
    assert "Memory" not in named_recipient_resources()


def test_the_names_are_the_ones_the_registry_uses():
    """The frontend passes these straight back as resourceType."""
    known = {model.__name__ for model in ENCRYPTED_MODELS}
    assert set(named_recipient_resources()) <= known
