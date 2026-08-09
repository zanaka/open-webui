"""Response rating is closed, so no feedback row is ever written.

Kept closed rather than encrypted because the leaderboard has to read every
user's rating to score a model, while the same row carries a snapshot of the
whole conversation. Closing keeps the table empty, so whenever the feature is
wanted the choice can still be made freely, with nothing to migrate.
"""

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute

from open_webui.routers.evaluations import check_evaluations_access, router
from open_webui.utils.encrypted_models import ENCRYPTED_MODELS, NOT_ENCRYPTED


def _dependency_calls(dependant):
    calls = []
    for dependency in dependant.dependencies:
        calls.append(dependency.call)
        calls.extend(_dependency_calls(dependency))
    return calls


def test_the_guard_refuses_regardless_of_configuration():
    with pytest.raises(HTTPException) as raised:
        check_evaluations_access()

    assert raised.value.status_code == 501


def test_every_evaluation_route_is_behind_the_guard():
    """A new route added without the guard would reopen the feature."""
    unguarded = [
        f"{sorted(route.methods)} {route.path}"
        for route in router.routes
        if isinstance(route, APIRoute)
        and check_evaluations_access not in _dependency_calls(route.dependant)
    ]

    assert unguarded == []


def test_there_are_routes_to_guard():
    """Guards against the test above passing because the router became empty."""
    assert len([r for r in router.routes if isinstance(r, APIRoute)]) > 10


def test_feedback_is_recorded_as_closed_not_as_a_gap():
    """The reason has to say it is closed, or it reads as work left undone."""
    from open_webui.models.feedbacks import Feedback

    assert Feedback not in ENCRYPTED_MODELS
    assert "closed" in NOT_ENCRYPTED["Feedback"]


def test_no_user_content_is_left_unclassified():
    """With feedback closed, nothing carrying user content is still pending."""
    pending = [name for name, reason in NOT_ENCRYPTED.items() if "TODO" in reason]

    assert pending == []
