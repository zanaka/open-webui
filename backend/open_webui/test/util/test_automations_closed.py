import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute

from open_webui.routers.automations import check_automations_access, router


def _dependency_calls(dependant):
    calls = []
    for dependency in dependant.dependencies:
        calls.append(dependency.call)
        calls.extend(_dependency_calls(dependency))
    return calls


def test_the_guard_refuses_regardless_of_configuration():
    """A scheduled run has no DEK in memory, so the setting opens nothing."""
    with pytest.raises(HTTPException) as raised:
        check_automations_access()

    assert raised.value.status_code == 501


def test_every_automation_route_is_behind_the_guard():
    """A new route added without the guard would reopen the feature."""
    unguarded = [
        f"{sorted(route.methods)} {route.path}"
        for route in router.routes
        if isinstance(route, APIRoute)
        and check_automations_access not in _dependency_calls(route.dependant)
    ]

    assert unguarded == []


def test_there_are_routes_to_guard():
    """Guards against the test above passing because the router became empty."""
    assert len([r for r in router.routes if isinstance(r, APIRoute)]) > 3
