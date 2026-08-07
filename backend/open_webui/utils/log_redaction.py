"""Describing a value in a log without writing what it says.

Redaction that lists the fields to hide gets it backwards: whatever the list
forgets is what leaks, and the list has to be revisited every time a payload
grows a field. This does the opposite. Structure is kept — keys, types, sizes,
counts — and every string is replaced by its length, so a value that nobody
thought about is hidden by default rather than by accident.

Numbers, booleans and None pass through: they are shapes, not sentences. A
string never does, not even a short one, because "which model" and "what the
person asked" are both strings and the difference is not visible from here.

An investigation sometimes needs the sentences. The rule for that is: content
may reach the logs only while every person using the deployment can see that
it might. DEBUG_MODE below derives from GLOBAL_LOG_LEVEL, and the same value
drives a banner in the interface (`debug_mode` in /api/config), so the two
cannot come apart: plaintext in the logs and the on-screen notice are one
switch. Flipping it is a deliberate act — logs land on the host's disk via
Docker, so this is not ephemeral — and the banner is what makes the session
an informed one instead of a quiet one.
"""

import logging
from typing import Any

from open_webui.env import GLOBAL_LOG_LEVEL

log = logging.getLogger(__name__)

MAX_DEPTH = 6
MAX_ITEMS = 20

#: One definition for both the log behaviour and the interface banner.
DEBUG_MODE = GLOBAL_LOG_LEVEL == "DEBUG"

if DEBUG_MODE:
    log.warning(
        "GLOBAL_LOG_LEVEL=DEBUG: debug logs will contain what people write, "
        "and Docker persists them on the host. The interface shows a debug-"
        "mode notice to every user while this is on."
    )


def describe(value: Any, depth: int = 0) -> Any:
    """The shape of a value — or, in an announced debug session, the value."""
    if DEBUG_MODE:
        # The banner is up for everyone; this session is an informed one.
        return value

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        return f"<str {len(value)}>"

    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<bytes {len(value)}>"

    if depth >= MAX_DEPTH:
        return f"<{type(value).__name__}>"

    if isinstance(value, dict):
        described = {
            # Keys name the schema rather than the content, so they stay.
            str(key): describe(item, depth + 1)
            for key, item in list(value.items())[:MAX_ITEMS]
        }
        if len(value) > MAX_ITEMS:
            described["..."] = f"<{len(value) - MAX_ITEMS} more>"
        return described

    if isinstance(value, (list, tuple, set)):
        items = [describe(item, depth + 1) for item in list(value)[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            items.append(f"<{len(value) - MAX_ITEMS} more>")
        return items

    if hasattr(value, "model_dump"):
        try:
            return describe(value.model_dump(), depth)
        except Exception:
            return f"<{type(value).__name__}>"

    # Anything else is summarised by its type alone. Calling str() on it could
    # print the very thing this is here to keep out of the log.
    return f"<{type(value).__name__}>"
