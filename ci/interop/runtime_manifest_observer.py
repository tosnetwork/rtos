"""Observe live startup manifests; never use this for stopped-state verification."""

import json


def read_starting_manifest(path):
    """No authority until a complete JSON value exists; caller owns the deadline.

    Native create_new/write_all exposes an empty or partial file to observers.
    This does not repair files or validate identities. Callers must retain their
    original budget, check process liveness and validate the completed binding.
    Other I/O errors and malformed complete values must not become readiness.
    """
    try:
        value = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        raise TypeError("Runtime manifest must be a JSON object")
    return value
