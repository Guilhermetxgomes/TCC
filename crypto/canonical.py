"""
Canonical byte encoding shared by everything that is hashed or signed (records, tokens,
log entries): each field is prefixed with its length, so no two field lists encode alike.
"""
import json


def field(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def encode(*fields: bytes) -> bytes:
    return b"".join(field(f) for f in fields)


def json_bytes(value) -> bytes:
    """Deterministic JSON (sorted keys, no spaces): the same dict always gives the same bytes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
