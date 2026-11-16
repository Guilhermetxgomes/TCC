from dataclasses import dataclass


@dataclass
class SessionKeyWrap:
    """
    A camera's session key (one per camera per session, e.g. per day) encrypted to the
    Emergency Committee's public key of that period (month). It is the only thing the
    committee path needs from the database: opening it yields the session key, and the
    session key yields the puzzle solution of every record that camera produced in
    that session (crypto/escrow.py) -- that is the Busca Total.

    Nothing in here is secret: `wrapped` is the HPKE output (X25519 encapsulated key ||
    AES-256-GCM ciphertext), bound to (camera_id, period, session) through HPKE's `info`.
    """
    camera_id: int
    period: str   # e.g. "2026-01": selects which committee key opens it
    session: str  # e.g. "2026-01-01": what it opens
    wrapped: bytes
