from dataclasses import dataclass


@dataclass
class SessionKeyWrap:
    """
    A camera's session key (one per camera per session, e.g. per day) encrypted to the
    Emergency Committee's public key of that period (month). It is the only thing the
    committee path needs from the database: opening it yields the session key, and the
    session key yields the puzzle solution of every record that camera produced in
    that session (crypto/escrow.py) -- that is the Busca Total.

    Nothing in here is secret: `r` is the ElGamal ephemeral point (65 bytes, SEC1),
    `wrapped` is AES-256-GCM(kem_key, nonce, session_key) bound to
    (camera_id, period, session) as associated data.
    """
    camera_id: int
    period: str   # e.g. "2026-01": selects which committee key opens it
    session: str  # e.g. "2026-01-01": what it opens
    r: bytes
    nonce: bytes
    wrapped: bytes
