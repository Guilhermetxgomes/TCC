"""
Key escrow for the Busca Total (exceptional access through the Emergency Committee).

Each camera keeps one random session key per session (by default per day) and sends
it to the server encrypted to the committee's public key of the month (a
SessionKeyWrap), with HPKE (RFC 9180: X25519 + HKDF-SHA256 + AES-256-GCM, from the
`cryptography` package), the context (camera, period, session) going into HPKE's
`info` so a wrap only opens as what it claims to be. While escrow is on, the camera does not draw the puzzle secrets at
random: it derives them from the session key,

    k = HMAC-SHA256(session_key, label || c') mod n

so the ciphertexts and puzzles stored in the database are exactly the usual ones --
Busca Aberta and Busca Fechada work unchanged, by brute force -- but whoever holds the
session key computes each k with one HMAC instead of ~n attempts. The session key can
only be recovered with the month's private key, which exists only as Shamir shares held
by the committee (services/committee.py).

Without the session key, k is indistinguishable from a uniform draw in [0, n) (HMAC
as a PRF; the modulo bias is at most n / 2^256), and a solved puzzle reveals log2(n)
bits of one PRF output, which says nothing about the session key or about other k's.

Cost of this design: the camera holds the current session key in memory for the
whole session, so a stolen camera exposes the session in progress.
"""
import hashlib
import hmac
import os
from typing import Callable, Optional

from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from crypto.block_crumpling import block_key_from_secret
from crypto.puzzle import open_record
from entities.block_header import BlockHeader
from entities.record import Record
from entities.session_key_wrap import SessionKeyWrap

# A time slot is a prefix of the ISO-8601 capture timestamp ("2026-01-01T08:17:30...").
GRANULARITY = {"month": 7, "day": 10, "hour": 13, "10min": 15, "minute": 16}

# HPKE suite of the session-key wraps (Curve25519, as in RF04/RF05 of the specification).
WRAP_SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)

RECORD_LABEL = b"record-k"
BLOCK_LABEL = b"block-k"


def time_slot(captured_at: str, granularity: str) -> str:
    return captured_at[: GRANULARITY[granularity]]


def wrap_context(camera_id: int, period: str, session: str) -> bytes:
    return f"session-key|{camera_id}|{period}|{session}".encode()


def derive_secret(session_key: bytes, label: bytes, c_prime: bytes, n: int) -> int:
    digest = hmac.new(session_key, label + c_prime, hashlib.sha256).digest()
    return int.from_bytes(digest, "big") % n


class CameraEscrow:
    """The escrow state of one camera: the session key in use and the wraps not yet uploaded."""

    def __init__(self, camera_id: int, public_key_for: Callable[[str], X25519PublicKey],
                 session_granularity: str = "day"):
        if GRANULARITY[session_granularity] < GRANULARITY["month"]:
            raise ValueError("a session cannot span more than one committee period (month)")
        self.camera_id = camera_id
        self.session_granularity = session_granularity
        self._public_key_for = public_key_for  # period -> committee public key
        self._session: Optional[str] = None
        self._key: Optional[bytes] = None
        self._pending: list[SessionKeyWrap] = []

    def session_key(self, captured_at: str) -> bytes:
        """Session key for this capture time; rotating it drops the previous one for good."""
        session = time_slot(captured_at, self.session_granularity)
        if session != self._session:
            period = time_slot(captured_at, "month")
            context = wrap_context(self.camera_id, period, session)
            key = os.urandom(32)
            self._pending.append(SessionKeyWrap(
                camera_id=self.camera_id, period=period, session=session,
                wrapped=WRAP_SUITE.encrypt(key, self._public_key_for(period), info=context),
            ))
            self._session, self._key = session, key
        return self._key

    def drain_wraps(self) -> list[SessionKeyWrap]:
        wraps, self._pending = self._pending, []
        return wraps


def unwrap_session_key(wrap: SessionKeyWrap, private_key: X25519PrivateKey) -> bytes:
    """Raises InvalidTag when the key is not the period's or the wrap's context was altered."""
    return WRAP_SUITE.decrypt(wrap.wrapped, private_key, info=wrap_context(wrap.camera_id, wrap.period, wrap.session))


def open_with_session_key(record: Record, session_key: bytes, header: Optional[BlockHeader] = None) -> str:
    """Decrypts one record through the escrow path: no brute force, one or two HMACs."""
    prefix = b""
    if record.block is not None:
        if header is None:
            raise ValueError("this record belongs to a block; its header is required")
        prefix = block_key_from_secret(header, derive_secret(session_key, BLOCK_LABEL, header.c_prime, header.t))
    return open_record(record, derive_secret(session_key, RECORD_LABEL, record.c_prime, record.n), prefix)
