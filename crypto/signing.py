"""
Integrity of the stored records: associated data (AD) and the camera's signature.

Two different attacks, two different defences (Seção 2.4.6 / Fase 1 of the Nêmesis):

1. Moving a record (AD). The row stored by the Servidor is (camera_id, captured_at, c',
   n, nonce, ciphertext). The AES-GCM tag only covers what goes into it, so without AD
   whoever runs the database can rewrite camera_id and captured_at -- move a capture of
   ABC1D23 from camera 11 at 08:10 to camera 40 at 09:00 -- and the record still opens,
   now telling a false story. With AD = (camera_id, captured_at) the tag binds the
   ciphertext to where and when it was captured: edit either one and decryption fails.

2. Forging a record (signature). AES-GCM is symmetric: the key that decrypts is the key
   that encrypts and authenticates. Whoever solves a puzzle learns K and can encrypt any
   other plate under the same c' (and the same AD, which is public). The forgery opens
   with the same puzzle and its tag is valid -- AES-GCM cannot tell it apart. Only a key
   the solver does NOT learn can: the camera signs the whole record with its own ECDSA
   (P-256) key, and records whose signature does not check against the camera's
   registered public key are rejected before any puzzle is attempted.

The public keys are the trust anchor: they must come from a registry the Servidor
operator cannot rewrite (in the simulation, World.camera_keys, kept outside the
database); otherwise the operator would simply sign forgeries with a key of his own.
"""
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from crypto.canonical import encode
from entities.record import Record

SIGNATURE_CONTEXT = b"nemesis-record-v1"


def record_ad(camera_id: int, captured_at: str) -> bytes:
    """Associated data of a record's AES-GCM encryption: the camera and the capture instant."""
    return f"record|{camera_id}|{captured_at}".encode()


def signed_payload(record: Record) -> bytes:
    """Canonical bytes the camera signs: every stored column of the record."""
    fields = [
        SIGNATURE_CONTEXT,
        str(record.camera_id).encode(),
        (record.captured_at or "").encode(),
        str(record.n).encode(),
        (record.block or "").encode(),
        record.c_prime,
        record.nonce,
        record.ciphertext,
    ]
    return encode(*fields)


class CameraSigner:
    """The camera's signing key. The private half never leaves the camera."""

    def __init__(self):
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key_bytes = self._private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )

    def sign(self, record: Record) -> bytes:
        return self._private_key.sign(signed_payload(record), ec.ECDSA(hashes.SHA256()))


def verify_record(record: Record, public_key_bytes: Optional[bytes]) -> bool:
    """True when the record carries a valid signature of the camera that owns that public key."""
    if public_key_bytes is None or not record.signature:
        return False
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)
    try:
        public_key.verify(record.signature, signed_payload(record), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True
